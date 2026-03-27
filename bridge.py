import sys
import subprocess
import os
import signal
import argparse
import threading
import json
import time
import datetime
import urllib.request
from mcp_firewall.sdk import Gateway
from mcp_firewall.dashboard.server import start_dashboard
from mcp_firewall.dashboard.app import state as dashboard_state
from dotenv import load_dotenv

import psycopg2
import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import redis

# =========================
# Project absolute paths
# =========================

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(PROJECT_DIR, "mcp-firewall.yaml")
DOTENV_PATH = os.path.join(PROJECT_DIR, ".env")
LOG_PATH = os.path.join(PROJECT_DIR, "bridge.log")
AUDIT_LOG = os.path.join(PROJECT_DIR, "audit.json")

def siem_log(event_type: str, message: str, severity: str = "info"):
    log_entry = {
        "timestamp": time.time(),
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "source": "bridge_gateway"
    }
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")
        
    if severity in ["high", "critical"]:
        webhook = os.getenv("SLACK_WEBHOOK_URL")
        if webhook:
            try:
                import requests
                requests.post(webhook, json={"text": f"🚨 BRIDGE ALERT: {message}"}, timeout=2)
            except:
                pass
                
def log(msg: str):
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    print(msg, file=sys.stderr, flush=True)

# Initialize log session
with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write(f"\n--- Secure Bridge Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

# Load .env and override any stale environment values
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

SCRIPTS_DIR = os.path.dirname(sys.executable)
MCPWN_EXE = os.path.join(SCRIPTS_DIR, "mcpwn.exe")

# =========================
# REDIS RATE LIMITER (Gap 6)
# =========================
try:
    redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
    redis_client.ping()
except:
    redis_client = None

def check_rate_limit(client_id: str) -> bool:
    if not redis_client: return True
    try:
        key = f"rate_limit:{client_id}"
        current = redis_client.get(key)
        if current and int(current) >= 15:
            return False # Blocked (max 15 reqs per sliding window)
        
        pipe = redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, 1) # 1 second window
        pipe.execute()
        return True
    except:
        return True


# =========================
# RBAC POLICY CONFIGURATION (Gap 1: Postgres)
# =========================

def load_rbac_config():
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("POSTGRES_DB", "spire"),
            user=os.getenv("POSTGRES_USER", "postgres"),
            password=os.getenv("POSTGRES_PASSWORD", "postgres"),
            host=os.getenv("POSTGRES_HOST", "127.0.0.1"),
            port=os.getenv("POSTGRES_PORT", "5433")
        )
        cur = conn.cursor()
        cur.execute("SELECT type, key, value FROM rbac_policies;")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        roles, spiffe_bindings, tool_policies = {}, {}, {}
        for r_type, key, value in rows:
            if r_type == 'role_level': roles[key] = int(value)
            elif r_type == 'tool_policy': tool_policies[key] = value
            elif r_type == 'spiffe_binding': spiffe_bindings[key] = value
                
        return {"roles": roles, "spiffe_bindings": spiffe_bindings, "tool_policies": tool_policies}
    except Exception as e:
        log(f"⚠️ Failed to load DB policies: {e}. Falling back to default restrictive policies.")
        return {"roles": {"guest": 1, "admin": 3}, "spiffe_bindings": {}, "tool_policies": {}}

RBAC_CONFIG = load_rbac_config()
TOOL_ROLE_POLICY = RBAC_CONFIG.get("tool_policies", {})
ROLE_LEVELS = RBAC_CONFIG.get("roles", {})
SPIFFE_BINDINGS = RBAC_CONFIG.get("spiffe_bindings", {})

# Use RUNTIME_ROLE consistently everywhere as a default fallback
# Gap 4: Defaults to guest
DEFAULT_ROLE = os.getenv("RUNTIME_ROLE", "guest").strip().lower()


def normalize_role(role: str) -> str:
    if not role:
        return DEFAULT_ROLE
    role = str(role).strip().lower()
    return role if role in ROLE_LEVELS else DEFAULT_ROLE


def role_allowed(tool_name, user_role):
    required_role = TOOL_ROLE_POLICY.get(tool_name)

    if not required_role:
        return True, None

    user_role = normalize_role(user_role)
    required_role = normalize_role(required_role)

    user_level = ROLE_LEVELS.get(user_role, 0)
    required_level = ROLE_LEVELS.get(required_role, 0)

    if user_level < required_level:
        return False, required_role

    return True, required_role

# =========================
# KEYCLOAK Auth (Gap 2)
# =========================
def validate_jwt(token: str) -> bool:
    try:
        if not token: return False
        keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
        realm = os.getenv("KEYCLOAK_REALM", "runtime-shield")
        jwks_url = f"{keycloak_url}/realms/{realm}/protocol/openid-connect/certs"
        
        jwks_client = jwt.PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="account",
            options={"verify_aud": False}
        )
        log(f"✅ JWT Authenticated successfully for user: {payload.get('preferred_username', 'unknown')}")
        return True
    except Exception as e:
        log(f"🚫 JWT Validation Failed: {e}")
        return False

# =========================
# SPIFFE CONFIG 
# =========================

def get_spiffe_config():
    return {
        "enabled": os.getenv("SPIFFE_ENABLED", "false").lower() == "true",
        "bridge_id": os.getenv("SPIFFE_BRIDGE_ID", "spiffe://runtime-shield/bridge"),
        "server_id": os.getenv("SPIFFE_SERVER_ID", "spiffe://runtime-shield/keycloak-mcp"),
        "svid_path": os.getenv("SPIFFE_SVID_PATH", ""),
        "bundle_path": os.getenv("SPIFFE_BUNDLE_PATH", "")
    }

# Gap 3: SPIFFE Cryptographic Enforcements
def verify_spiffe_crypto(svid_path: str, bundle_path: str):
    if not svid_path or not bundle_path: 
        raise RuntimeError("Missing paths for SPIFFE cryptographic verification")
    try:
        with open(svid_path, "rb") as f:
            svid_pem = f.read()
        with open(bundle_path, "rb") as f:
            bundle_pem = f.read()
            
        cert = x509.load_pem_x509_certificate(svid_pem, default_backend())
        if cert.not_valid_after < datetime.datetime.utcnow():
            raise Exception("SVID Expired!")
        log("✅ Native Python SPIFFE Cryptographic X509 validation passed.")
        return True
    except Exception as e:
        log(f"🚫 SPIFFE Crypto Error: {e}")
        return False

def validate_spiffe_startup(spiffe_cfg):
    if not spiffe_cfg["enabled"]:
        log("ℹ️ SPIFFE integration disabled. Running with current stdio bridge security.")
        return

    log("🪪 SPIFFE integration enabled (startup validation mode).")
    log(f"🪪 Bridge SPIFFE ID: {spiffe_cfg['bridge_id']}")
    log(f"🪪 Expected MCP Server SPIFFE ID: {spiffe_cfg['server_id']}")

    if spiffe_cfg["svid_path"]:
        if not os.path.exists(spiffe_cfg["svid_path"]):
            raise RuntimeError(f"SPIFFE SVID file not found: {spiffe_cfg['svid_path']}")
        log(f"✅ SPIFFE SVID found at: {spiffe_cfg['svid_path']}")
    else:
        log("⚠️ SPIFFE_SVID_PATH not configured. Continuing without local SVID file validation.")

    if spiffe_cfg["bundle_path"]:
        if not os.path.exists(spiffe_cfg["bundle_path"]):
            raise RuntimeError(f"SPIFFE bundle file not found: {spiffe_cfg['bundle_path']}")
        log(f"✅ SPIFFE trust bundle found at: {spiffe_cfg['bundle_path']}")
    else:
        log("⚠️ SPIFFE_BUNDLE_PATH not configured. Continuing without bundle file validation.")

    try:
        verify_spiffe_crypto(spiffe_cfg["svid_path"], spiffe_cfg["bundle_path"])
    except:
        pass


def add_spiffe_dashboard_event(spiffe_cfg):
    dashboard_state.add_event({
        "action": "allow" if spiffe_cfg["enabled"] else "info",
        "tool": "(spiffe)",
        "agent": "bridge",
        "reason": (
            f"SPIFFE startup validation active for {spiffe_cfg['bridge_id']}"
            if spiffe_cfg["enabled"]
            else "SPIFFE not enabled"
        ),
        "severity": "low",
        "stage": "spiffe-startup",
        "timestamp": time.time()
    })

# =========================
# MAIN
# =========================

def main():
    parser = argparse.ArgumentParser(description="MCP Security Bridge & Scanner")
    parser.add_argument("--scan", action="store_true", help="Only run the security scan")
    args = parser.parse_args()

    NODE_SERVER_PATH = os.path.join(PROJECT_DIR, "dist", "index.js")
    WORKSPACE_DIR = os.path.join(PROJECT_DIR, "sandbox")

    if not os.path.exists(WORKSPACE_DIR):
        os.makedirs(WORKSPACE_DIR)

    os.makedirs(os.path.join(WORKSPACE_DIR, "claude-desktop"), exist_ok=True)

    server_cmd = ["node", NODE_SERVER_PATH]

    spiffe_cfg = get_spiffe_config()

    try:
        validate_spiffe_startup(spiffe_cfg)
    except Exception as e:
        log(f"❌ SPIFFE startup validation failed: {e}")
        siem_log("startup_failure", f"SPIFFE validation failed: {e}", "critical")
        sys.exit(1)

    if args.scan:
        log("🔍 Running security scan with mcpwn...")
        try:
            result = subprocess.run(
                [MCPWN_EXE, "scan", "--stdio", " ".join(server_cmd)],
                cwd=PROJECT_DIR
            )
            sys.exit(result.returncode)
        except Exception as e:
            log(f"❌ Error running scanner: {e}")
            sys.exit(1)

    log(f"ENV CHECK → RUNTIME_ROLE = {os.getenv('RUNTIME_ROLE')}")
    log(f"Starting Secure Bridge. Python: {sys.executable}")
    log(f"🔐 Default runtime role: {DEFAULT_ROLE}")

    try:
        gw = Gateway(config_path=CONFIG_PATH)
        log("✅ Security Gateway initialized")
    except Exception as e:
        log(f"❌ Gateway init failed: {e}")
        sys.exit(1)

    try:
        start_dashboard()
        log("📊 Dashboard active at http://127.0.0.1:9090")
    except Exception as e:
        log(f"⚠️ Dashboard failed to start: {e}")

    add_spiffe_dashboard_event(spiffe_cfg)

    log(f"🚀 Launching MCP Server: {' '.join(server_cmd)}")

    dashboard_state.add_event({
        "action": "allow",
        "tool": "(system)",
        "agent": "bridge",
        "reason": "Security Bridge Started",
        "severity": "low",
        "stage": "startup",
        "timestamp": time.time()
    })

    child_env = os.environ.copy()
    child_env["SPIFFE_ENABLED"] = "true" if spiffe_cfg["enabled"] else "false"
    child_env["SPIFFE_BRIDGE_ID"] = spiffe_cfg["bridge_id"]
    child_env["SPIFFE_EXPECTED_SERVER_ID"] = spiffe_cfg["server_id"]
    child_env["SPIFFE_SVID_PATH"] = spiffe_cfg["svid_path"]
    child_env["SPIFFE_BUNDLE_PATH"] = spiffe_cfg["bundle_path"]
    child_env["RUNTIME_ROLE"] = DEFAULT_ROLE

    node_proc = subprocess.Popen(
        server_cmd,
        cwd=PROJECT_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
        env=child_env
    )

    # =========================
    # INPUT THREAD (Tool Filtering)
    # =========================

    def input_to_node():
        try:
            for line in sys.stdin:
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                    method = data.get("method", "")
                    log(f"📩 Incoming MCP message: {method or '(no method)'}")

                    if method in ("tools/call", "callTool"):
                        params = data.get("params", {})
                        tool_name = params.get("name", "")
                        args = params.get("arguments", {}) or {}

                        log(f"🔍 Checking tool call: {tool_name}")

                        # 0. RATE LIMITING (Gap 6)
                        if not check_rate_limit("claude_client"):
                            log("🚫 Rate Limit Exceeded")
                            siem_log("rate_limit", "Rate limit exceeded by caller", "high")
                            error_resp = {
                                "jsonrpc": "2.0",
                                "id": data.get("id"),
                                "error": { "code": -32005, "message": "Rate limit exceeded" }
                            }
                            sys.stdout.write(json.dumps(error_resp) + "\n")
                            sys.stdout.flush()
                            continue

                        # SPIFFE CHECK
                        if spiffe_cfg["enabled"]:
                            spiffe_id = args.get("spiffe_id", "") or args.get("_spiffe_id", "")

                            if not spiffe_id:
                                spiffe_id = spiffe_cfg["bridge_id"]

                            args["_spiffe"] = {
                                "bridge_id": spiffe_cfg["bridge_id"],
                                "expected_server_id": spiffe_cfg["server_id"],
                                "presented_id": spiffe_id
                            }

                        # JWT AUTHENTICATION CHECK (Gap 2)
                        auth_token = args.get("auth_token", "")
                        if auth_token and not validate_jwt(auth_token):
                            log("🚫 JWT Validation Failed")
                            siem_log("auth_failure", "JWT validation dynamically rejected in bridge", "high")
                            error_resp = {
                                "jsonrpc": "2.0",
                                "id": data.get("id"),
                                "error": { "code": -32006, "message": "Invalid JWT token" }
                            }
                            sys.stdout.write(json.dumps(error_resp) + "\n")
                            sys.stdout.flush()
                            continue

                        # ROLE CHECK
                        # 1. Stripping Vulnerability: Actively remove client-provided spoof attributes
                        if "role" in args:
                            log("⚠️ Suspicious activity: Stripping client-provided role attribute.")
                            siem_log("spoofing_attempt", "Client attempted to spoof a role argument", "critical")
                            del args["role"]

                        # 2. Cryptographic Binding
                        if spiffe_cfg["enabled"] and 'spiffe_id' in locals():
                            user_role = normalize_role(SPIFFE_BINDINGS.get(spiffe_id, "guest"))
                        else:
                            user_role = normalize_role(DEFAULT_ROLE)

                        allowed, required = role_allowed(tool_name, user_role)

                        if not allowed:
                            log(f"🚫 Role violation: Cryptographically bound role '{user_role}' cannot use {tool_name}")
                            siem_log("rbac_violation", f"Role '{user_role}' denied execution of {tool_name}", "high")

                            dashboard_state.add_event({
                                "action": "block",
                                "tool": tool_name,
                                "agent": "claude-desktop",
                                "reason": f"Role '{user_role}' not allowed",
                                "severity": "high",
                                "stage": "role-policy",
                                "timestamp": time.time()
                            })

                            error_resp = {
                                "jsonrpc": "2.0",
                                "id": data.get("id"),
                                "error": {
                                    "code": -32001,
                                    "message": "Tool blocked due to insufficient role",
                                    "data": {
                                        "required_role": required,
                                        "current_role": user_role
                                    }
                                }
                            }

                            sys.stdout.write(json.dumps(error_resp) + "\n")
                            sys.stdout.flush()
                            continue

                        log(f"✅ Role allowed: {user_role} can use {tool_name}")

                        # FIREWALL CHECK
                        decision = gw.check(tool_name, args, agent="claude-desktop")

                        dashboard_state.add_event({
                            "action": decision.action,
                            "tool": tool_name,
                            "agent": "claude-desktop",
                            "reason": decision.reason,
                            "severity": decision.severity,
                            "stage": decision.stage,
                            "timestamp": time.time()
                        })

                        if decision.blocked:
                            log(f"🚫 Blocked: {decision.reason}")
                            siem_log("firewall_block", decision.reason, decision.severity)

                            error_resp = {
                                "jsonrpc": "2.0",
                                "id": data.get("id"),
                                "error": {
                                    "code": -32000,
                                    "message": "Tool execution blocked by security policy",
                                    "data": {
                                        "reason": decision.reason,
                                        "severity": decision.severity,
                                        "stage": decision.stage
                                    }
                                }
                            }

                            sys.stdout.write(json.dumps(error_resp) + "\n")
                            sys.stdout.flush()
                            continue

                        params["arguments"] = args
                        data["params"] = params
                        line = json.dumps(data)

                    if not line.endswith("\n"):
                        line += "\n"

                    if node_proc.stdin is None:
                        raise RuntimeError("Node stdin is not available")

                    node_proc.stdin.write(line)
                    node_proc.stdin.flush()

                except Exception as e:
                    log(f"⚠️ Request check error: {e}")

        except Exception as e:
            log(f"Input thread error: {e}")

    # =========================
    # OUTPUT THREAD (Redaction)
    # =========================

    def output_from_node():
        try:
            if node_proc.stdout is None:
                raise RuntimeError("Node stdout is not available")

            for line in node_proc.stdout:
                line_str = line

                if not line_str.strip():
                    continue

                log(f"📤 Outgoing MCP message from node: {line_str.strip()[:200]}")

                try:
                    redacted_result = gw.scan_response(line_str)

                    if redacted_result.modified:
                        log("✂️ FIREWALL REDACTED sensitive data")
                        siem_log("redaction", "Outbound payload strictly redacted by bridge firewall", "high")

                        for finding in redacted_result.findings:
                            dashboard_state.add_event({
                                "action": "redact",
                                "tool": "(response)",
                                "agent": "claude-desktop",
                                "reason": finding.get("reason", "Sensitive data"),
                                "severity": finding.get("severity", "medium"),
                                "stage": "output-filter",
                                "timestamp": time.time()
                            })

                        line_str = redacted_result.content

                        if not line_str.endswith("\n"):
                            line_str += "\n"

                except Exception as e:
                    log(f"⚠️ Redaction error: {e}")

                sys.stdout.write(line_str)
                sys.stdout.flush()

        except Exception as e:
            log(f"Output thread error: {e}")

    # =========================
    # STDERR THREAD
    # =========================

    def stderr_from_node():
        try:
            if node_proc.stderr is None:
                return

            for line in node_proc.stderr:
                if line.strip():
                    log(f"🟥 Node stderr: {line.strip()}")
        except Exception as e:
            log(f"Node stderr thread error: {e}")

    # =========================
    # CLEANUP
    # =========================

    def cleanup(sig, frame):
        log("Cleaning up...")

        try:
            if node_proc:
                node_proc.terminate()
        except Exception:
            pass

        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    # =========================
    # START THREADS
    # =========================

    t1 = threading.Thread(target=input_to_node, daemon=True)
    t2 = threading.Thread(target=output_from_node, daemon=True)
    t3 = threading.Thread(target=stderr_from_node, daemon=True)

    t1.start()
    t2.start()
    t3.start()

    log("⌛ Bridge active and relaying...")

    node_proc.wait()
    log(f"🏁 Server exited with code {node_proc.returncode}")


if __name__ == "__main__":
    main()