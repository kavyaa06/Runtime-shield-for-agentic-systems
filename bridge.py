import sys
import subprocess
import os
import signal
import argparse
import threading
import json
import time
from mcp_firewall.sdk import Gateway
from mcp_firewall.dashboard.server import start_dashboard
from mcp_firewall.dashboard.app import state as dashboard_state
from dotenv import load_dotenv


# =========================
# Project absolute paths
# =========================

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(PROJECT_DIR, "mcp-firewall.yaml")
DOTENV_PATH = os.path.join(PROJECT_DIR, ".env")
LOG_PATH = os.path.join(PROJECT_DIR, "bridge.log")


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
# TOOL ROLE POLICY
# =========================

TOOL_ROLE_POLICY = {
    "keycloak_revoke_user_sessions": "admin",
    "keycloak_list_user_sessions": "analyst",
    "keycloak_get_user_events": "guest"
}

ROLE_LEVELS = {
    "guest": 1,
    "analyst": 2,
    "admin": 3
}

# Use RUNTIME_ROLE consistently everywhere
DEFAULT_ROLE = os.getenv("RUNTIME_ROLE", "analyst").strip().lower()


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

    if ROLE_LEVELS[user_role] < ROLE_LEVELS[required_role]:
        return False, required_role

    return True, required_role


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

    log("⚠️ Current transport is stdio, so this is not full mTLS SPIFFE authentication.")


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
# SPIFFE RUNTIME POLICY
# =========================

ALLOWED_SPIFFE_IDS = {
    "spiffe://runtime-shield/agent",
    "spiffe://runtime-shield/dashboard",
    "spiffe://runtime-shield/bridge"
}


def spiffe_allowed(spiffe_id: str) -> bool:
    if not spiffe_id:
        return False
    return spiffe_id in ALLOWED_SPIFFE_IDS


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

    with open(os.path.join(WORKSPACE_DIR, "claude-desktop", "log_export.csv"), "w", encoding="utf-8") as f:
        f.write("user_id,login_time,session_token\n101,2024-02-23,Bearer test-token-1234567890abcdef\n")

    secrets_path = os.path.join(WORKSPACE_DIR, "claude-desktop", "secrets.txt")
    if os.path.exists(secrets_path):
        os.remove(secrets_path)

    server_cmd = ["node", NODE_SERVER_PATH]

    spiffe_cfg = get_spiffe_config()

    try:
        validate_spiffe_startup(spiffe_cfg)
    except Exception as e:
        log(f"❌ SPIFFE startup validation failed: {e}")
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

                        # SPIFFE CHECK
                        if spiffe_cfg["enabled"]:
                            spiffe_id = args.get("spiffe_id", "") or args.get("_spiffe_id", "")

                            if not spiffe_id:
                                spiffe_id = spiffe_cfg["bridge_id"]

                            if not spiffe_allowed(spiffe_id):
                                log(f"🚫 SPIFFE violation: unauthorized service identity {spiffe_id}")

                                dashboard_state.add_event({
                                    "action": "block",
                                    "tool": tool_name,
                                    "agent": "claude-desktop",
                                    "reason": f"Unauthorized SPIFFE ID '{spiffe_id}'",
                                    "severity": "high",
                                    "stage": "spiffe-auth",
                                    "timestamp": time.time()
                                })

                                error_resp = {
                                    "jsonrpc": "2.0",
                                    "id": data.get("id"),
                                    "error": {
                                        "code": -32002,
                                        "message": "Tool blocked due to untrusted SPIFFE identity",
                                        "data": {
                                            "spiffe_id": spiffe_id,
                                            "allowed_ids": sorted(list(ALLOWED_SPIFFE_IDS))
                                        }
                                    }
                                }

                                sys.stdout.write(json.dumps(error_resp) + "\n")
                                sys.stdout.flush()
                                continue

                            args["_spiffe"] = {
                                "bridge_id": spiffe_cfg["bridge_id"],
                                "expected_server_id": spiffe_cfg["server_id"],
                                "presented_id": spiffe_id
                            }

                        # ROLE CHECK
                        user_role = normalize_role(args.get("role", DEFAULT_ROLE))
                        allowed, required = role_allowed(tool_name, user_role)

                        if not allowed:
                            log(f"🚫 Role violation: {user_role} cannot use {tool_name}")

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