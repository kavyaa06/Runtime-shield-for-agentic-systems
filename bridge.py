import sys
import subprocess
import os
import signal
import argparse
import threading
import json
import time
import re
from mcp_firewall.sdk import Gateway
from mcp_firewall.dashboard.server import start_dashboard
from mcp_firewall.dashboard.app import state as dashboard_state
from dotenv import load_dotenv

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(PROJECT_DIR, "mcp-firewall.yaml")
DOTENV_PATH = os.path.join(PROJECT_DIR, ".env")
LOG_PATH = os.path.join(PROJECT_DIR, "bridge.log")
DISCOVERY_PATH = os.path.join(PROJECT_DIR, "discovery.log")

# Force UTF-8 for ALL streams on Windows to prevent 'charmap' crashes
if sys.platform == 'win32':
    import io
    sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

class FraudDetectionEngine:
    def __init__(self, learning_mode=False):
        self.agent_risk_scores = {}
        self.user_risk_scores = {} # Identity-aware risk tracking
        self.last_calls = {} # Deduplication cache: {agent: (tool, args, timestamp)}
        self.last_activity = {} # For cooldown/decay: {identifier: timestamp}
        self.lock = threading.Lock() # Ensure thread-safe access
        self.RISK_THRESHOLD = 50
        self.learning_mode = learning_mode
        self.DECAY_RATE = 5 # Points to remove per interval
        self.DECAY_INTERVAL = 60 # Seconds per decay step (1 minute)

        # Start background decay thread for real-time cooldown
        threading.Thread(target=self._decay_loop, daemon=True).start()

    def _decay_loop(self):
        """Proactively decay risk scores every minute even if no tools are called."""
        while True:
            time.sleep(10) # Check every 10s for responsiveness
            now = time.time()
            with self.lock:
                # Combine agents and users for check
                all_ids = list(self.agent_risk_scores.keys()) + list(self.user_risk_scores.keys())
                for entry in set(all_ids):
                    if entry not in self.last_activity:
                        continue
                    
                    elapsed = now - self.last_activity[entry]
                    if elapsed >= self.DECAY_INTERVAL:
                        # Perform decay
                        if entry in self.agent_risk_scores:
                            old_score = self.agent_risk_scores[entry]
                            if old_score > 0:
                                self.agent_risk_scores[entry] = max(0, old_score - self.DECAY_RATE)
                                log(f"📉 Fraud Engine: Agent {entry} risk cooled down from {old_score} to {self.agent_risk_scores[entry]}")
                        
                        if entry in self.user_risk_scores:
                            old_score = self.user_risk_scores[entry]
                            if old_score > 0:
                                self.user_risk_scores[entry] = max(0, old_score - self.DECAY_RATE)
                                log(f"📉 Fraud Engine: User {entry} risk cooled down from {old_score} to {self.user_risk_scores[entry]}")

                        self.last_activity[entry] = now # Reset timer after successful decay step

    def analyze(self, agent: str, decision, tool_name: str = None, tool_args: dict = None, user_id: str = None) -> tuple[bool, str, str, str]:
        action_val = decision.action.value if hasattr(decision.action, 'value') else str(decision.action)
        now = time.time()

        with self.lock:
            if agent not in self.agent_risk_scores:
                self.agent_risk_scores[agent] = 0
                self.last_activity[agent] = now
            
            if user_id and user_id not in self.user_risk_scores:
                self.user_risk_scores[user_id] = 0
                self.last_activity[user_id] = now
            
            # --- UPDATED: REFRESH ACTIVITY ---
            # (Decay is now handled by _decay_loop background thread)

            # Increase risk score based on static firewall triggers
            risk_increase = 0
            if action_val == "deny":
                # --- RISK DEDUPLICATION ---
                is_retry = False
                if tool_name and tool_args and agent in self.last_calls:
                    last_tool, last_args, last_time = self.last_calls[agent]
                    time_diff = now - last_time
                    
                    # Normalize arguments for comparison (e.g. paths trailing slashes)
                    current_args_norm = tool_args.copy()
                    last_args_norm = last_args.copy()
                    
                    for args_dict in [current_args_norm, last_args_norm]:
                        if "path" in args_dict:
                            # Strip trailing slashes and normalize separators
                            args_dict["path"] = os.path.normpath(args_dict["path"]).rstrip(os.path.sep)
                    
                    if last_tool == tool_name and last_args_norm == current_args_norm and (time_diff < 60):
                        is_retry = True
                
                if not is_retry:
                    risk_increase = 20 # User set this to 20
                else:
                    log(f"🛡️ Fraud Engine: Risk deduplicated for repeated call to {tool_name}")
                
                # Update last call cache
                if tool_name and tool_args:
                    self.last_calls[agent] = (tool_name, tool_args, now)
                    
            elif action_val == "redact":
                risk_increase = 10 # User set this to 10
                
            # Suppress risk score increments if in learning mode
            if self.learning_mode:
                risk_increase = 0

            self.agent_risk_scores[agent] += risk_increase
            if user_id:
                self.user_risk_scores[user_id] += risk_increase
                
            # Keep activity alive so cooldown starts AFTER the last call
            self.last_activity[agent] = now
            if user_id:
                self.last_activity[user_id] = now
                
            current_score = self.agent_risk_scores[agent]
            if user_id:
                current_score = max(current_score, self.user_risk_scores[user_id])
            
            # Determine if dynamic threshold is crossed
            if current_score >= self.RISK_THRESHOLD:
                return True, "deny", f"Fraud Engine Block: Risk Score ({current_score}) exceeded threshold ({self.RISK_THRESHOLD}).", "critical"
                
            return False, action_val, decision.reason, decision.severity.value if hasattr(decision.severity, 'value') else str(decision.severity)

def log_discovery(tool, args, agent):
    with open(DISCOVERY_PATH, "a", encoding="utf-8") as f:
        entry = {
            "timestamp": time.time(),
            "tool": tool,
            "args": args,
            "agent": agent,
            "proposed_rule": f"- name: auto-rule-{int(time.time())}\n  tool: \"{tool}\"\n  action: allow"
        }
        f.write(json.dumps(entry) + "\n")


def log(msg: str):
    timestamp = time.strftime('%H:%M:%S')
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg}\n")
    except Exception:
        pass
    
    try:
        print(msg, file=sys.stderr, flush=True)
    except UnicodeEncodeError:
        # Fallback for terminals that don't support UTF-8
        print(msg.encode('ascii', 'replace').decode('ascii'), file=sys.stderr, flush=True)


# Initialize log session
with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write(f"\n--- Secure Bridge Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")


# Load .env but don't override variables set in the terminal/environment
load_dotenv(dotenv_path=DOTENV_PATH, override=False)

SCRIPTS_DIR = os.path.join(os.environ.get('APPDATA', ''), 'Python', 'Python313', 'Scripts')
MCPWN_EXE = os.path.join(SCRIPTS_DIR, "mcpwn.exe")

# Fallback to sys.executable's scripts dir if not in user dir
if not os.path.exists(MCPWN_EXE):
    SCRIPTS_DIR = os.path.dirname(sys.executable)
    if os.path.exists(os.path.join(SCRIPTS_DIR, "Scripts")):
        SCRIPTS_DIR = os.path.join(SCRIPTS_DIR, "Scripts")
    MCPWN_EXE = os.path.join(SCRIPTS_DIR, "mcpwn.exe")


# =========================
# TOOL ROLE POLICY
# =========================

TOOL_ROLE_POLICY = {
    "keycloak_revoke_user_sessions": "admin",
    "keycloak_list_user_sessions": "analyst",
    "keycloak_list_users": "analyst",
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
        "server_id": os.getenv("SPIFFE_SERVER_ID", "spiffe://runtime-shield/secure-runtime-shield"),
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

def get_allowed_spiffe_ids():
    """Parse allowed SPIFFE IDs from environment variable."""
    allowed_ids_str = os.getenv(
        "ALLOWED_SPIFFE_IDS",
        "spiffe://runtime-shield/agent,spiffe://runtime-shield/dashboard,spiffe://runtime-shield/bridge,spiffe://runtime-shield/secure-runtime-shield"
    ).strip()
    
    # Handle both comma-separated and JSON array formats
    if allowed_ids_str.startswith("["):
        try:
            import json
            return set(json.loads(allowed_ids_str))
        except Exception:
            pass
    
    # Comma-separated format
    return set(id_.strip() for id_ in allowed_ids_str.split(",") if id_.strip())


ALLOWED_SPIFFE_IDS = get_allowed_spiffe_ids()


def spiffe_allowed(spiffe_id: str) -> bool:
    if not spiffe_id:
        return False
    
    # Check exact match first
    if spiffe_id in ALLOWED_SPIFFE_IDS:
        return True
    
    # Support prefix matching for dynamic SVIDs (e.g. spiffe://runtime-shield/spire/agent/x509pop/*)
    for allowed_pattern in ALLOWED_SPIFFE_IDS:
        if "*" in allowed_pattern:
            regex_pattern = re.escape(allowed_pattern).replace(r"\*", ".*")
            if re.fullmatch(regex_pattern, spiffe_id):
                return True
        elif spiffe_id.startswith(allowed_pattern):
            return True
            
    return False


# =========================
# MAIN
# =========================

def main():
    parser = argparse.ArgumentParser(description="MCP Security Bridge & Scanner")
    parser.add_argument("--scan", action="store_true", help="Only run the security scan")
    parser.add_argument("--learning", action="store_true", help="Enable Learning Mode (log unknown tools instead of blocking)")
    args = parser.parse_args()

    # Path to the node-based MCP server
    NODE_SERVER_PATH = os.path.join(PROJECT_DIR, "dist", "index.js")
    WORKSPACE_DIR = os.path.join(PROJECT_DIR, "secure-experiment-zone")

    if not os.path.exists(WORKSPACE_DIR):
        os.makedirs(WORKSPACE_DIR)

    os.makedirs(os.path.join(WORKSPACE_DIR, "claude-desktop"), exist_ok=True)

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

    # Toggling Learning Mode (Command Line or .env)
    is_learning = args.learning or os.getenv("LEARNING_MODE", "false").lower() == "true"
    
    # Initialize Fraud Detection Engine (Identity Aware & Resilience for AI agents)
    fraud_engine = FraudDetectionEngine(learning_mode=is_learning)
    if is_learning:
        log("📚 LEARNING MODE ACTIVE: Blocks will be discovered but not enforced (risk score = 0)")
    else:
        log("🕵️‍♂️ PROTECTION MODE ACTIVE: Fraud Engine will enforce risk limits")

    # Start the Dashboard with configurable port
    dashboard_port = int(os.getenv("DASHBOARD_PORT", "9090"))
    try:
        start_dashboard(port=dashboard_port)
        log(f"📊 Dashboard active at http://127.0.0.1:{dashboard_port}")
    except Exception as e:
        log(f"⚠️ Dashboard failed to start on port {dashboard_port}: {e}")
        log("ℹ️ Continuing without local dashboard (likely already running in another instance)")

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
                        tool_args = params.get("arguments", {}) or {}
                        
                        # Extract user_id if available (Identity Awareness)
                        user_id = tool_args.get("user_id") or tool_args.get("userId") or tool_args.get("username") or "unknown_user"

                                          # 1. SPIFFE CHECK
                        if spiffe_cfg["enabled"]:
                            spiffe_id = tool_args.get("spiffe_id", "") or tool_args.get("_spiffe_id", "")
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
                                        "message": "Tool blocked due to untrusted SPIFFE identity"
                                    }
                                }
                                sys.stdout.write(json.dumps(error_resp) + "\n")
                                sys.stdout.flush()
                                continue

                        # 2. ROLE CHECK
                        user_role = normalize_role(tool_args.get("role", DEFAULT_ROLE))
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
                                    "message": "Tool blocked due to insufficient role"
                                }
                            }
                            sys.stdout.write(json.dumps(error_resp) + "\n")
                            sys.stdout.flush()
                            continue

                        # 3. FIREWALL & FRAUD ENGINE CHECK
                        decision = gw.check(tool_name, tool_args, agent="claude-desktop")
                        
                        # Apply Fraud Detection Engine analysis (with risk deduplication)
                        fraud_blocked, final_action, final_reason, final_severity = fraud_engine.analyze(
                            agent="claude-desktop",
                            decision=decision,
                            tool_name=tool_name,
                            tool_args=tool_args,
                            user_id=user_id
                        )

                        if fraud_blocked:
                            decision.blocked = True
                            decision.action = final_action
                            decision.reason = final_reason
                            decision.severity = final_severity

                        # Handle learning mode (from command line or .env)
                        learning_allowed = False
                        if is_learning and decision.blocked:
                            log(f"📚 Learning mode: Logging blocked tool '{tool_name}'")
                            log_discovery(tool_name, tool_args, "claude-desktop")
                            learning_allowed = True
                        dashboard_state.add_event({
                            "action": decision.action.value if hasattr(decision.action, 'value') else str(decision.action),
                            "tool": tool_name,
                            "agent": "claude-desktop",
                            "reason": decision.reason,
                            "severity": decision.severity.value if hasattr(decision.severity, 'value') else str(decision.severity),
                            "stage": decision.stage,
                            "timestamp": time.time()
                        })

                        if decision.blocked and not learning_allowed:
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

                        params["arguments"] = tool_args
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
                    
                    # Manual Redaction Fallback (ensures emails are caught even if SDK matching lags)
                    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    manual_redacted = re.sub(email_pattern, '[REDACTED]', line_str)
                    
                    if redacted_result.modified:
                        log("✂️ FIREWALL REDACTED sensitive data")
                        line_str = redacted_result.content
                        
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
                    elif manual_redacted != line_str:
                        log("✂️ FIREWALL REDACTED sensitive data (Manual Fallback)")
                        line_str = manual_redacted
                        dashboard_state.add_event({
                            "action": "redact",
                            "tool": "(response)",
                            "agent": "claude-desktop",
                            "reason": "Email PII (Fallback)",
                            "severity": "medium",
                            "stage": "output-filter-fallback",
                            "timestamp": time.time()
                        })

                        if not line_str.endswith("\n"):
                            line_str += "\n"

                except Exception as e:
                    log(f"⚠️ Redaction error: {e}")

                try:
                    sys.stdout.write(line_str)
                    sys.stdout.flush()
                except UnicodeEncodeError:
                    # Fallback for Windows terminals failing on emojis
                    sys.stdout.write(line_str.encode('ascii', 'backslashreplace').decode('ascii'))
                    sys.stdout.flush()

        except Exception as e:
            log(f"🆘 ERROR: Output thread crashed: {e}")
            # Don't let a single encoding error kill the whole relay
            time.sleep(1) 

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