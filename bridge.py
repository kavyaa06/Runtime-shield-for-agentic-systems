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

# Project absolute paths
PROJECT_DIR = r"c:\Users\kavya\OneDrive\Desktop\keycloak-mcp-server"
CONFIG_PATH = os.path.join(PROJECT_DIR, "mcp-firewall.yaml")
DOTENV_PATH = os.path.join(PROJECT_DIR, ".env")
LOG_PATH = os.path.join(PROJECT_DIR, "bridge.log")
DISCOVERY_PATH = os.path.join(PROJECT_DIR, "discovery.log")

class FraudDetectionEngine:
    def __init__(self):
        self.agent_risk_scores = {}
        self.user_risk_scores = {} # Identity-aware risk tracking
        self.RISK_THRESHOLD = 50

    def analyze(self, agent: str, decision, user_id: str = None) -> tuple[bool, str, str, str]:
        action_val = decision.action.value if hasattr(decision.action, 'value') else str(decision.action)

        if agent not in self.agent_risk_scores:
            self.agent_risk_scores[agent] = 0
        
        if user_id and user_id not in self.user_risk_scores:
            self.user_risk_scores[user_id] = 0
            
        # Increase risk score based on static firewall triggers
        risk_increase = 0
        if action_val == "deny":
            risk_increase = 25
        elif action_val == "redact":
            risk_increase = 15
            
        self.agent_risk_scores[agent] += risk_increase
        if user_id:
            self.user_risk_scores[user_id] += risk_increase
            
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

def log(msg):
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    print(msg, file=sys.stderr)

# Initialize Log
with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write(f"\n--- Secure Bridge Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

load_dotenv(DOTENV_PATH)

# Absolute paths to tool executables
SCRIPTS_DIR = r"C:\Users\kavya\AppData\Roaming\Python\Python313\Scripts"
MCPWN_EXE = os.path.join(SCRIPTS_DIR, "mcpwn.exe")

def main():
    parser = argparse.ArgumentParser(description="MCP Security Bridge & Scanner")
    parser.add_argument("--scan", action="store_true", help="Only run the security scan")
    parser.add_argument("--learning", action="store_true", help="Enable Learning Mode (log unknown tools instead of blocking)")
    args = parser.parse_args()

    # Path to the vulnerable Python MCP server
    VULNERABLE_SERVER_PATH = r"c:\Users\kavya\OneDrive\Desktop\keycloak-mcp-server\vulnerable-mcp-server-filesystem-workspace-actions-mcp.py"
    WORKSPACE_DIR = os.path.join(PROJECT_DIR, "sandbox")
    
    if not os.path.exists(WORKSPACE_DIR):
        os.makedirs(WORKSPACE_DIR)
        
    # Always ensure dummy folders and demo files exist for the demo
    os.makedirs(os.path.join(WORKSPACE_DIR, "claude-desktop"), exist_ok=True)
    with open(os.path.join(WORKSPACE_DIR, "claude-desktop", "log_export.csv"), "w") as f:
        f.write("user_id,login_time,session_token\n101,2024-02-23,Bearer test-token-1234567890abcdef\n")
    
    # Remove secrets.txt if it exists to avoid LLM refusal
    secrets_path = os.path.join(WORKSPACE_DIR, "claude-desktop", "secrets.txt")
    if os.path.exists(secrets_path):
        os.remove(secrets_path)
        
    server_cmd = [sys.executable, VULNERABLE_SERVER_PATH, WORKSPACE_DIR]

    if args.scan:
        log("🔍 Running security scan with mcpwn...")
        try:
            result = subprocess.run([MCPWN_EXE, "scan", "--stdio", " ".join(server_cmd)], cwd=PROJECT_DIR)
            sys.exit(result.returncode)
        except Exception as e:
            log(f"❌ Error running scanner: {e}")
            sys.exit(1)

    log(f"Starting Secure Bridge. Python: {sys.executable}")
    
    try:
        gw = Gateway(config_path=CONFIG_PATH)
        log("✅ Security Gateway initialized")
    except Exception as e:
        log(f"❌ Gateway init failed: {e}")
        sys.exit(1)

    # Initialize Fraud Detection Engine
    fraud_engine = FraudDetectionEngine()
    log("🕵️‍♂️ Fraud Detection Engine initialized")

    # Start the Dashboard
    try:
        start_dashboard()
        log("📊 Dashboard active at http://127.0.0.1:9090")
    except Exception as e:
        log(f"⚠️ Dashboard failed to start: {e}")

    # Start the original Node.js MCP server
    log(f"🚀 Launching Vulnerable Server: {' '.join(server_cmd)}")
    
    # Add startup event to dashboard
    dashboard_state.add_event({
        "action": "allow",
        "tool": "(system)",
        "agent": "bridge",
        "reason": "Security Bridge Started",
        "severity": "low",
        "stage": "startup",
        "timestamp": time.time()
    })

    node_proc = subprocess.Popen(
        server_cmd,
        cwd=PROJECT_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        bufsize=0
    )

    def input_to_node():
        """Reads from Claude (stdin), filters, and sends to Node."""
        try:
            for line in sys.stdin:
                if not line or not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    # Support both standard tools/call and generic callTool
                    method = data.get("method", "")
                    if method in ("tools/call", "callTool"):
                        params = data.get("params", {})
                        tool_name = params.get("name", "")
                        tool_args = params.get("arguments", {}) or {}
                        
                        # Extract user_id if available (Identity Awareness)
                        user_id = tool_args.get("user_id") or tool_args.get("userId") or tool_args.get("username")
                        if not user_id:
                            user_id = "unknown_user"

                        log(f"🔍 Checking tool call: {tool_name} (User: {user_id})")
                        decision = gw.check(tool_name, tool_args, agent="claude-desktop")

                        # Handle learning mode (using command-line args.learning)
                        learning_allowed = False
                        if args.learning and decision.blocked:
                            log(f"📚 Learning mode: Logging blocked tool '{tool_name}' instead of refusing.")
                            log_discovery(tool_name, tool_args, "claude-desktop")
                            learning_allowed = True

                        # Apply Fraud Detection Engine analysis
                        fraud_blocked, final_action, final_reason, final_severity = fraud_engine.analyze(
                            agent="claude-desktop",
                            decision=decision,
                            user_id=user_id
                        )

                        # Update decision based on fraud engine
                        if fraud_blocked:
                            decision.blocked = True
                            decision.action = final_action
                            decision.reason = final_reason
                            decision.severity = final_severity
                        
                        # Add to dashboard
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
                                "result": {
                                    "content": [{"type": "text", "text": f"[mcp-firewall] Blocked: {decision.reason}"}],
                                    "isError": True
                                }
                            }
                            sys.stdout.write(json.dumps(error_resp) + "\n")
                            sys.stdout.flush()
                            continue
                except Exception as e:
                    log(f"⚠️ Request check error: {e}")

                node_proc.stdin.write(line.encode('utf-8'))
                node_proc.stdin.flush()
        except Exception as e:
            log(f"Input thread error: {e}")

    def output_from_node():
        """Reads from Node (stdout), redacts, and sends to Claude."""
        try:
            for line in node_proc.stdout:
                line_str = line.decode('utf-8')
                if not line_str or not line_str.strip():
                    continue

                try:
                    # Scan and redact responses
                    redacted_result = gw.scan_response(line_str)
                    if redacted_result.modified:
                        log(f"✂️  FIREWALL REDACTED: Found sensitive data")
                        # Add redaction to dashboard
                        for finding in redacted_result.findings:
                            log(f"  - Finding: {finding.get('reason', 'Sensitive data')}")
                            dashboard_state.add_event({
                                "action": "redact",
                                "tool": "(response)",
                                "agent": "claude-desktop",
                                "reason": finding.get("reason", "Sensitive data"),
                                "severity": finding.get("severity", "medium"),
                                "stage": "output-filter",
                                "timestamp": time.time()
                            })
                        line_str = redacted_result.content + ("\n" if not redacted_result.content.endswith("\n") else "")
                except Exception as e:
                    log(f"⚠️ Redaction error: {e}")

                sys.stdout.write(line_str)
                sys.stdout.flush()
        except Exception as e:
            log(f"Output thread error: {e}")

    # Set up signal handling
    def cleanup(sig, frame):
        log("Cleaning up...")
        node_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Start threads
    t1 = threading.Thread(target=input_to_node, daemon=True)
    t2 = threading.Thread(target=output_from_node, daemon=True)
    t1.start()
    t2.start()

    log("⌛ Bridge active and relaying...")
    node_proc.wait()
    log(f"🏁 Server exited with code {node_proc.returncode}")

if __name__ == "__main__":
    main()
