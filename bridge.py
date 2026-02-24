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
    args = parser.parse_args()

    # Path to the vulnerable Python MCP server
    VULNERABLE_SERVER_PATH = r"c:\Users\kavya\OneDrive\Desktop\agentic AI\vulnerable-mcp-servers-lab\vulnerable-mcp-server-filesystem-workspace-actions\vulnerable-mcp-server-filesystem-workspace-actions-mcp.py"
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
                        args = params.get("arguments", {})
                        
                        log(f"🔍 Checking tool call: {tool_name}")
                        decision = gw.check(tool_name, args, agent="claude-desktop")
                        
                        # Add to dashboard
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
