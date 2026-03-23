import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getKcClient } from "../utils/keycloak.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function registerTools(server: McpServer) {

    // Helper to resolve ID from username
    const resolveUserId = async (kc: any, userId?: string, username?: string): Promise<string> => {
        if (userId) return userId;
        if (username) {
            const users = await kc.users.find({ username: username, exact: true });
            if (users.length > 0 && users[0].id) {
                return users[0].id;
            }
            throw new Error(`User '${username}' not found.`);
        }
        throw new Error("You must provide either 'userId' or 'username'.");
    };

    // Tool 1: Get User Events
    server.tool(
        "keycloak_get_user_events",
        {
            userId: z.string().optional().describe("Filter by specific User ID"),
            username: z.string().optional().describe("Filter by Username"),
            limit: z.number().optional().default(50).describe("Number of events to fetch"),
        },
        async ({ userId, username, limit }: any) => {
            const kc = await getKcClient();
            const targetId = (userId || username) ? await resolveUserId(kc, userId, username) : undefined;
            const realm = process.env.KEYCLOAK_REALM || "master";
            const events = await kc.realms.findEvents({ realm, user: targetId, max: limit });

            const simplifiedEvents = events.map((e: any) => ({
                time: new Date(e.time || 0).toISOString(),
                type: e.type,
                ipAddress: e.ipAddress,
                userId: e.userId,
            }));

            return { content: [{ type: "text", text: JSON.stringify(simplifiedEvents, null, 2) }] };
        }
    );

    // Tool 2: List User Sessions
    server.tool(
        "keycloak_list_user_sessions",
        {
            userId: z.string().optional(),
            username: z.string().optional(),
        },
        async ({ userId, username }: any) => {
            const kc = await getKcClient();
            const targetId = await resolveUserId(kc, userId, username);
            const sessions = await kc.users.listSessions({ id: targetId });
            return { content: [{ type: "text", text: JSON.stringify(sessions, null, 2) }] };
        }
    );

    // Tool 3: Revoke User Sessions
    server.tool(
        "keycloak_revoke_user_sessions",
        {
            userId: z.string().optional(),
            username: z.string().optional(),
        },
        async ({ userId, username }: any) => {
            const kc = await getKcClient();
            const targetId = await resolveUserId(kc, userId, username);
            await kc.users.logout({ id: targetId });
            return { content: [{ type: "text", text: `Revoked sessions for ${targetId}` }] };
        }
    );

    // Tool 4: Security Report
    server.tool(
        "keycloak_security_report",
        {},
        async () => {
            const projectRoot = path.resolve(__dirname, "../../");
            const logPath = path.join(projectRoot, "bridge.log");
            const discoveryPath = path.join(projectRoot, "discovery.log");

            let logContent = "";
            let discoveryContent = "";

            if (fs.existsSync(logPath)) logContent = fs.readFileSync(logPath, "utf-8");
            if (fs.existsSync(discoveryPath)) discoveryContent = fs.readFileSync(discoveryPath, "utf-8");

            const blocks = (logContent.match(/🚫 Blocked/g) || []).length;
            const redactions = (logContent.match(/✂️  FIREWALL REDACTED/g) || []).length;
            const discoveries = discoveryContent.split("\n").filter(l => l.trim()).length;

            const report = [
                "### 🛡️ MCP Shield: Security Posture Report",
                `- **Blocked Attacks**: ${blocks}`,
                `- **Sensitive Data Redactions**: ${redactions}`,
                `- **Newly Discovered Tools (Learning Mode)**: ${discoveries}`,
                "",
                "**Risk Assessment**: " + (blocks > 5 ? "🔴 High - Frequent unauthorized attempts detected." : "🟢 Low - System stable."),
                "**Recommendation**: Check `discovery.log` to authorize new tool patterns."
            ].join("\n");

            return { content: [{ type: "text", text: report }] };
        }
    );

    // Tool 5: Generate Policy (from Learning Mode)
    server.tool(
        "keycloak_generate_policy",
        {},
        async () => {
            const projectRoot = path.resolve(__dirname, "../../");
            const discoveryPath = path.join(projectRoot, "discovery.log");

            if (!fs.existsSync(discoveryPath) || fs.readFileSync(discoveryPath, "utf-8").trim() === "") {
                return { content: [{ type: "text", text: "No tool discoveries found. Run the bridge with --learning to discover new patterns." }] };
            }

            const discoveries = fs.readFileSync(discoveryPath, "utf-8")
                .split("\n")
                .filter(l => l.trim())
                .map(l => JSON.parse(l));

            const proposedRules = discoveries.map(d => d.proposed_rule).join("\n\n");

            const output = [
                "### 🧠 Proposed Firewall Rules",
                "Review and add these to your `mcp-firewall.yaml` rules section:",
                "```yaml",
                proposedRules,
                "```"
            ].join("\n");

            return { content: [{ type: "text", text: output }] };
        }
    );

    // Tool 6: Quarantine User (The Panic Button)
    server.tool(
        "keycloak_quarantine_user",
        {
            userId: z.string().optional(),
            username: z.string().optional(),
            reason: z.string().optional().default("Suspicious behavior detected"),
        },
        async ({ userId, username, reason }: any) => {
            const kc = await getKcClient();
            const targetId = await resolveUserId(kc, userId, username);
            
            // 1. Force Logout in Keycloak
            await kc.users.logout({ id: targetId });

            // 2. Add to dynamic_blocks in mcp-firewall.yaml
            const projectRoot = path.resolve(__dirname, "../../");
            const configPath = path.join(projectRoot, "mcp-firewall.yaml");
            
            try {
                let config = fs.readFileSync(configPath, "utf-8");
                const blockEntry = `  - user_id: "${targetId}"\n    reason: "${reason}"\n    timestamp: "${new Date().toISOString()}"`;
                
                if (config.includes("dynamic_blocks: []")) {
                    config = config.replace("dynamic_blocks: []", `dynamic_blocks:\n${blockEntry}`);
                } else {
                    config = config.replace("dynamic_blocks:", `dynamic_blocks:\n${blockEntry}`);
                }
                
                fs.writeFileSync(configPath, config);
                return { content: [{ type: "text", text: `🚨 QUARANTINED ${targetId}:\n- Sessions revoked in Keycloak\n- Identity added to Firewall Blocklist\n- Reason: ${reason}` }] };
            } catch (e) {
                return { content: [{ type: "text", text: `Partial success: Sessions revoked for ${targetId}, but failed to update firewall config: ${e}` }] };
            }
        }
    );
}
