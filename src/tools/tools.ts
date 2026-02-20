import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getKcClient } from "../utils/keycloak";
// import { ShieldService } from "../shield/shield.js"; // DEPRECATED
import { RuntimeShield } from "../security/shield";
import { UserContext } from "../security/types";
import fs from "fs/promises";
import path from "path";

export function registerTools(server: McpServer) {
    const shield = new RuntimeShield();

    // --- HELPER: The "Interceptor" Wrapper ---
    const withShield = (toolName: string, schema: any, handler: Function) => {
        server.tool(toolName, schema, async (args: any) => {
            // Context Logic: In a real app, this comes from an Auth Token.
            // For this demo (stdio), we derive it from args/environment or assume a default "Session".
            const context: UserContext = {
                userId: args.userId || "unknown-id",
                username: args.username || "guest",
                roles: args.username === "admin" ? ["admin", "user"] : ["user"], // Mock Role derivation
                homeDir: path.resolve(process.cwd(), "sandbox", args.username || "guest"),
                ipAddress: args.simulateIp || "127.0.0.1"
            };

            try {
                // 1. INBOUND INTERCEPTION
                await shield.interceptRequest(toolName, args, context);

                // 2. TOOL EXECUTION
                const result = await handler(args);

                // 3. OUTBOUND INTERCEPTION
                const safeResult = await shield.interceptResult(result, context);

                return safeResult;

            } catch (error: any) {
                // Determine if it's a Block or generic error
                const isBlock = error.message.includes("[Shield]");
                return {
                    content: [{
                        type: "text",
                        text: isBlock ? `🛡️ SECURITY BLOCK: ${error.message}` : `Error: ${error.message}`
                    }],
                    isError: true,
                };
            }
        });
    };

    // Helper to resolve ID (Legacy helper, kept for compatibility)
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

    // --- TOOL DEFINITIONS ---

    // Tool 1: Get User Events
    withShield(
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
    withShield(
        "keycloak_list_user_sessions",
        {
            userId: z.string().optional(),
            username: z.string().optional(),
            simulateIp: z.string().optional(),
        },
        async ({ userId, username }: any) => {
            const kc = await getKcClient();
            const targetId = await resolveUserId(kc, userId, username);
            const sessions = await kc.users.listSessions({ id: targetId });
            return { content: [{ type: "text", text: JSON.stringify(sessions, null, 2) }] };
        }
    );

    // Tool 3: Revoke User Sessions
    withShield(
        "keycloak_revoke_user_sessions",
        {
            userId: z.string().optional(),
            username: z.string().optional(),
            simulateIp: z.string().optional(),
        },
        async ({ userId, username }: any) => {
            const kc = await getKcClient();
            const targetId = await resolveUserId(kc, userId, username);
            await kc.users.logout({ id: targetId });
            return { content: [{ type: "text", text: `Revoked sessions for ${targetId}` }] };
        }
    );

    // --- THE VULNERABLE TOOL (DEMO) ---
    // This tool mimics the "Directory Traversal" vulnerability.
    // It blindly reads whatever path is passed to it.
    withShield(
        "read_file_vulnerable",
        {
            path: z.string().describe("The file path to read"),
            username: z.string().describe("The user requesting access (for context)"),
        },
        async ({ path: filePath }: any) => {
            // VULNERABLE LOGIC: No checks! 
            // "I just work here, let me read the file."
            const content = await fs.readFile(filePath, "utf-8");
            return {
                content: [{ type: "text", text: content }]
            };
        }
    );
}

