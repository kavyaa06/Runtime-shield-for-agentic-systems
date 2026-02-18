import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getKcClient } from "../utils/keycloak.js";
import { ShieldService } from "../shield/shield.js";

export function registerTools(server: McpServer) {
    const shield = new ShieldService();

    // Helper to resolve ID
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

    // Tool 1: Get User Events (Logs)
    server.tool(
        "keycloak_get_user_events",
        {
            userId: z.string().optional().describe("Filter by specific User ID"),
            username: z.string().optional().describe("Filter by Username"),
            limit: z.number().optional().default(50).describe("Number of events to fetch"),
        },
        async ({ userId, username, limit }) => {
            try {
                const kc = await getKcClient();
                const targetId = (userId || username) ? await resolveUserId(kc, userId, username) : undefined;

                const realm = process.env.KEYCLOAK_REALM || "master";
                const events = await kc.realms.findEvents({
                    realm: realm,
                    user: targetId,
                    max: limit,
                });

                const simplifiedEvents = events.map((e) => ({
                    time: new Date(e.time || 0).toISOString(),
                    type: e.type,
                    ipAddress: e.ipAddress,
                    userId: e.userId,
                    details: e.details,
                }));

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify(simplifiedEvents, null, 2),
                        },
                    ],
                };
            } catch (error: any) {
                return {
                    content: [{ type: "text", text: `Error fetching events: ${error.message}` }],
                    isError: true,
                };
            }
        }
    );

    // Tool 2: List User Sessions (PROTECTED BY SHIELD)
    server.tool(
        "keycloak_list_user_sessions",
        {
            userId: z.string().optional().describe("The User ID (UUID)"),
            username: z.string().optional().describe("The Username"),
            simulateIp: z.string().optional().describe("For testing: Simulate request coming from this IP"),
        },
        async ({ userId, username, simulateIp }) => {
            try {
                const kc = await getKcClient();
                const targetId = await resolveUserId(kc, userId, username);

                // --- RUNTIME SHIELD CHECK ---
                const currentRequestIp = simulateIp || "127.0.0.1";
                await shield.validateRequest(targetId, currentRequestIp);
                // ---------------------------

                const sessions = await kc.users.listSessions({
                    id: targetId,
                });

                const simplifiedSessions = sessions.map((s) => ({
                    id: s.id,
                    ipAddress: s.ipAddress,
                    start: new Date(s.start || 0).toISOString(),
                    lastAccess: new Date(s.lastAccess || 0).toISOString(),
                }));

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify(simplifiedSessions, null, 2),
                        },
                    ],
                };
            } catch (error: any) {
                return {
                    content: [{ type: "text", text: `Security Error: ${error.message}` }],
                    isError: true,
                };
            }
        }
    );

    // Tool 3: Revoke User Sessions (Kill Switch) (PROTECTED BY SHIELD)
    server.tool(
        "keycloak_revoke_user_sessions",
        {
            userId: z.string().optional().describe("The User ID to revoke sessions for"),
            username: z.string().optional().describe("The Username to revoke sessions for"),
            simulateIp: z.string().optional().describe("For testing: Simulate request coming from this IP"),
        },
        async ({ userId, username, simulateIp }) => {
            try {
                const kc = await getKcClient();
                const targetId = await resolveUserId(kc, userId, username);

                // --- RUNTIME SHIELD CHECK ---
                const currentRequestIp = simulateIp || "127.0.0.1";
                await shield.validateRequest(targetId, currentRequestIp);

                // RBAC CHECK: Only 'admin' role can revoke sessions
                await shield.validateUserRole(targetId, 'admin');
                // ---------------------------

                await kc.users.logout({ id: targetId });

                return {
                    content: [
                        {
                            type: "text",
                            text: `Successfully revoked all sessions for user ${username || targetId}.`,
                        },
                    ],
                };
            } catch (error: any) {
                return {
                    content: [{ type: "text", text: `Security Error: ${error.message}` }],
                    isError: true,
                };
            }
        }
    );
}
