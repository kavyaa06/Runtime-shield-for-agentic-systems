"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerTools = registerTools;
const zod_1 = require("zod");
const keycloak_1 = require("../utils/keycloak");
function registerTools(server) {
    // Helper to resolve ID from username
    const resolveUserId = async (kc, userId, username) => {
        if (userId)
            return userId;
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
    server.tool("keycloak_get_user_events", {
        userId: zod_1.z.string().optional().describe("Filter by specific User ID"),
        username: zod_1.z.string().optional().describe("Filter by Username"),
        limit: zod_1.z.number().optional().default(50).describe("Number of events to fetch"),
    }, async ({ userId, username, limit }) => {
        const kc = await (0, keycloak_1.getKcClient)();
        const targetId = (userId || username) ? await resolveUserId(kc, userId, username) : undefined;
        const realm = process.env.KEYCLOAK_REALM || "master";
        const events = await kc.realms.findEvents({ realm, user: targetId, max: limit });
        const simplifiedEvents = events.map((e) => ({
            time: new Date(e.time || 0).toISOString(),
            type: e.type,
            ipAddress: e.ipAddress,
            userId: e.userId,
        }));
        return { content: [{ type: "text", text: JSON.stringify(simplifiedEvents, null, 2) }] };
    });
    // Tool 2: List User Sessions
    server.tool("keycloak_list_user_sessions", {
        userId: zod_1.z.string().optional(),
        username: zod_1.z.string().optional(),
    }, async ({ userId, username }) => {
        const kc = await (0, keycloak_1.getKcClient)();
        const targetId = await resolveUserId(kc, userId, username);
        const sessions = await kc.users.listSessions({ id: targetId });
        return { content: [{ type: "text", text: JSON.stringify(sessions, null, 2) }] };
    });
    // Tool 3: Revoke User Sessions
    server.tool("keycloak_revoke_user_sessions", {
        userId: zod_1.z.string().optional(),
        username: zod_1.z.string().optional(),
    }, async ({ userId, username }) => {
        const kc = await (0, keycloak_1.getKcClient)();
        const targetId = await resolveUserId(kc, userId, username);
        await kc.users.logout({ id: targetId });
        return { content: [{ type: "text", text: `Revoked sessions for ${targetId}` }] };
    });
}
