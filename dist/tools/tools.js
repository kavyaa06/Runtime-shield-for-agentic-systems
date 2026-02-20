"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerTools = registerTools;
const zod_1 = require("zod");
const keycloak_1 = require("../utils/keycloak");
// import { ShieldService } from "../shield/shield.js"; // DEPRECATED
const shield_1 = require("../security/shield");
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
function registerTools(server) {
    const shield = new shield_1.RuntimeShield();
    // --- HELPER: The "Interceptor" Wrapper ---
    const withShield = (toolName, schema, handler) => {
        server.tool(toolName, schema, async (args) => {
            // Context Logic: In a real app, this comes from an Auth Token.
            // For this demo (stdio), we derive it from args/environment or assume a default "Session".
            const context = {
                userId: args.userId || "unknown-id",
                username: args.username || "guest",
                roles: args.username === "admin" ? ["admin", "user"] : ["user"], // Mock Role derivation
                homeDir: path_1.default.resolve(process.cwd(), "sandbox", args.username || "guest"),
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
            }
            catch (error) {
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
    // --- TOOL DEFINITIONS ---
    // Tool 1: Get User Events
    withShield("keycloak_get_user_events", {
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
    withShield("keycloak_list_user_sessions", {
        userId: zod_1.z.string().optional(),
        username: zod_1.z.string().optional(),
        simulateIp: zod_1.z.string().optional(),
    }, async ({ userId, username }) => {
        const kc = await (0, keycloak_1.getKcClient)();
        const targetId = await resolveUserId(kc, userId, username);
        const sessions = await kc.users.listSessions({ id: targetId });
        return { content: [{ type: "text", text: JSON.stringify(sessions, null, 2) }] };
    });
    // Tool 3: Revoke User Sessions
    withShield("keycloak_revoke_user_sessions", {
        userId: zod_1.z.string().optional(),
        username: zod_1.z.string().optional(),
        simulateIp: zod_1.z.string().optional(),
    }, async ({ userId, username }) => {
        const kc = await (0, keycloak_1.getKcClient)();
        const targetId = await resolveUserId(kc, userId, username);
        await kc.users.logout({ id: targetId });
        return { content: [{ type: "text", text: `Revoked sessions for ${targetId}` }] };
    });
    // --- THE VULNERABLE TOOL (DEMO) ---
    // This tool mimics the "Directory Traversal" vulnerability.
    // It blindly reads whatever path is passed to it.
    withShield("read_file_vulnerable", {
        path: zod_1.z.string().describe("The file path to read"),
        username: zod_1.z.string().describe("The user requesting access (for context)"),
    }, async ({ path: filePath }) => {
        // VULNERABLE LOGIC: No checks! 
        // "I just work here, let me read the file."
        const content = await promises_1.default.readFile(filePath, "utf-8");
        return {
            content: [{ type: "text", text: content }]
        };
    });
}
