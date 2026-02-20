import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getKcClient } from "../utils/keycloak";
// import { ShieldService } from "../shield/shield.js"; // DEPRECATED
import { RuntimeShield } from "../security/shield";
import { UserContext } from "../security/types";
import fs from "fs/promises";
import path from "path";

// Helper to get absolute path to workspace root
// Since we are compiling to CJS (no "type": "module"), __dirname works natively
// Structure: dist/tools/tools.js -> dist/tools -> dist -> root
// So we need to go up 2 levels
const PROJECT_ROOT = path.resolve(__dirname, "../../");
console.error(`[DEBUG] Resolved PROJECT_ROOT: ${PROJECT_ROOT}`);

export function registerTools(server: McpServer) {
    const shield = new RuntimeShield();

    // --- HELPER: The "Interceptor" Wrapper ---
    const withShield = (toolName: string, schema: any, handler: Function) => {
        server.tool(toolName, schema, async (args: any) => {
            // Context Logic: In a real app, this comes from an Auth Token.
            // For this demo (stdio), we derive it from args/environment or assume a default "Session".

            // FIX: Use Absolute Path for Sandbox
            const sandboxRoot = path.resolve(PROJECT_ROOT, "sandbox");

            const context: UserContext = {
                userId: args.userId || "unknown-id",
                username: args.username || "guest",
                roles: args.username === "admin" ? ["admin", "user"] : ["user"], // Mock Role derivation
                homeDir: path.resolve(sandboxRoot, args.username || "guest"),
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
    // --- THE VULNERABLE TOOL (DEMO) ---
    // This tool mimics the "Directory Traversal" vulnerability.
    // It blindly reads whatever path is passed to it.
    withShield(
        "read_file_vulnerable",
        {
            path: z.string().describe("The file path to read (Relative to workspace)"),
            username: z.string().describe("The user requesting access (for context)"),
        },
        async ({ path: filePath }: any) => {
            // VULNERABLE LOGIC: Naive path joining
            // Python equivalent: full_path = os.path.join(workspace_dir, relative_path)

            // FIX: Use PROJECT_ROOT instead of process.cwd()
            const fullPath = path.resolve(PROJECT_ROOT, filePath);

            // INTENTIONAL VULNERABILITY: No check if fullPath startsWith(workspace)
            const content = await fs.readFile(fullPath, "utf-8");
            return {
                content: [{ type: "text", text: content }]
            };
        }
    );

    // VULNERABILITY: write_file (Path Traversal)
    withShield(
        "write_file_vulnerable",
        {
            path: z.string().describe("The file path to write"),
            content: z.string().describe("Content to write"),
            username: z.string().describe("The user requesting access"),
        },
        async ({ path: filePath, content }: any) => {
            // FIX: Use PROJECT_ROOT instead of process.cwd()
            const fullPath = path.resolve(PROJECT_ROOT, filePath);

            // INTENTIONAL VULNERABILITY: No scope check
            await fs.mkdir(path.dirname(fullPath), { recursive: true });
            await fs.writeFile(fullPath, content, "utf-8");

            return {
                content: [{ type: "text", text: `Successfully wrote to ${filePath}` }]
            };
        }
    );

    // VULNERABILITY: list_directory (Path Traversal)
    withShield(
        "list_directory_vulnerable",
        {
            path: z.string().optional().default(".").describe("Directory to list"),
            username: z.string().describe("The user requesting access"),
        },
        async ({ path: dirPath }: any) => {
            // FIX: Use PROJECT_ROOT instead of process.cwd()
            const fullPath = path.resolve(PROJECT_ROOT, dirPath);

            // INTENTIONAL VULNERABILITY: No scope check
            const files = await fs.readdir(fullPath, { withFileTypes: true });
            const output = files.map(f => f.isDirectory() ? `📁 ${f.name}/` : `📄 ${f.name}`).join("\n");

            return {
                content: [{ type: "text", text: `Contents of ${dirPath}:\n\n${output}` }]
            };
        }
    );
}
