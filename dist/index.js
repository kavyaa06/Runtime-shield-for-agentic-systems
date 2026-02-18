"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const tools_js_1 = require("./tools/tools.js");
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const envPath = path_1.default.resolve(__dirname, '../.env');
dotenv_1.default.config({ path: envPath });
if (!process.env.KEYCLOAK_URL) {
    // If loading failed, try to debug why
    console.error("Error: KEYCLOAK_URL not found in environment variables.");
    console.error("Make sure you are running the server from the project root.");
    console.error("Current directory:", process.cwd());
}
// Create an MCP server instance
const server = new mcp_js_1.McpServer({
    name: "keycloak-mcp-server",
    version: "1.0.0",
});
// Register the Keycloak tools
(0, tools_js_1.registerTools)(server);
// Connect via Stdio
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("Keycloak MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
