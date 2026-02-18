import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools/tools.js";
import dotenv from "dotenv";

import path from "path";


const envPath = path.resolve(__dirname, '../.env');
dotenv.config({ path: envPath });

if (!process.env.KEYCLOAK_URL) {
    // If loading failed, try to debug why
    console.error("Error: KEYCLOAK_URL not found in environment variables.");
    console.error("Make sure you are running the server from the project root.");
    console.error("Current directory:", process.cwd());
}

// Create an MCP server instance
const server = new McpServer({
    name: "keycloak-mcp-server",
    version: "1.0.0",
});

// Register the Keycloak tools
registerTools(server);

// Connect via Stdio
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Keycloak MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
