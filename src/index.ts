import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools/tools.js";
import { initSpiffe } from "./tools/spiffeAuth.js";
import { startMetricsServer } from "./utils/metrics.js";
import { logger } from "./utils/logger.js";
import dotenv from "dotenv";
import path from "path";

const envPath = path.resolve(__dirname, '../.env');
dotenv.config({ path: envPath });

if (!process.env.KEYCLOAK_URL) {
    logger.error("Error: KEYCLOAK_URL not found in environment variables.");
    logger.error("Make sure you are running the server from the project root.");
    logger.error(`Current directory: ${process.cwd()}`);
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
    // 1. Startup Socket Validation for SPIFFE
    initSpiffe();
    
    // 2. Start Prometheus Metrics
    startMetricsServer();

    // 3. Connect standard IO
    const transport = new StdioServerTransport();
    await server.connect(transport);
    
    logger.info("Keycloak MCP Server successfully started and running on stdio");
}

main().catch((error) => {
    logger.error(`Fatal error in main(): ${error.message}`);
    process.exit(1);
});
