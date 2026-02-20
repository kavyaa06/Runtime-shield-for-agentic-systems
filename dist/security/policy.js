"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyEngine = void 0;
class PolicyEngine {
    constructor() { }
    async evaluate(toolName, args, context) {
        // Default Policy: Allow All for now (until configured)
        // Ideally: Fetch rules from Keycloak or config file
        // Example: Only admins can use "delete_file"
        if (toolName === "delete_file" && !context.roles.includes("admin")) {
            return false;
        }
        // Example: Only support can use "read_logs"
        if (toolName === "read_logs" && !context.roles.includes("support")) {
            return false;
        }
        return true;
    }
}
exports.PolicyEngine = PolicyEngine;
