"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyEngine = void 0;
class PolicyEngine {
    constructor() { }
    async evaluate(toolName, args, context) {
        // --- IDENTITY-CENTRIC POLICY RULES ---
        // Rule 1: High Risk Tools (Write) -> ADMIN ONLY
        const highRiskTools = ["write_file_vulnerable", "keycloak_revoke_user_sessions"];
        if (highRiskTools.includes(toolName)) {
            if (!context.roles.includes("admin")) {
                // VIOLATION: User is not admin
                return false;
            }
        }
        // Rule 2: Medium Risk (List Directory) -> Authenticated Users Only (Simplified)
        if (toolName === "list_directory_vulnerable") {
            // Allow for now, since we have Path Canonicalization as a second layer
            // But maybe restrict root listing?
        }
        return true;
    }
}
exports.PolicyEngine = PolicyEngine;
