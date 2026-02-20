import { UserContext } from "./types.js";

export class PolicyEngine {
    constructor() { }

    async evaluate(toolName: string, args: any, context: UserContext): Promise<boolean> {
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
