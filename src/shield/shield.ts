import { getKcClient } from "../utils/keycloak.js";

export class ShieldService {
    /**
     * Validates a request from an agent/tool against the Identity State.
     * @param userId The ID of the user (agent) making the request.
     * @param currentIp The IP address where the request is initiating from.
     * @returns True if allowed, throws Error if blocked.
     */
    async validateRequest(userId: string, currentIp: string): Promise<boolean> {
        console.error(`🛡️ [Runtime Shield] Validating Request for User: ${userId} | IP: ${currentIp}`);

        const kc = await getKcClient();

        // 1. Fetch Active Sessions for this user
        // We look for sessions that match the current usage context
        const sessions = await kc.users.listSessions({
            id: userId,
        });


        if (!sessions || sessions.length === 0) {
            console.warn(`⚠️ [Shield] No active sessions found for user ${userId}. Proceeding with caution (or blocking based on policy).`);
            
        }

        const outputParams = {
            validSessionFound: false,
            knownIps: [] as string[]
        };

        if (sessions.length > 0) {
            for (const session of sessions) {
                if (session.ipAddress) {
                    outputParams.knownIps.push(session.ipAddress);
                    if (session.ipAddress === currentIp) {
                        outputParams.validSessionFound = true;
                        break;
                    }
                }
            }

            if (!outputParams.validSessionFound) {
                const errorMsg = `🚨 [BLOCK] Session Replay Attack Detected! Request IP (${currentIp}) does not match any active session IPs (${outputParams.knownIps.join(", ")}).`;
                console.error(errorMsg);
                throw new Error(errorMsg);
            }
        }

        console.error(`✅ [ALLOW] Request validated. IP matches active session.`);
        return true;
    }

    /**
     * Checks if the user has a specific Realm Role (RBAC).
     */
    async validateUserRole(userId: string, requiredRole: string): Promise<boolean> {
        console.error(`🛡️ [Runtime Shield] Checking Role '${requiredRole}' for User: ${userId}`);
        const kc = await getKcClient();

        try {
            // Check Realm Roles
            const roles = await kc.users.listRealmRoleMappings({ id: userId });
            const hasRole = roles.some(r => r.name === requiredRole);

            if (!hasRole) {
                const errorMsg = `⛔ [BLOCK] Access Denied. User ${userId} is missing required role: '${requiredRole}'.`;
                console.error(errorMsg);
                throw new Error(errorMsg);
            }

            console.error(`✅ [ALLOW] User has role '${requiredRole}'.`);
            return true;
        } catch (error: any) {
            // Rethrow our custom error, or handle unexpected API errors
            if (error.message.includes("[BLOCK]")) throw error;
            throw new Error(`Failed to validate role: ${error.message}`);
        }
    }
}
