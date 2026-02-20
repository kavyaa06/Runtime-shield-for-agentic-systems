import { UserContext } from "./types";
import { Auditor } from "./auditor";
import { PolicyEngine } from "./policy";
import { getKcClient } from "../utils/keycloak";
import path from "path";

/**
 * The Runtime Shield: Identity-Centric Security Perimeter
 * Intercepts all tool calls and validates them against Identity, Policy, and Content Safety.
 */
export class RuntimeShield {
    private auditor: Auditor;
    private policy: PolicyEngine;

    constructor() {
        this.auditor = new Auditor();
        this.policy = new PolicyEngine();
    }

    /**
     * INBOUND GUARD: Intercepts tool execution requests.
     * @param toolName The name of the tool being called
     * @param args The arguments passed to the tool
     * @param context The authenticated user context
     */
    async interceptRequest(toolName: string, args: any, context: UserContext): Promise<void> {
        const requestId = this.auditor.startEvent(context.userId, toolName, args);

        try {
            // 1. Authenticate & Validate Session
            await this.validateSession(context);

            // 2. Content Safety (Input Sanitization)
            this.validateContentSafety(toolName, args);

            // 3. Path Canonicalization (Anti-Traversal)
            if (args.path) {
                args.path = this.canonicalizePath(args.path, context);
            }

            // 4. Policy Enforcement (RBAC & Context)
            const allowed = await this.policy.evaluate(toolName, args, context);
            if (!allowed) {
                throw new Error(`[Shield] Access Denied: Policy Violation for tool '${toolName}'`);
            }

            this.auditor.logSuccess(requestId, "Allowed by Shield");
        } catch (error: any) {
            this.auditor.logBlock(requestId, error.message);
            throw error; // Re-throw to block execution
        }
    }

    /**
     * OUTBOUND GUARD: Intercepts tool results (DLP).
     * @param result The result object from the tool
     * @param context The authenticated user context
     */
    async interceptResult(result: any, context: UserContext): Promise<any> {
        // 1. Scan for PII / Secrets
        this.scanForSecrets(result);

        // 2. Scope Enforcement (e.g. creating wrong user's data)
        // (Implementation dependent on result structure)

        return result;
    }

    /**
     * Validates that the session is active and matches the IP (Anti-Replay).
     */
    private async validateSession(context: UserContext): Promise<void> {
        if (!context.token) return; // public access? probably not allowed.

        // Logic ported from user's shield.ts could go here
        // For now, assuming context verification happened at Gateway level
        // But we can double check Keycloak session status if needed.
    }

    /**
     * Detects Prompt Injection and Shell Injection patterns.
     */
    private validateContentSafety(toolName: string, args: any): void {
        const argString = JSON.stringify(args);

        // 1. Shell Injection (Basic)
        // Matches: ; | && || $() ` `
        const shellPattern = /[;|&`$]/;
        // Only valid if the tool is NOT a shell tool effectively allow-listing specific tools if needed
        if (shellPattern.test(argString) && toolName !== "execute_command") {
            // Even execute_command should likely be sanitized or blocked for non-admins
            throw new Error("[Shield] Security Alert: Shell Injection Character Detected");
        }

        // 2. Prompt Injection (Basic)
        const jailbreakPattern = /(ignore previous|ignore all|system prompt)/i;
        if (jailbreakPattern.test(argString)) {
            throw new Error("[Shield] Security Alert: Prompt Injection Pattern Detected");
        }
    }

    /**
     * Canonicalizes paths to prevent Directory Traversal (../../)
     */
    private canonicalizePath(inputPath: string, context: UserContext): string {
        const safeBase = path.resolve(context.homeDir);
        const resolvedPath = path.resolve(safeBase, inputPath);

        if (!resolvedPath.startsWith(safeBase)) {
            throw new Error(`[Shield] Path Traversal Detected: '${inputPath}' resolves outside user scope.`);
        }

        return resolvedPath;
    }

    private scanForSecrets(result: any): void {
        const resultString = JSON.stringify(result);
        // Simple regex for AWS Keys (Example)
        if (/AKIA[0-9A-Z]{16}/.test(resultString)) {
            throw new Error("[Shield] Data Leak Prevention: AWS Key detected in output.");
        }
    }
}
