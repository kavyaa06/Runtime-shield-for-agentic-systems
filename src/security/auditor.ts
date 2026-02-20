
export class Auditor {
    constructor() { }

    startEvent(userId: string, tool: string, args: any): string {
        const requestId = `req-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        console.log(`[AUDIT] START | ID: ${requestId} | User: ${userId} | Tool: ${tool} | Args: ${JSON.stringify(args)}`);
        return requestId;
    }

    logSuccess(requestId: string, message: string): void {
        console.log(`[AUDIT] ALLOW | ID: ${requestId} | ${message}`);
    }

    logBlock(requestId: string, reason: string): void {
        console.error(`[AUDIT] BLOCK | ID: ${requestId} | Reason: ${reason}`);
    }
}
