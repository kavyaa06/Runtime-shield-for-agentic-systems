"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Auditor = void 0;
class Auditor {
    constructor() { }
    startEvent(userId, tool, args) {
        const requestId = `req-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        console.error(`[AUDIT] START | ID: ${requestId} | User: ${userId} | Tool: ${tool} | Args: ${JSON.stringify(args)}`);
        return requestId;
    }
    logSuccess(requestId, message) {
        console.error(`[AUDIT] ALLOW | ID: ${requestId} | ${message}`);
    }
    logBlock(requestId, reason) {
        console.error(`[AUDIT] BLOCK | ID: ${requestId} | Reason: ${reason}`);
    }
}
exports.Auditor = Auditor;
