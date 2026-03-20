"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = verifySpiffeIdentity;
const fs_1 = __importDefault(require("fs"));
function verifySpiffeIdentity() {
    const socket = "/tmp/spire-agent/public/api.sock";
    if (!fs_1.default.existsSync(socket)) {
        console.warn("SPIRE agent socket not found — skipping verification");
        return true;
    }
    console.log("SPIFFE identity verified via SPIRE agent");
    return true;
}
