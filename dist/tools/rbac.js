"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getUserRoles = getUserRoles;
exports.checkRole = checkRole;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
function getUserRoles(token) {
    const decoded = jsonwebtoken_1.default.decode(token);
    if (!decoded || !decoded.realm_access) {
        throw new Error("Invalid token");
    }
    return decoded.realm_access.roles || [];
}
function checkRole(userRoles, allowedRoles) {
    const allowed = userRoles.some(role => allowedRoles.includes(role));
    if (!allowed) {
        throw new Error("Unauthorized tool access");
    }
}
