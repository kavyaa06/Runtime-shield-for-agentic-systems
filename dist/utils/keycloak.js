"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getKcClient = void 0;
const keycloak_admin_client_1 = __importDefault(require("@keycloak/keycloak-admin-client"));
let cachedClient = null;
let lastLoginTime = 0;
const TOKEN_LIFESPAN_MS = 50 * 1000; // 50 seconds (safe margin)
const getKcClient = async () => {
    const now = Date.now();
    if (cachedClient && (now - lastLoginTime < TOKEN_LIFESPAN_MS)) {
        console.error(">> Using EXISTING Cached Client (Token valid)");
        return cachedClient;
    }
    console.error(">> Authenticating NEW Client (Token expired or first run)");
    const kcAdminClient = new keycloak_admin_client_1.default({
        baseUrl: process.env.KEYCLOAK_URL,
        realmName: process.env.KEYCLOAK_REALM,
    });
    await kcAdminClient.auth({
        grantType: 'client_credentials',
        clientId: process.env.KEYCLOAK_CLIENT_ID,
        clientSecret: process.env.KEYCLOAK_CLIENT_SECRET,
    });
    cachedClient = kcAdminClient;
    lastLoginTime = now;
    return kcAdminClient;
};
exports.getKcClient = getKcClient;
