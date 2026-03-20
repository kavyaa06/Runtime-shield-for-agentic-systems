"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getKcClient = getKcClient;
const keycloak_admin_client_1 = __importDefault(require("@keycloak/keycloak-admin-client"));
let kc = null;
async function getKcClient() {
    if (!kc) {
        kc = new keycloak_admin_client_1.default({
            baseUrl: process.env.KEYCLOAK_URL,
            realmName: process.env.KEYCLOAK_REALM
        });
    }
    // 🔥 ALWAYS AUTH (refresh token every time)
    await kc.auth({
        grantType: "client_credentials",
        clientId: process.env.KEYCLOAK_CLIENT_ID,
        clientSecret: process.env.KEYCLOAK_CLIENT_SECRET
    });
    return kc;
}
