import KcAdminClient from '@keycloak/keycloak-admin-client';

let cachedClient: KcAdminClient | null = null;
let lastLoginTime: number = 0;
const TOKEN_LIFESPAN_MS = 50 * 1000; // 50 seconds (safe margin)

export const getKcClient = async () => {
    const now = Date.now();

    if (cachedClient && (now - lastLoginTime < TOKEN_LIFESPAN_MS)) {
        console.error(">> Using EXISTING Cached Client (Token valid)");
        return cachedClient;
    }

    console.error(">> Authenticating NEW Client (Token expired or first run)");
    const kcAdminClient = new KcAdminClient({
        baseUrl: process.env.KEYCLOAK_URL,
        realmName: process.env.KEYCLOAK_REALM,
    });

    await kcAdminClient.auth({
        grantType: 'client_credentials',
        clientId: process.env.KEYCLOAK_CLIENT_ID!,
        clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
    });

    cachedClient = kcAdminClient;
    lastLoginTime = now;
    return kcAdminClient;
};
