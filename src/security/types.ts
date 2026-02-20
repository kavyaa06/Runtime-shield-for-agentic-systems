export interface UserContext {
    userId: string;
    username: string;
    roles: string[];
    homeDir: string;
    ipAddress?: string;
    token?: string;
}
