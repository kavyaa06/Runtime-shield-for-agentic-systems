import { z } from "zod";
import { getKcClient } from "../utils/keycloak";

/* -----------------------------
   Resolve userId
----------------------------- */
async function resolveUserId(kc: any, userId?: string, username?: string) {
  if (userId) return userId;

  if (!username) {
    throw new Error("Provide either userId or username");
  }

  const users = await kc.users.find({
    search: username,
    max: 20
  });

  const user = users.find(
    (u: any) => (u.username || "").toLowerCase() === username.toLowerCase()
  );

  if (!user) {
    throw new Error(`User '${username}' not found`);
  }

  return user.id;
}

/* -----------------------------
   Register tools
----------------------------- */
export function registerTools(server: any) {

  /* -----------------------------
     LIST USER SESSIONS (WORKING)
  ----------------------------- */
  server.tool(
    "keycloak_list_user_sessions",
    {
      username: z.string().optional(),
      userId: z.string().optional()
    },

    async (params: any) => {

      try {
        console.log("🔍 LIST SESSIONS CALLED");

        const kc = await getKcClient();

        const targetId = await resolveUserId(
          kc,
          params.userId,
          params.username
        );

        const sessions = await kc.users.listSessions({
          id: targetId
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(sessions || [], null, 2)
            }
          ]
        };

      } catch (err: any) {

        console.error("SESSION ERROR:", err);

        return {
          content: [
            {
              type: "text",
              text: `Session error: ${err.message}`
            }
          ]
        };
      }
    }
  );


  /* -----------------------------
     REVOKE USER SESSIONS (FIXED)
     ADMIN ONLY
  ----------------------------- */
  server.tool(
    "keycloak_revoke_user_sessions",
    {
      username: z.string().optional(),
      userId: z.string().optional()
    },

    async (params: any) => {

      try {
        console.log("🔍 REVOKE CALLED");

        /* 🔐 RBAC */
        const role = process.env.RUNTIME_ROLE || "analyst";

        if (role !== "admin") {
          return {
            content: [
              {
                type: "text",
                text: "❌ Only admin can revoke sessions"
              }
            ]
          };
        }

        const kc = await getKcClient();

        const targetId = await resolveUserId(
          kc,
          params.userId,
          params.username
        );

        /* ✅ DIRECT SDK CALL (NO HANG) */
        await kc.users.logout({
          id: targetId
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Sessions revoked for ${params.username || targetId}`
            }
          ]
        };

      } catch (err: any) {

        console.error("REVOKE ERROR:", err);

        return {
          content: [
            {
              type: "text",
              text: `❌ Revoke failed: ${err.message}`
            }
          ]
        };
      }
    }
  );


  /* -----------------------------
     GET USER EVENTS (WORKING)
  ----------------------------- */
  server.tool(
    "keycloak_get_user_events",
    {
      username: z.string().optional(),
      userId: z.string().optional(),
      limit: z.number().optional().default(20)
    },

    async (params: any) => {

      try {
        console.log("🔍 EVENTS CALLED");

        const kc = await getKcClient();

        const targetId = await resolveUserId(
          kc,
          params.userId,
          params.username
        );

        const realm = process.env.KEYCLOAK_REALM || "runtime-shield";

        const events = await kc.realms.findEvents({
          realm,
          user: targetId,
          max: params.limit
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(events || [], null, 2)
            }
          ]
        };

      } catch (err: any) {

        console.error("EVENT ERROR:", err);

        return {
          content: [
            {
              type: "text",
              text: `Event error: ${err.message}`
            }
          ]
        };
      }
    }
  );

}