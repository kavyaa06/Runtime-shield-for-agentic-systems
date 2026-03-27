import { z } from "zod";
import { getKcClient } from "../utils/keycloak";
import { verifySpiffeIdentity } from "./spiffeAuth";

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
   Common Security Check
----------------------------- */
async function authorize(action: string) {
  // 🔐 Step 1: SPIFFE Authentication
  const identity = await verifySpiffeIdentity();

  if (!identity.valid || !identity.spiffe_id) {
    throw new Error("❌ Unauthorized: Invalid SPIFFE identity");
  }

  // 🛡️ Step 2: RBAC is handled primarily by bridge.py!

  return identity;
}

/* -----------------------------
   Register tools
----------------------------- */
export function registerTools(server: any) {

  /* -----------------------------
     LIST USER SESSIONS
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

        // 🔐 Security Check
        await authorize("list-sessions");

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
              text: `❌ Session error: ${err.message}`
            }
          ]
        };
      }
    }
  );

  /* -----------------------------
     REVOKE USER SESSIONS
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

        // 🔐 Security Check
        await authorize("revoke-sessions");

        const kc = await getKcClient();

        const targetId = await resolveUserId(
          kc,
          params.userId,
          params.username
        );

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
     GET USER EVENTS
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

        // 🔐 Security Check
        await authorize("view-events");

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
              text: `❌ Event error: ${err.message}`
            }
          ]
        };
      }
    }
  );
}