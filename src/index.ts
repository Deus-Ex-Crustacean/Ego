import * as LaunchDarkly from "@launchdarkly/node-server-sdk";
import { Observability } from "@launchdarkly/observability-node";
import { initDb, db } from "./db.ts";
import { PORT } from "./config.ts";
import { generateKeyPair } from "./crypto.ts";
import { initBootstrap } from "./bootstrap.ts";
import { handleToken } from "./routes/token.ts";
import { handleOpenIdConfig, handleJwks } from "./routes/wellknown.ts";
import { handleCreateUser, handleListUsers, handleGetUser, handleUpdateUser, handleDeleteUser } from "./routes/users.ts";
import { handleCreateGroup, handleListGroups, handleGetGroup, handleUpdateGroup, handleDeleteGroup, handleAddMember, handleRemoveMember } from "./routes/groups.ts";
import { handleCreateScimTarget, handleListScimTargets, handleDeleteScimTarget } from "./routes/scim-targets.ts";
import { handleListKeys, handleRotateKey } from "./routes/keys.ts";

// Initialize
initDb();
initBootstrap();

// Ensure at least one signing key exists
const keyCount = db.query("SELECT COUNT(*) as count FROM signing_keys").get() as { count: number };
if (keyCount.count === 0) {
  const { id, privateKey, publicKey } = generateKeyPair();
  const now = Math.floor(Date.now() / 1000);
  db.query("INSERT INTO signing_keys (id, private_key, public_key, active, created_at) VALUES (?, ?, ?, 1, ?)").run(
    id, privateKey, publicKey, now
  );
  console.log("Generated initial signing key:", id);
}

// Router
function matchRoute(method: string, pathname: string): ((req: Request) => Response | Promise<Response>) | null {
  // Public routes
  if (method === "POST" && pathname === "/token") return handleToken;
  if (method === "GET" && pathname === "/.well-known/openid-configuration") return handleOpenIdConfig;
  if (method === "GET" && pathname === "/.well-known/jwks.json") return handleJwks;

  // Admin: Users
  if (method === "POST" && pathname === "/admin/users") return handleCreateUser;
  if (method === "GET" && pathname === "/admin/users") return handleListUsers;

  // Admin: Groups
  if (method === "POST" && pathname === "/admin/groups") return handleCreateGroup;
  if (method === "GET" && pathname === "/admin/groups") return handleListGroups;

  // Admin: SCIM Targets
  if (method === "POST" && pathname === "/admin/scim-targets") return handleCreateScimTarget;
  if (method === "GET" && pathname === "/admin/scim-targets") return handleListScimTargets;

  // Admin: Keys
  if (method === "GET" && pathname === "/admin/keys") return handleListKeys;
  if (method === "POST" && pathname === "/admin/keys/rotate") return handleRotateKey;

  return null;
}

// Parameterized route patterns
const paramPatterns: Array<{
  method: string;
  pattern: RegExp;
  handler: (req: Request, ...params: string[]) => Response | Promise<Response>;
}> = [
  { method: "GET", pattern: /^\/admin\/users\/([^/]+)$/, handler: handleGetUser },
  { method: "PATCH", pattern: /^\/admin\/users\/([^/]+)$/, handler: handleUpdateUser },
  { method: "DELETE", pattern: /^\/admin\/users\/([^/]+)$/, handler: handleDeleteUser },
  { method: "GET", pattern: /^\/admin\/groups\/([^/]+)$/, handler: handleGetGroup },
  { method: "PATCH", pattern: /^\/admin\/groups\/([^/]+)$/, handler: handleUpdateGroup },
  { method: "DELETE", pattern: /^\/admin\/groups\/([^/]+)$/, handler: handleDeleteGroup },
  { method: "POST", pattern: /^\/admin\/groups\/([^/]+)\/members$/, handler: handleAddMember },
  { method: "DELETE", pattern: /^\/admin\/groups\/([^/]+)\/members\/([^/]+)$/, handler: handleRemoveMember },
  { method: "DELETE", pattern: /^\/admin\/scim-targets\/([^/]+)$/, handler: handleDeleteScimTarget },
];

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    const { method } = req;
    const { pathname } = url;

    try {
      // Try exact match first
      const handler = matchRoute(method, pathname);
      if (handler) return await handler(req);

      // Try parameterized routes
      for (const route of paramPatterns) {
        if (route.method !== method) continue;
        const match = pathname.match(route.pattern);
        if (match) return await route.handler(req, ...match.slice(1));
      }

      return Response.json({ error: "not found" }, { status: 404 });
    } catch (err) {
      if (err instanceof Response) return err;
      console.error("Unhandled error:", err);
      return Response.json({ error: "internal server error" }, { status: 500 });
    }
  },
});

console.log(`Ego listening on port ${PORT}`);

// LaunchDarkly with Observability
const ldClient = LaunchDarkly.init("sdk-fadd54c8-967d-40ac-8848-e75fe4f28cb6", {
  plugins: [
    new Observability({
      serviceName: "ego",
      serviceVersion: process.env.npm_package_version || "dev",
      environment: "production",
    }),
  ],
});
const ldContext: LaunchDarkly.LDContext = { kind: "service", key: "ego", name: "Ego" };

ldClient.on("ready", () => {
  console.log("LaunchDarkly client ready");
});

ldClient.on("failed", (err) => {
  console.error("LaunchDarkly client failed to initialize:", err);
});

process.on("SIGINT", async () => {
  await ldClient.close();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  await ldClient.close();
  process.exit(0);
});

export { ldClient, ldContext };
