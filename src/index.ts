import * as LaunchDarkly from "@launchdarkly/node-server-sdk";
import { Observability } from "@launchdarkly/observability-node";
import { initDb, db } from "./db.ts";
import { PORT } from "./config.ts";
import { generateKeyPair } from "./crypto.ts";
import { initBootstrap } from "./bootstrap.ts";
import { handleToken } from "./routes/token.ts";
import { handleOpenIdConfig, handleJwks } from "./routes/wellknown.ts";
import { handleCreateWorkspace, handleListWorkspaces, handleGetWorkspace, handleDeleteWorkspace } from "./routes/workspaces.ts";
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
  if (method === "POST" && pathname === "/token") return handleToken;
  if (method === "GET" && pathname === "/.well-known/openid-configuration") return handleOpenIdConfig;
  if (method === "GET" && pathname === "/.well-known/jwks.json") return handleJwks;
  if (method === "POST" && pathname === "/admin/workspaces") return handleCreateWorkspace;
  if (method === "GET" && pathname === "/admin/workspaces") return handleListWorkspaces;
  if (method === "GET" && pathname === "/admin/keys") return handleListKeys;
  if (method === "POST" && pathname === "/admin/keys/rotate") return handleRotateKey;
  return null;
}

const paramPatterns: Array<{
  method: string;
  pattern: RegExp;
  handler: (req: Request, ...params: string[]) => Response | Promise<Response>;
}> = [
  { method: "GET", pattern: /^\/admin\/workspaces\/([^/]+)$/, handler: handleGetWorkspace },
  { method: "DELETE", pattern: /^\/admin\/workspaces\/([^/]+)$/, handler: handleDeleteWorkspace },
];

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    const { method } = req;
    const { pathname } = url;
    try {
      const handler = matchRoute(method, pathname);
      if (handler) return await handler(req);
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
const ldSdkKey = process.env.LD_SDK_KEY;
if (!ldSdkKey) console.warn("LD_SDK_KEY not set — LaunchDarkly disabled");
const ldClient = ldSdkKey ? LaunchDarkly.init(ldSdkKey, {
  plugins: [new Observability({
    serviceName: "ego",
    serviceVersion: process.env.npm_package_version || "dev",
    environment: process.env.NODE_ENV || "production",
    consoleMethodsToRecord: ["warn", "error"],
  })],
}) : null;
export const ldContext: LaunchDarkly.LDContext = { kind: "service", key: "ego", name: "Ego" };

if (ldClient) {
  ldClient.on("ready", () => console.log("LaunchDarkly client ready"));
  ldClient.on("failed", (err) => console.error("LaunchDarkly client failed:", err));
}
process.on("SIGINT", async () => { await ldClient?.close(); process.exit(0); });
process.on("SIGTERM", async () => { await ldClient?.close(); process.exit(0); });
export { ldClient };
