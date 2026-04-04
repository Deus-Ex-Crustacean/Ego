import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { Database } from "bun:sqlite";

// Use in-memory DB for tests by overriding before imports
process.env.DB_PATH = ":memory:";
process.env.PORT = "0"; // Let OS pick a port

// We need to re-wire the DB. Since modules are cached, we'll do a full integration test
// by starting the server and hitting it with fetch.

let server: ReturnType<typeof Bun.serve>;
let baseUrl: string;
let bootstrapToken: string;
let adminSecret: string;
let adminJwt: string;
let adminId: string;

beforeAll(async () => {
  // Capture console.log to grab bootstrap token
  const originalLog = console.log;
  const logs: string[] = [];
  console.log = (...args: any[]) => {
    logs.push(args.join(" "));
    originalLog(...args);
  };

  // Fresh DB setup - reimport with memory DB
  // We need to reset the module cache for db.ts to pick up :memory:
  // Easiest: just inline the setup here

  const { initDb, db } = await import("./db.ts");
  const { generateKeyPair } = await import("./crypto.ts");
  const { initBootstrap } = await import("./bootstrap.ts");
  const { handleToken } = await import("./routes/token.ts");
  const { handleOpenIdConfig, handleJwks } = await import("./routes/wellknown.ts");
  const { handleCreateUser, handleListUsers, handleGetUser, handleUpdateUser, handleDeleteUser } = await import("./routes/users.ts");
  const { handleCreateGroup, handleListGroups, handleGetGroup, handleUpdateGroup, handleDeleteGroup, handleAddMember, handleRemoveMember } = await import("./routes/groups.ts");
  const { handleCreateScimTarget, handleListScimTargets, handleDeleteScimTarget } = await import("./routes/scim-targets.ts");
  const { handleListKeys, handleRotateKey } = await import("./routes/keys.ts");

  initDb();
  initBootstrap();

  // Generate initial signing key
  const keyCount = db.query("SELECT COUNT(*) as count FROM signing_keys").get() as { count: number };
  if (keyCount.count === 0) {
    const { id, privateKey, publicKey } = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    db.query("INSERT INTO signing_keys (id, private_key, public_key, active, created_at) VALUES (?, ?, ?, 1, ?)").run(id, privateKey, publicKey, now);
  }

  // Extract bootstrap token from logs
  bootstrapToken = logs.find((l) => /^[a-f0-9]{64}$/.test(l.trim()))?.trim() || "";

  console.log = originalLog;

  // Parameterized routes
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

  function matchRoute(method: string, pathname: string): ((req: Request) => Response | Promise<Response>) | null {
    if (method === "POST" && pathname === "/token") return handleToken;
    if (method === "GET" && pathname === "/.well-known/openid-configuration") return handleOpenIdConfig;
    if (method === "GET" && pathname === "/.well-known/jwks.json") return handleJwks;
    if (method === "POST" && pathname === "/admin/users") return handleCreateUser;
    if (method === "GET" && pathname === "/admin/users") return handleListUsers;
    if (method === "POST" && pathname === "/admin/groups") return handleCreateGroup;
    if (method === "GET" && pathname === "/admin/groups") return handleListGroups;
    if (method === "POST" && pathname === "/admin/scim-targets") return handleCreateScimTarget;
    if (method === "GET" && pathname === "/admin/scim-targets") return handleListScimTargets;
    if (method === "GET" && pathname === "/admin/keys") return handleListKeys;
    if (method === "POST" && pathname === "/admin/keys/rotate") return handleRotateKey;
    return null;
  }

  server = Bun.serve({
    port: 0,
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

  baseUrl = `http://localhost:${server.port}`;
});

afterAll(() => {
  server?.stop();
});

// Helpers
function post(path: string, body: object, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function get(path: string, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, { headers });
}

function patch(path: string, body: object, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function del(path: string, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, { method: "DELETE", headers });
}

function auth() {
  return { Authorization: `Bearer ${adminJwt}` };
}

// ─── Bootstrap Flow ───

describe("bootstrap", () => {
  test("bootstrap token was generated", () => {
    expect(bootstrapToken).toMatch(/^[a-f0-9]{64}$/);
  });

  test("admin endpoints reject unauthenticated requests", async () => {
    const res = await get("/admin/users");
    expect(res.status).toBe(401);
  });

  test("create first admin user with bootstrap token", async () => {
    const res = await post(
      "/admin/users",
      { username: "admin" },
      { "X-Bootstrap-Token": bootstrapToken }
    );
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.username).toBe("admin");
    expect(body.admin).toBe(true);
    expect(body.client_secret).toMatch(/^[a-f0-9]{64}$/);
    adminSecret = body.client_secret;
    adminId = body.id;
  });

  test("bootstrap token is consumed — cannot reuse", async () => {
    const res = await post(
      "/admin/users",
      { username: "admin2" },
      { "X-Bootstrap-Token": bootstrapToken }
    );
    expect(res.status).toBe(401);
  });
});

// ─── Token Endpoint ───

describe("POST /token", () => {
  test("client_credentials grant returns JWT", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: "admin",
        client_secret: adminSecret,
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toBeDefined();
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
    adminJwt = body.access_token;
  });

  test("rejects wrong secret", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: "admin",
        client_secret: "wrong",
      }),
    });
    expect(res.status).toBe(401);
  });

  test("rejects unsupported grant type", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: "admin",
        client_secret: adminSecret,
      }),
    });
    expect(res.status).toBe(400);
  });

  test("JSON body also works", async () => {
    const res = await post("/token", {
      grant_type: "client_credentials",
      client_id: "admin",
      client_secret: adminSecret,
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toBeDefined();
  });
});

// ─── Well-Known ───

describe("well-known endpoints", () => {
  test("OIDC discovery", async () => {
    const res = await get("/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.issuer).toBeDefined();
    expect(body.jwks_uri).toContain("/.well-known/jwks.json");
    expect(body.grant_types_supported).toContain("client_credentials");
  });

  test("JWKS", async () => {
    const res = await get("/.well-known/jwks.json");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.keys).toBeArray();
    expect(body.keys.length).toBeGreaterThanOrEqual(1);
    expect(body.keys[0].kty).toBe("RSA");
    expect(body.keys[0].kid).toBeDefined();
  });
});

// ─── Users CRUD ───

describe("admin users", () => {
  let machineUserId: string;

  test("create machine user", async () => {
    const res = await post("/admin/users", { username: "svc-deploy", machine: true }, auth());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.username).toBe("svc-deploy");
    expect(body.admin).toBe(false);
    expect(body.client_secret).toMatch(/^[a-f0-9]{64}$/);
    machineUserId = body.id;
  });

  test("list users", async () => {
    const res = await get("/admin/users", auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.length).toBe(2);
  });

  test("get user by id", async () => {
    const res = await get(`/admin/users/${machineUserId}`, auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.username).toBe("svc-deploy");
  });

  test("update user", async () => {
    const res = await patch(`/admin/users/${machineUserId}`, { active: false }, auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.active).toBe(false);
  });

  test("duplicate username rejected", async () => {
    const res = await post("/admin/users", { username: "admin" }, auth());
    expect(res.status).toBe(409);
  });

  test("delete user", async () => {
    const res = await del(`/admin/users/${machineUserId}`, auth());
    expect(res.status).toBe(204);

    const check = await get(`/admin/users/${machineUserId}`, auth());
    expect(check.status).toBe(404);
  });

  test("non-admin JWT rejected", async () => {
    // Create a non-admin user, get their token, try to list users
    const createRes = await post("/admin/users", { username: "nonadmin", admin: false }, auth());
    const { client_secret: secret } = await createRes.json();

    const tokenRes = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: "nonadmin",
        client_secret: secret,
      }),
    });
    const { access_token } = await tokenRes.json();

    const res = await get("/admin/users", { Authorization: `Bearer ${access_token}` });
    expect(res.status).toBe(403);
  });
});

// ─── Groups CRUD ───

describe("admin groups", () => {
  let groupId: string;

  test("create group", async () => {
    const res = await post("/admin/groups", { name: "engineers" }, auth());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.name).toBe("engineers");
    groupId = body.id;
  });

  test("list groups", async () => {
    const res = await get("/admin/groups", auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.length).toBe(1);
  });

  test("get group by id", async () => {
    const res = await get(`/admin/groups/${groupId}`, auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.name).toBe("engineers");
    expect(body.members).toBeArray();
  });

  test("add member to group", async () => {
    const res = await post(`/admin/groups/${groupId}/members`, { userId: adminId }, auth());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.members).toContain(adminId);
  });

  test("duplicate member rejected", async () => {
    const res = await post(`/admin/groups/${groupId}/members`, { userId: adminId }, auth());
    expect(res.status).toBe(409);
  });

  test("remove member from group", async () => {
    const res = await del(`/admin/groups/${groupId}/members/${adminId}`, auth());
    expect(res.status).toBe(204);
  });

  test("update group", async () => {
    const res = await patch(`/admin/groups/${groupId}`, { name: "platform" }, auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.name).toBe("platform");
  });

  test("delete group", async () => {
    const res = await del(`/admin/groups/${groupId}`, auth());
    expect(res.status).toBe(204);

    const check = await get(`/admin/groups/${groupId}`, auth());
    expect(check.status).toBe(404);
  });
});

// ─── Groups in JWT ───

describe("groups in JWT", () => {
  test("JWT includes group membership", async () => {
    // Create group, add admin to it, get new token, verify groups claim
    const groupRes = await post("/admin/groups", { name: "admins-group" }, auth());
    const { id: gid } = await groupRes.json();
    await post(`/admin/groups/${gid}/members`, { userId: adminId }, auth());

    const tokenRes = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: "admin",
        client_secret: adminSecret,
      }),
    });
    const { access_token } = await tokenRes.json();

    // Decode JWT payload
    const payload = JSON.parse(atob(access_token.split(".")[1]));
    expect(payload.groups).toContain("admins-group");
  });
});

// ─── SCIM Targets ───

describe("admin scim-targets", () => {
  let targetId: string;

  test("create scim target", async () => {
    const res = await post("/admin/scim-targets", {
      name: "test-target",
      url: "https://scim.example.com/v2",
      token: "bearer-token-123",
    }, auth());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.name).toBe("test-target");
    expect(body.active).toBe(true);
    targetId = body.id;
  });

  test("list scim targets", async () => {
    const res = await get("/admin/scim-targets", auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.length).toBe(1);
  });

  test("delete scim target", async () => {
    const res = await del(`/admin/scim-targets/${targetId}`, auth());
    expect(res.status).toBe(204);

    const list = await get("/admin/scim-targets", auth());
    const body = await list.json();
    expect(body.length).toBe(0);
  });
});

// ─── Key Rotation ───

describe("key rotation", () => {
  test("rotate key", async () => {
    const res = await post("/admin/keys/rotate", {}, auth());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.active).toBe(true);
  });

  test("list keys shows old + new", async () => {
    const res = await get("/admin/keys", auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.length).toBeGreaterThanOrEqual(2);
    const active = body.filter((k: any) => k.active);
    const inactive = body.filter((k: any) => !k.active);
    expect(active.length).toBe(1);
    expect(inactive.length).toBeGreaterThanOrEqual(1);
  });

  test("old JWT still works after rotation", async () => {
    // adminJwt was signed with the old key
    const res = await get("/admin/users", auth());
    expect(res.status).toBe(200);
  });

  test("JWKS includes all keys", async () => {
    const res = await get("/.well-known/jwks.json");
    const body = await res.json();
    expect(body.keys.length).toBeGreaterThanOrEqual(2);
  });
});

// ─── 404 ───

describe("routing", () => {
  test("unknown route returns 404", async () => {
    const res = await get("/nonexistent");
    expect(res.status).toBe(404);
  });
});
