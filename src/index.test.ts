import { describe, test, expect, beforeAll, afterAll } from "bun:test";

process.env.DB_PATH = ":memory:";
process.env.PORT = "0";

let server: ReturnType<typeof Bun.serve>;
let baseUrl: string;

// Tenant A state
let tenantAId: string;
let tenantABootstrap: string;
let adminASecret: string;
let adminAJwt: string;
let adminAId: string;

// Tenant B state
let tenantBId: string;
let tenantBBootstrap: string;
let adminBJwt: string;

beforeAll(async () => {
  const { initDb, db } = await import("./db.ts");
  const { generateKeyPair } = await import("./crypto.ts");
  const { handleToken } = await import("./routes/token.ts");
  const { handleOpenIdConfig, handleJwks } = await import("./routes/wellknown.ts");
  const { handleCreateUser, handleListUsers, handleGetUser, handleUpdateUser, handleDeleteUser } = await import("./routes/users.ts");
  const { handleCreateGroup, handleListGroups, handleGetGroup, handleUpdateGroup, handleDeleteGroup, handleAddMember, handleRemoveMember } = await import("./routes/groups.ts");
  const { handleCreateScimTarget, handleListScimTargets, handleDeleteScimTarget } = await import("./routes/scim-targets.ts");
  const { handleListKeys, handleRotateKey } = await import("./routes/keys.ts");
  const { handleCreateTenant, handleGetTenant } = await import("./routes/tenants.ts");

  initDb();

  const keyCount = db.query("SELECT COUNT(*) as count FROM signing_keys").get() as { count: number };
  if (keyCount.count === 0) {
    const { id, privateKey, publicKey } = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    db.query("INSERT INTO signing_keys (id, private_key, public_key, active, created_at) VALUES (?, ?, ?, 1, ?)").run(id, privateKey, publicKey, now);
  }

  const paramPatterns: Array<{
    method: string;
    pattern: RegExp;
    handler: (req: Request, ...params: string[]) => Response | Promise<Response>;
  }> = [
    { method: "GET", pattern: /^\/tenants\/([^/]+)$/, handler: handleGetTenant },
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
    if (method === "POST" && pathname === "/tenants") return handleCreateTenant;
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
        return Response.json({ error: "internal server error" }, { status: 500 });
      }
    },
  });

  baseUrl = `http://localhost:${server.port}`;
});

afterAll(() => server?.stop());

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
function authA() { return { Authorization: `Bearer ${adminAJwt}` }; }
function authB() { return { Authorization: `Bearer ${adminBJwt}` }; }

// ─── Tenant Creation ───

describe("tenant creation", () => {
  test("create tenant A — no auth required", async () => {
    const res = await post("/tenants", { name: "Acme Corp" });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.tenant.name).toBe("Acme Corp");
    expect(body.tenant.slug).toBe("acme-corp");
    expect(body.bootstrapToken).toMatch(/^[a-f0-9]{64}$/);
    tenantAId = body.tenant.id;
    tenantABootstrap = body.bootstrapToken;
  });

  test("create tenant B", async () => {
    const res = await post("/tenants", { name: "Beta Inc" });
    expect(res.status).toBe(201);
    const body = await res.json();
    tenantBId = body.tenant.id;
    tenantBBootstrap = body.bootstrapToken;
  });

  test("duplicate tenant name rejected", async () => {
    const res = await post("/tenants", { name: "Acme Corp" });
    expect(res.status).toBe(409);
  });

  test("name required", async () => {
    const res = await post("/tenants", {});
    expect(res.status).toBe(400);
  });
});

// ─── Bootstrap + Token ───

describe("bootstrap flow", () => {
  test("create admin A with tenant A bootstrap token", async () => {
    const res = await post(
      "/admin/users",
      { username: "admin-a" },
      { "X-Bootstrap-Token": tenantABootstrap }
    );
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.admin).toBe(true);
    expect(body.tenant_id).toBe(tenantAId);
    expect(body.client_secret).toMatch(/^[a-f0-9]{64}$/);
    adminASecret = body.client_secret;
    adminAId = body.id;
  });

  test("bootstrap token consumed — cannot reuse", async () => {
    const res = await post(
      "/admin/users",
      { username: "admin-a2" },
      { "X-Bootstrap-Token": tenantABootstrap }
    );
    expect(res.status).toBe(401);
  });

  test("bootstrap token is tenant-scoped — tenant B token creates tenant B user", async () => {
    const res = await post(
      "/admin/users",
      { username: "admin-b" },
      { "X-Bootstrap-Token": tenantBBootstrap }
    );
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.tenant_id).toBe(tenantBId);
    const secret = body.client_secret;

    const tokenRes = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "admin-b", client_secret: secret }),
    });
    const tokenBody = await tokenRes.json();
    adminBJwt = tokenBody.access_token;
    expect(adminBJwt).toBeDefined();
    const payload = JSON.parse(atob(adminBJwt.split(".")[1]));
    expect(payload.tenant_id).toBe(tenantBId);
  });

  test("get JWT for admin A", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "admin-a", client_secret: adminASecret }),
    });
    const body = await res.json();
    expect(body.access_token).toBeDefined();
    adminAJwt = body.access_token;
    const payload = JSON.parse(atob(adminAJwt.split(".")[1]));
    expect(payload.tenant_id).toBe(tenantAId);
  });
});

// ─── Token Endpoint ───

describe("POST /token", () => {
  test("wrong secret rejected", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "admin-a", client_secret: "wrong" }),
    });
    expect(res.status).toBe(401);
  });

  test("wrong grant type rejected", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: "admin-a", client_secret: adminASecret }),
    });
    expect(res.status).toBe(400);
  });

  test("JSON body works", async () => {
    const res = await post("/token", { grant_type: "client_credentials", client_id: "admin-a", client_secret: adminASecret });
    expect(res.status).toBe(200);
  });
});

// ─── Well-Known ───

describe("well-known", () => {
  test("OIDC discovery", async () => {
    const res = await get("/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.jwks_uri).toContain("/.well-known/jwks.json");
  });

  test("JWKS", async () => {
    const res = await get("/.well-known/jwks.json");
    const body = await res.json();
    expect(body.keys.length).toBeGreaterThanOrEqual(1);
    expect(body.keys[0].kty).toBe("RSA");
  });
});

// ─── Tenant Isolation ───

describe("tenant isolation", () => {
  let userAId: string;
  let groupAId: string;

  test("admin A can create user in tenant A", async () => {
    const res = await post("/admin/users", { username: "svc-a" }, authA());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.tenant_id).toBe(tenantAId);
    userAId = body.id;
  });

  test("admin A can list users — only sees tenant A users", async () => {
    const res = await get("/admin/users", authA());
    const users = await res.json();
    expect(users.every((u: any) => u.tenant_id === tenantAId)).toBe(true);
    // admin-b should NOT appear (different tenant)
    expect(users.find((u: any) => u.username === "admin-b")).toBeUndefined();
  });

  test("admin B cannot access tenant A user by id", async () => {
    const res = await get(`/admin/users/${userAId}`, authB());
    expect(res.status).toBe(404);
  });

  test("admin A can create group in tenant A", async () => {
    const res = await post("/admin/groups", { name: "engineers" }, authA());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.tenant_id).toBe(tenantAId);
    groupAId = body.id;
  });

  test("admin B cannot access tenant A group by id", async () => {
    const res = await get(`/admin/groups/${groupAId}`, authB());
    expect(res.status).toBe(404);
  });

  test("admin A can add tenant A user to tenant A group", async () => {
    const res = await post(`/admin/groups/${groupAId}/members`, { userId: userAId }, authA());
    expect(res.status).toBe(201);
  });

  test("admin B cannot delete tenant A group", async () => {
    const res = await del(`/admin/groups/${groupAId}`, authB());
    expect(res.status).toBe(404);
  });

  test("same group name allowed in different tenants", async () => {
    const res = await post("/admin/groups", { name: "engineers" }, authB());
    expect(res.status).toBe(201);
  });
});

// ─── Users CRUD ───

describe("users CRUD", () => {
  let userId: string;

  test("create user", async () => {
    const res = await post("/admin/users", { username: "svc-deploy" }, authA());
    expect(res.status).toBe(201);
    userId = (await res.json()).id;
  });

  test("get user", async () => {
    const res = await get(`/admin/users/${userId}`, authA());
    expect(res.status).toBe(200);
  });

  test("update user", async () => {
    const res = await patch(`/admin/users/${userId}`, { active: false }, authA());
    expect(res.status).toBe(200);
    expect((await res.json()).active).toBe(false);
  });

  test("duplicate username rejected", async () => {
    const res = await post("/admin/users", { username: "admin-a" }, authA());
    expect(res.status).toBe(409);
  });

  test("delete user", async () => {
    const res = await del(`/admin/users/${userId}`, authA());
    expect(res.status).toBe(204);
  });
});

// ─── Groups CRUD ───

describe("groups CRUD", () => {
  let groupId: string;
  let memberId: string;

  test("create group", async () => {
    const res = await post("/admin/groups", { name: "ops" }, authA());
    expect(res.status).toBe(201);
    groupId = (await res.json()).id;
  });

  test("list groups", async () => {
    const res = await get("/admin/groups", authA());
    const groups = await res.json();
    expect(groups.every((g: any) => g.tenant_id === tenantAId)).toBe(true);
  });

  test("add member", async () => {
    const userRes = await post("/admin/users", { username: "svc-ops" }, authA());
    memberId = (await userRes.json()).id;
    const res = await post(`/admin/groups/${groupId}/members`, { userId: memberId }, authA());
    expect(res.status).toBe(201);
    expect((await res.json()).members).toContain(memberId);
  });

  test("remove member", async () => {
    const res = await del(`/admin/groups/${groupId}/members/${memberId}`, authA());
    expect(res.status).toBe(204);
  });

  test("update group", async () => {
    const res = await patch(`/admin/groups/${groupId}`, { name: "platform" }, authA());
    expect(res.status).toBe(200);
    expect((await res.json()).name).toBe("platform");
  });

  test("delete group", async () => {
    const res = await del(`/admin/groups/${groupId}`, authA());
    expect(res.status).toBe(204);
  });
});

// ─── SCIM Targets ───

describe("scim-targets", () => {
  let targetId: string;

  test("create scim target", async () => {
    const res = await post("/admin/scim-targets", {
      name: "okta",
      url: "https://scim.example.com/v2",
      token: "tok-123",
    }, authA());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.tenant_id).toBe(tenantAId);
    targetId = body.id;
  });

  test("admin B cannot see tenant A scim targets", async () => {
    const res = await get("/admin/scim-targets", authB());
    const targets = await res.json();
    expect(targets.find((t: any) => t.id === targetId)).toBeUndefined();
  });

  test("invalid url rejected", async () => {
    const res = await post("/admin/scim-targets", {
      name: "bad",
      url: "not-a-url",
      token: "tok",
    }, authA());
    expect(res.status).toBe(400);
  });

  test("delete scim target", async () => {
    const res = await del(`/admin/scim-targets/${targetId}`, authA());
    expect(res.status).toBe(204);
  });
});

// ─── JWT contains tenant_id and groups ───

describe("JWT claims", () => {
  test("JWT includes tenant_id and groups", async () => {
    const groupRes = await post("/admin/groups", { name: "jwt-test-group" }, authA());
    const { id: gid } = await groupRes.json();
    await post(`/admin/groups/${gid}/members`, { userId: adminAId }, authA());

    const tokenRes = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "admin-a", client_secret: adminASecret }),
    });
    const { access_token } = await tokenRes.json();
    const payload = JSON.parse(atob(access_token.split(".")[1]));
    expect(payload.tenant_id).toBe(tenantAId);
    expect(payload.groups).toContain("jwt-test-group");
  });
});

// ─── Key Rotation ───

describe("key rotation", () => {
  test("rotate key", async () => {
    const res = await post("/admin/keys/rotate", {}, authA());
    expect(res.status).toBe(201);
  });

  test("list keys shows old + new", async () => {
    const res = await get("/admin/keys", authA());
    const keys = await res.json();
    expect(keys.filter((k: any) => k.active).length).toBe(1);
    expect(keys.filter((k: any) => !k.active).length).toBeGreaterThanOrEqual(1);
  });

  test("old JWT still valid after rotation", async () => {
    const res = await get("/admin/users", authA());
    expect(res.status).toBe(200);
  });

  test("JWKS includes all keys", async () => {
    const res = await get("/.well-known/jwks.json");
    const body = await res.json();
    expect(body.keys.length).toBeGreaterThanOrEqual(2);
  });
});

// ─── Tenant GET ───

describe("GET /tenants/:id", () => {
  test("admin can get own tenant", async () => {
    const res = await get(`/tenants/${tenantAId}`, authA());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.name).toBe("Acme Corp");
  });

  test("admin cannot get other tenant", async () => {
    const res = await get(`/tenants/${tenantBId}`, authA());
    expect(res.status).toBe(403);
  });
});

// ─── 404 ───

describe("routing", () => {
  test("unknown route returns 404", async () => {
    const res = await get("/nonexistent");
    expect(res.status).toBe(404);
  });
});
