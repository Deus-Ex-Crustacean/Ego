import { describe, test, expect, beforeAll, afterAll } from "bun:test";

process.env.DB_PATH = ":memory:";
process.env.PORT = "0";

let server: ReturnType<typeof Bun.serve>;
let baseUrl: string;
let bootstrapToken: string;
let adminSecret: string;
let adminJwt: string;
let adminId: string;

beforeAll(async () => {
  const originalLog = console.log;
  const logs: string[] = [];
  console.log = (...args: any[]) => { logs.push(args.join(" ")); originalLog(...args); };

  const { initDb, db } = await import("./db.ts");
  const { generateKeyPair } = await import("./crypto.ts");
  const { initBootstrap } = await import("./bootstrap.ts");
  const { handleToken } = await import("./routes/token.ts");
  const { handleOpenIdConfig, handleJwks } = await import("./routes/wellknown.ts");
  const { handleCreateWorkspace, handleListWorkspaces, handleGetWorkspace, handleDeleteWorkspace } = await import("./routes/workspaces.ts");
  const { handleListKeys, handleRotateKey } = await import("./routes/keys.ts");

  initDb();
  initBootstrap();

  const keyCount = db.query("SELECT COUNT(*) as count FROM signing_keys").get() as { count: number };
  if (keyCount.count === 0) {
    const { id, privateKey, publicKey } = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    db.query("INSERT INTO signing_keys (id, private_key, public_key, active, created_at) VALUES (?, ?, ?, 1, ?)").run(id, privateKey, publicKey, now);
  }

  bootstrapToken = logs.find((l) => /^[a-f0-9]{64}$/.test(l.trim()))?.trim() || "";
  console.log = originalLog;

  const paramPatterns: Array<{ method: string; pattern: RegExp; handler: (req: Request, ...p: string[]) => Response | Promise<Response>; }> = [
    { method: "GET", pattern: /^\/admin\/workspaces\/([^/]+)$/, handler: handleGetWorkspace },
    { method: "DELETE", pattern: /^\/admin\/workspaces\/([^/]+)$/, handler: handleDeleteWorkspace },
  ];

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

  server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      try {
        const handler = matchRoute(req.method, url.pathname);
        if (handler) return await handler(req);
        for (const r of paramPatterns) {
          if (r.method !== req.method) continue;
          const m = url.pathname.match(r.pattern);
          if (m) return await r.handler(req, ...m.slice(1));
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

function post(path: string, body: object, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
}
function get(path: string, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, { headers });
}
function del(path: string, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, { method: "DELETE", headers });
}
function auth() { return { Authorization: `Bearer ${adminJwt}` }; }

// ─── Bootstrap ───

describe("bootstrap", () => {
  test("bootstrap token generated", () => {
    expect(bootstrapToken).toMatch(/^[a-f0-9]{64}$/);
  });

  test("admin endpoints reject unauthenticated requests", async () => {
    const res = await get("/admin/workspaces");
    expect(res.status).toBe(401);
  });

  test("create first admin workspace with bootstrap token", async () => {
    const res = await post("/admin/workspaces", { name: "admin" }, { "X-Bootstrap-Token": bootstrapToken });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.name).toBe("admin");
    expect(body.admin).toBe(true);
    expect(body.client_secret).toMatch(/^[a-f0-9]{64}$/);
    adminSecret = body.client_secret;
    adminId = body.id;
  });

  test("bootstrap token consumed — cannot reuse", async () => {
    const res = await post("/admin/workspaces", { name: "admin2" }, { "X-Bootstrap-Token": bootstrapToken });
    expect(res.status).toBe(401);
  });
});

// ─── Token ───

describe("POST /token", () => {
  test("client_credentials returns JWT", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "admin", client_secret: adminSecret }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toBeDefined();
    expect(body.token_type).toBe("Bearer");
    adminJwt = body.access_token;

    const payload = JSON.parse(atob(adminJwt.split(".")[1]));
    expect(payload.sub).toBe(adminId);
    expect(payload.name).toBe("admin");
    expect(payload.admin).toBe(true);
  });

  test("wrong secret rejected", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "admin", client_secret: "wrong" }),
    });
    expect(res.status).toBe(401);
  });

  test("unsupported grant type rejected", async () => {
    const res = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: "admin", client_secret: adminSecret }),
    });
    expect(res.status).toBe(400);
  });

  test("JSON body works", async () => {
    const res = await post("/token", { grant_type: "client_credentials", client_id: "admin", client_secret: adminSecret });
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
    expect(body.grant_types_supported).toContain("client_credentials");
  });

  test("JWKS", async () => {
    const res = await get("/.well-known/jwks.json");
    const body = await res.json();
    expect(body.keys.length).toBeGreaterThanOrEqual(1);
    expect(body.keys[0].kty).toBe("RSA");
  });
});

// ─── Workspaces CRUD ───

describe("workspaces", () => {
  let wsId: string;

  test("create workspace", async () => {
    const res = await post("/admin/workspaces", { name: "hive-prod" }, auth());
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.name).toBe("hive-prod");
    expect(body.admin).toBe(false);
    expect(body.client_secret).toMatch(/^[a-f0-9]{64}$/);
    wsId = body.id;
  });

  test("create admin workspace", async () => {
    const res = await post("/admin/workspaces", { name: "cortex", admin: true }, auth());
    expect(res.status).toBe(201);
    expect((await res.json()).admin).toBe(true);
  });

  test("list workspaces", async () => {
    const res = await get("/admin/workspaces", auth());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.length).toBeGreaterThanOrEqual(2);
    expect(body.every((w: any) => !w.client_secret)).toBe(true);
  });

  test("get workspace by id", async () => {
    const res = await get(`/admin/workspaces/${wsId}`, auth());
    expect(res.status).toBe(200);
    expect((await res.json()).name).toBe("hive-prod");
  });

  test("duplicate name rejected", async () => {
    const res = await post("/admin/workspaces", { name: "hive-prod" }, auth());
    expect(res.status).toBe(409);
  });

  test("non-admin JWT rejected", async () => {
    const createRes = await post("/admin/workspaces", { name: "svc-nonadmin" }, auth());
    const { client_secret: secret } = await createRes.json();
    const tokenRes = await fetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: "svc-nonadmin", client_secret: secret }),
    });
    const { access_token } = await tokenRes.json();
    const res = await get("/admin/workspaces", { Authorization: `Bearer ${access_token}` });
    expect(res.status).toBe(403);
  });

  test("delete workspace", async () => {
    const res = await del(`/admin/workspaces/${wsId}`, auth());
    expect(res.status).toBe(204);
    const check = await get(`/admin/workspaces/${wsId}`, auth());
    expect(check.status).toBe(404);
  });
});

// ─── Key Rotation ───

describe("key rotation", () => {
  test("rotate key", async () => {
    const res = await post("/admin/keys/rotate", {}, auth());
    expect(res.status).toBe(201);
  });

  test("list keys shows old + new", async () => {
    const res = await get("/admin/keys", auth());
    const keys = await res.json();
    expect(keys.filter((k: any) => k.active).length).toBe(1);
    expect(keys.filter((k: any) => !k.active).length).toBeGreaterThanOrEqual(1);
  });

  test("old JWT still valid after rotation", async () => {
    const res = await get("/admin/workspaces", auth());
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
