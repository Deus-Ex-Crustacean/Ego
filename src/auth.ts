import { verifyJwt } from "./crypto.ts";
import { db } from "./db.ts";
import { consumeTenantBootstrapToken } from "./bootstrap.ts";
import type { User } from "./types.ts";

export interface AdminAuth {
  type: "admin";
  user: User;
  tenantId: string;
}

export interface BootstrapAuth {
  type: "bootstrap";
  tenantId: string;
}

export type AuthResult = AdminAuth | BootstrapAuth;

export function extractBearer(req: Request): string | null {
  const auth = req.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

export function requireAdmin(req: Request): AdminAuth {
  const token = extractBearer(req);
  if (!token) throw new Response("Unauthorized", { status: 401 });

  const payload = verifyJwt(token);
  if (!payload) throw new Response("Invalid token", { status: 401 });

  const user = db.query("SELECT * FROM users WHERE id = ? AND active = 1").get(payload.sub as string) as User | null;
  if (!user || !user.admin) throw new Response("Forbidden", { status: 403 });

  return { type: "admin", user, tenantId: user.tenant_id };
}

export function requireAdminOrBootstrap(req: Request): AuthResult {
  // Try JWT admin first
  const token = extractBearer(req);
  if (token) {
    const payload = verifyJwt(token);
    if (payload) {
      const user = db.query("SELECT * FROM users WHERE id = ? AND active = 1").get(payload.sub as string) as User | null;
      if (user?.admin) return { type: "admin", user, tenantId: user.tenant_id };
    }
  }

  // Try bootstrap token
  const bootstrapToken = req.headers.get("x-bootstrap-token");
  if (bootstrapToken) {
    const tenantId = consumeTenantBootstrapToken(bootstrapToken);
    if (tenantId) return { type: "bootstrap", tenantId };
  }

  throw new Response("Unauthorized", { status: 401 });
}
