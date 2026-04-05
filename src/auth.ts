import { verifyJwt } from "./crypto.ts";
import { db } from "./db.ts";
import { isBootstrapAvailable } from "./bootstrap.ts";
import type { Workspace } from "./types.ts";

export function extractBearer(req: Request): string | null {
  const auth = req.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

export function requireAdmin(req: Request): Workspace {
  const token = extractBearer(req);
  if (!token) throw new Response("Unauthorized", { status: 401 });

  const payload = verifyJwt(token);
  if (!payload) throw new Response("Invalid token", { status: 401 });

  const ws = db.query("SELECT * FROM workspaces WHERE id = ? AND active = 1").get(payload.sub as string) as Workspace | null;
  if (!ws || !ws.admin) throw new Response("Forbidden", { status: 403 });

  return ws;
}

export interface AuthResult {
  type: "admin" | "bootstrap";
  workspace?: Workspace;
}

export function requireAdminOrBootstrap(req: Request): AuthResult {
  const token = extractBearer(req);
  if (token) {
    const payload = verifyJwt(token);
    if (payload) {
      const ws = db.query("SELECT * FROM workspaces WHERE id = ? AND active = 1").get(payload.sub as string) as Workspace | null;
      if (ws?.admin) return { type: "admin", workspace: ws };
    }
  }

  const bootstrapToken = req.headers.get("x-bootstrap-token");
  if (bootstrapToken && isBootstrapAvailable()) {
    return { type: "bootstrap" };
  }

  throw new Response("Unauthorized", { status: 401 });
}
