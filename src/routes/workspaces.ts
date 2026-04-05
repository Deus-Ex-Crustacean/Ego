import { randomUUID, randomBytes } from "crypto";
import { db } from "../db.ts";
import { hashSecret } from "../crypto.ts";
import { requireAdmin, requireAdminOrBootstrap } from "../auth.ts";
import { consumeBootstrap } from "../bootstrap.ts";
import type { Workspace } from "../types.ts";

function sanitize(ws: Workspace) {
  const { client_secret, ...rest } = ws;
  return { ...rest, admin: !!rest.admin, active: !!rest.active };
}

export async function handleCreateWorkspace(req: Request): Promise<Response> {
  const auth = requireAdminOrBootstrap(req);
  const body = await req.json();

  if (!body.name) {
    return Response.json({ error: "name required" }, { status: 400 });
  }

  const id = randomUUID();
  const plainSecret = randomBytes(32).toString("hex");
  const hashedSecret = await hashSecret(plainSecret);
  const now = Math.floor(Date.now() / 1000);
  const isAdmin = auth.type === "bootstrap" ? true : !!body.admin;

  try {
    db.query(
      "INSERT INTO workspaces (id, name, client_secret, admin, active, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(id, body.name, hashedSecret, isAdmin ? 1 : 0, 1, now);
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) {
      return Response.json({ error: "name already exists" }, { status: 409 });
    }
    throw err;
  }

  if (auth.type === "bootstrap") {
    const bootstrapToken = req.headers.get("x-bootstrap-token")!;
    consumeBootstrap(bootstrapToken);
  }

  const ws = db.query("SELECT * FROM workspaces WHERE id = ?").get(id) as Workspace;
  return Response.json({ ...sanitize(ws), client_secret: plainSecret }, { status: 201 });
}

export function handleListWorkspaces(req: Request): Response {
  requireAdmin(req);
  const workspaces = db.query("SELECT * FROM workspaces").all() as Workspace[];
  return Response.json(workspaces.map(sanitize));
}

export function handleGetWorkspace(req: Request, id: string): Response {
  requireAdmin(req);
  const ws = db.query("SELECT * FROM workspaces WHERE id = ?").get(id) as Workspace | null;
  if (!ws) return Response.json({ error: "not found" }, { status: 404 });
  return Response.json(sanitize(ws));
}

export function handleDeleteWorkspace(req: Request, id: string): Response {
  requireAdmin(req);
  const result = db.query("DELETE FROM workspaces WHERE id = ?").run(id);
  if (result.changes === 0) return Response.json({ error: "not found" }, { status: 404 });
  return new Response(null, { status: 204 });
}
