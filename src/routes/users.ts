import { randomUUID, randomBytes } from "crypto";
import { db } from "../db.ts";
import { hashSecret } from "../crypto.ts";
import { requireAdmin, requireAdminOrBootstrap } from "../auth.ts";
import { consumeBootstrap } from "../bootstrap.ts";
import { pushUserToAll } from "../scim.ts";
import type { User } from "../types.ts";

function sanitizeUser(user: User) {
  const { client_secret, ...rest } = user;
  return { ...rest, machine: !!rest.machine, admin: !!rest.admin, active: !!rest.active };
}

export async function handleCreateUser(req: Request): Promise<Response> {
  const auth = requireAdminOrBootstrap(req);
  const body = await req.json();

  if (!body.username) {
    return Response.json({ error: "username required" }, { status: 400 });
  }

  const id = randomUUID();
  const plainSecret = randomBytes(32).toString("hex");
  const hashedSecret = await hashSecret(plainSecret);
  const now = Math.floor(Date.now() / 1000);
  const isAdmin = auth.type === "bootstrap" ? true : !!body.admin;

  try {
    db.query(
      "INSERT INTO users (id, username, client_secret, machine, admin, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(id, body.username, hashedSecret, body.machine ?? 1, isAdmin ? 1 : 0, 1, now, now);
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) {
      return Response.json({ error: "username already exists" }, { status: 409 });
    }
    throw err;
  }

  if (auth.type === "bootstrap") {
    const bootstrapToken = req.headers.get("x-bootstrap-token");
    if (!bootstrapToken || !consumeBootstrap(bootstrapToken)) {
      return Response.json({ error: "invalid bootstrap token" }, { status: 401 });
    }
  }

  const user = db.query("SELECT * FROM users WHERE id = ?").get(id) as User;
  await pushUserToAll(user, "create");

  return Response.json({ ...sanitizeUser(user), client_secret: plainSecret }, { status: 201 });
}

export function handleListUsers(req: Request): Response {
  requireAdmin(req);
  const users = db.query("SELECT * FROM users").all() as User[];
  return Response.json(users.map(sanitizeUser));
}

export function handleGetUser(req: Request, id: string): Response {
  requireAdmin(req);
  const user = db.query("SELECT * FROM users WHERE id = ?").get(id) as User | null;
  if (!user) return Response.json({ error: "not found" }, { status: 404 });
  return Response.json(sanitizeUser(user));
}

export async function handleUpdateUser(req: Request, id: string): Promise<Response> {
  requireAdmin(req);
  const user = db.query("SELECT * FROM users WHERE id = ?").get(id) as User | null;
  if (!user) return Response.json({ error: "not found" }, { status: 404 });

  const body = await req.json();
  const now = Math.floor(Date.now() / 1000);

  const updates: string[] = [];
  const values: any[] = [];

  for (const field of ["username", "machine", "admin", "active"] as const) {
    if (body[field] !== undefined) {
      updates.push(`${field} = ?`);
      values.push(typeof body[field] === "boolean" ? (body[field] ? 1 : 0) : body[field]);
    }
  }

  if (updates.length === 0) return Response.json({ error: "no fields to update" }, { status: 400 });

  updates.push("updated_at = ?");
  values.push(now);
  values.push(id);

  db.query(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).run(...values);

  const updated = db.query("SELECT * FROM users WHERE id = ?").get(id) as User;
  await pushUserToAll(updated, "update");

  return Response.json(sanitizeUser(updated));
}

export async function handleDeleteUser(req: Request, id: string): Promise<Response> {
  requireAdmin(req);
  const user = db.query("SELECT * FROM users WHERE id = ?").get(id) as User | null;
  if (!user) return Response.json({ error: "not found" }, { status: 404 });

  db.query("DELETE FROM group_members WHERE user_id = ?").run(id);
  db.query("DELETE FROM users WHERE id = ?").run(id);
  await pushUserToAll(user, "delete");

  return new Response(null, { status: 204 });
}
