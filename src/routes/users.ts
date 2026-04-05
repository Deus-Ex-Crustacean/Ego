import { randomUUID, randomBytes } from "crypto";
import { db } from "../db.ts";
import { hashSecret } from "../crypto.ts";
import { requireAdmin } from "../auth.ts";
import type { User } from "../types.ts";

function sanitize(user: User) {
  const { client_secret, ...rest } = user;
  return { ...rest, machine: !!rest.machine, active: !!rest.active };
}

export async function handleCreateUser(req: Request): Promise<Response> {
  requireAdmin(req);
  const body = await req.json();

  if (!body.username) {
    return Response.json({ error: "username required" }, { status: 400 });
  }

  const id = randomUUID();
  const plainSecret = randomBytes(32).toString("hex");
  const hashedSecret = await hashSecret(plainSecret);
  const now = Math.floor(Date.now() / 1000);

  try {
    db.query(
      "INSERT INTO users (id, username, client_secret, machine, active, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(id, body.username, hashedSecret, body.machine ? 1 : 0, 1, now);
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) {
      return Response.json({ error: "username already exists" }, { status: 409 });
    }
    throw err;
  }

  const user = db.query("SELECT * FROM users WHERE id = ?").get(id) as User;
  return Response.json({ ...sanitize(user), client_secret: plainSecret }, { status: 201 });
}

export function handleListUsers(req: Request): Response {
  requireAdmin(req);
  const users = db.query("SELECT * FROM users").all() as User[];
  return Response.json(users.map(sanitize));
}

export function handleGetUser(req: Request, id: string): Response {
  requireAdmin(req);
  const user = db.query("SELECT * FROM users WHERE id = ?").get(id) as User | null;
  if (!user) return Response.json({ error: "not found" }, { status: 404 });
  return Response.json(sanitize(user));
}

export function handleDeleteUser(req: Request, id: string): Response {
  requireAdmin(req);
  const result = db.query("DELETE FROM users WHERE id = ?").run(id);
  if (result.changes === 0) return Response.json({ error: "not found" }, { status: 404 });
  return new Response(null, { status: 204 });
}
