import { randomUUID } from "crypto";
import { db } from "../db.ts";
import { requireAdmin } from "../auth.ts";
import type { ScimTarget } from "../types.ts";

export async function handleCreateScimTarget(req: Request): Promise<Response> {
  requireAdmin(req);
  const body = await req.json();

  if (!body.name || !body.url || !body.token) {
    return Response.json({ error: "name, url, and token required" }, { status: 400 });
  }

  try {
    const parsed = new URL(body.url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return Response.json({ error: "url must use http or https" }, { status: 400 });
    }
  } catch {
    return Response.json({ error: "invalid url" }, { status: 400 });
  }

  const id = randomUUID();
  db.query("INSERT INTO scim_targets (id, name, url, token, active) VALUES (?, ?, ?, ?, ?)").run(
    id, body.name, body.url, body.token, 1
  );

  const target = db.query("SELECT * FROM scim_targets WHERE id = ?").get(id) as ScimTarget;
  return Response.json({ ...target, active: !!target.active }, { status: 201 });
}

export function handleListScimTargets(req: Request): Response {
  requireAdmin(req);
  const targets = db.query("SELECT * FROM scim_targets").all() as ScimTarget[];
  return Response.json(targets.map((t) => ({ ...t, active: !!t.active })));
}

export function handleDeleteScimTarget(req: Request, id: string): Response {
  requireAdmin(req);
  const result = db.query("DELETE FROM scim_targets WHERE id = ?").run(id);
  if (result.changes === 0) return Response.json({ error: "not found" }, { status: 404 });
  return new Response(null, { status: 204 });
}
