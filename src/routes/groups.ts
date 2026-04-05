import { randomUUID } from "crypto";
import { db } from "../db.ts";
import { requireAdmin } from "../auth.ts";
import { pushGroupToAll } from "../scim.ts";
import type { Group } from "../types.ts";

function getGroupMembers(groupId: string): string[] {
  return (db.query("SELECT user_id FROM group_members WHERE group_id = ?").all(groupId) as { user_id: string }[]).map(
    (r) => r.user_id
  );
}

export async function handleCreateGroup(req: Request): Promise<Response> {
  const { tenantId } = requireAdmin(req);
  const body = await req.json();
  if (!body.name) return Response.json({ error: "name required" }, { status: 400 });

  const id = randomUUID();
  const now = Math.floor(Date.now() / 1000);

  try {
    db.query("INSERT INTO groups (id, tenant_id, name, created_at) VALUES (?, ?, ?, ?)").run(id, tenantId, body.name, now);
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) {
      return Response.json({ error: "group name already exists" }, { status: 409 });
    }
    throw err;
  }

  const group = db.query("SELECT * FROM groups WHERE id = ?").get(id) as Group;
  await pushGroupToAll(group, [], "create");

  return Response.json(group, { status: 201 });
}

export function handleListGroups(req: Request): Response {
  const { tenantId } = requireAdmin(req);
  const groups = db.query("SELECT * FROM groups WHERE tenant_id = ?").all(tenantId) as Group[];
  return Response.json(groups);
}

export function handleGetGroup(req: Request, id: string): Response {
  const { tenantId } = requireAdmin(req);
  const group = db.query("SELECT * FROM groups WHERE id = ? AND tenant_id = ?").get(id, tenantId) as Group | null;
  if (!group) return Response.json({ error: "not found" }, { status: 404 });
  const members = getGroupMembers(id);
  return Response.json({ ...group, members });
}

export async function handleUpdateGroup(req: Request, id: string): Promise<Response> {
  const { tenantId } = requireAdmin(req);
  const group = db.query("SELECT * FROM groups WHERE id = ? AND tenant_id = ?").get(id, tenantId) as Group | null;
  if (!group) return Response.json({ error: "not found" }, { status: 404 });

  const body = await req.json();
  if (!body.name) return Response.json({ error: "name required" }, { status: 400 });

  db.query("UPDATE groups SET name = ? WHERE id = ?").run(body.name, id);
  const updated = db.query("SELECT * FROM groups WHERE id = ?").get(id) as Group;
  const members = getGroupMembers(id);
  await pushGroupToAll(updated, members, "update");

  return Response.json({ ...updated, members });
}

export async function handleDeleteGroup(req: Request, id: string): Promise<Response> {
  const { tenantId } = requireAdmin(req);
  const group = db.query("SELECT * FROM groups WHERE id = ? AND tenant_id = ?").get(id, tenantId) as Group | null;
  if (!group) return Response.json({ error: "not found" }, { status: 404 });

  db.query("DELETE FROM group_members WHERE group_id = ?").run(id);
  db.query("DELETE FROM groups WHERE id = ?").run(id);
  await pushGroupToAll(group, [], "delete");

  return new Response(null, { status: 204 });
}

export async function handleAddMember(req: Request, groupId: string): Promise<Response> {
  const { tenantId } = requireAdmin(req);
  const group = db.query("SELECT * FROM groups WHERE id = ? AND tenant_id = ?").get(groupId, tenantId) as Group | null;
  if (!group) return Response.json({ error: "group not found" }, { status: 404 });

  const body = await req.json();
  if (!body.userId) return Response.json({ error: "userId required" }, { status: 400 });

  const user = db.query("SELECT id FROM users WHERE id = ? AND tenant_id = ?").get(body.userId, tenantId);
  if (!user) return Response.json({ error: "user not found" }, { status: 404 });

  try {
    db.query("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").run(groupId, body.userId);
  } catch (err: any) {
    if (err.message?.includes("UNIQUE") || err.message?.includes("PRIMARY")) {
      return Response.json({ error: "already a member" }, { status: 409 });
    }
    throw err;
  }

  const members = getGroupMembers(groupId);
  await pushGroupToAll(group, members, "update");

  return Response.json({ ...group, members }, { status: 201 });
}

export async function handleRemoveMember(req: Request, groupId: string, userId: string): Promise<Response> {
  const { tenantId } = requireAdmin(req);
  const group = db.query("SELECT * FROM groups WHERE id = ? AND tenant_id = ?").get(groupId, tenantId) as Group | null;
  if (!group) return Response.json({ error: "group not found" }, { status: 404 });

  const result = db.query("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").run(groupId, userId);
  if (result.changes === 0) return Response.json({ error: "not a member" }, { status: 404 });

  const members = getGroupMembers(groupId);
  await pushGroupToAll(group, members, "update");

  return new Response(null, { status: 204 });
}
