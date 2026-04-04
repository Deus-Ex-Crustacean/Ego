import { db } from "./db.ts";
import type { User, Group, ScimTarget } from "./types.ts";

function getActiveTargets(): ScimTarget[] {
  return db.query("SELECT * FROM scim_targets WHERE active = 1").all() as ScimTarget[];
}

function userToScim(user: User) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: user.id,
    userName: user.username,
    active: !!user.active,
    meta: {
      resourceType: "User",
      created: new Date(user.created_at * 1000).toISOString(),
      lastModified: new Date(user.updated_at * 1000).toISOString(),
    },
  };
}

function groupToScim(group: Group, memberIds: string[]) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    id: group.id,
    displayName: group.name,
    members: memberIds.map((id) => ({ value: id })),
    meta: {
      resourceType: "Group",
      created: new Date(group.created_at * 1000).toISOString(),
    },
  };
}

async function pushToTarget(target: ScimTarget, path: string, method: string, body?: object) {
  try {
    const url = `${target.url.replace(/\/$/, "")}${path}`;
    await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/scim+json",
        Authorization: `Bearer ${target.token}`,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    console.error(`SCIM push failed for target ${target.name} (${target.id}):`, err);
  }
}

export async function pushUserToAll(user: User, op: "create" | "update" | "delete") {
  const targets = getActiveTargets();
  const promises = targets.map((t) => {
    if (op === "delete") return pushToTarget(t, `/Users/${user.id}`, "DELETE");
    if (op === "create") return pushToTarget(t, "/Users", "POST", userToScim(user));
    return pushToTarget(t, `/Users/${user.id}`, "PUT", userToScim(user));
  });
  await Promise.all(promises);
}

export async function pushGroupToAll(group: Group, memberIds: string[], op: "create" | "update" | "delete") {
  const targets = getActiveTargets();
  const promises = targets.map((t) => {
    if (op === "delete") return pushToTarget(t, `/Groups/${group.id}`, "DELETE");
    if (op === "create") return pushToTarget(t, "/Groups", "POST", groupToScim(group, memberIds));
    return pushToTarget(t, `/Groups/${group.id}`, "PUT", groupToScim(group, memberIds));
  });
  await Promise.all(promises);
}
