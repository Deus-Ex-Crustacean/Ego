import { randomUUID } from "crypto";
import { db } from "../db.ts";
import { requireAdmin } from "../auth.ts";
import { createTenantBootstrapToken } from "../bootstrap.ts";
import type { Tenant } from "../types.ts";

function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

export async function handleCreateTenant(req: Request): Promise<Response> {
  const body = await req.json();
  if (!body.name) return Response.json({ error: "name required" }, { status: 400 });

  const id = randomUUID();
  const slug = slugify(body.name);
  const now = Math.floor(Date.now() / 1000);

  try {
    db.query("INSERT INTO tenants (id, name, slug, created_at) VALUES (?, ?, ?, ?)").run(id, body.name, slug, now);
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) {
      return Response.json({ error: "tenant name or slug already exists" }, { status: 409 });
    }
    throw err;
  }

  const tenant = db.query("SELECT * FROM tenants WHERE id = ?").get(id) as Tenant;
  const bootstrapToken = createTenantBootstrapToken(id);

  return Response.json({ tenant, bootstrapToken }, { status: 201 });
}

export function handleGetTenant(req: Request, id: string): Response {
  const auth = requireAdmin(req);
  if (auth.user!.tenant_id !== id) {
    return Response.json({ error: "forbidden" }, { status: 403 });
  }
  const tenant = db.query("SELECT * FROM tenants WHERE id = ?").get(id) as Tenant | null;
  if (!tenant) return Response.json({ error: "not found" }, { status: 404 });
  return Response.json(tenant);
}
