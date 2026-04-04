import { db } from "../db.ts";
import { generateKeyPair } from "../crypto.ts";
import { requireAdmin } from "../auth.ts";
import type { SigningKey } from "../types.ts";

export function handleListKeys(req: Request): Response {
  requireAdmin(req);
  const keys = db.query("SELECT id, public_key, active, created_at FROM signing_keys").all() as Omit<SigningKey, "private_key">[];
  return Response.json(keys.map((k) => ({ ...k, active: !!k.active })));
}

export function handleRotateKey(req: Request): Response {
  requireAdmin(req);
  const { id, privateKey, publicKey } = generateKeyPair();
  const now = Math.floor(Date.now() / 1000);

  db.query("UPDATE signing_keys SET active = 0").run();
  db.query("INSERT INTO signing_keys (id, private_key, public_key, active, created_at) VALUES (?, ?, ?, 1, ?)").run(
    id, privateKey, publicKey, now
  );

  return Response.json({ id, active: true, created_at: now }, { status: 201 });
}
