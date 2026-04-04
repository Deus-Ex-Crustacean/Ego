import { randomBytes, createHash } from "crypto";
import { db } from "./db.ts";
import type { Bootstrap } from "./types.ts";

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function initBootstrap() {
  const existing = db.query("SELECT * FROM bootstrap").get() as Bootstrap | null;
  if (existing) return;

  const token = randomBytes(32).toString("hex");
  const hash = hashToken(token);
  db.query("INSERT INTO bootstrap (token_hash, consumed) VALUES (?, 0)").run(hash);

  console.log("=".repeat(60));
  console.log("BOOTSTRAP TOKEN (use once to create first admin user):");
  console.log(token);
  console.log("=".repeat(60));
}

export function consumeBootstrap(token: string): boolean {
  const hash = hashToken(token);
  const result = db.query("UPDATE bootstrap SET consumed = 1 WHERE token_hash = ? AND consumed = 0").run(hash);
  return result.changes > 0;
}

export function isBootstrapConsumed(): boolean {
  const row = db.query("SELECT consumed FROM bootstrap").get() as { consumed: number } | null;
  return row ? row.consumed === 1 : true;
}
