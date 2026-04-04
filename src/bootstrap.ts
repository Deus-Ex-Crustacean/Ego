import { randomBytes, createHash } from "crypto";
import { db } from "./db.ts";
import type { Bootstrap } from "./types.ts";

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function initBootstrap() {
  // If there are admin users, no bootstrap needed
  const adminCount = db.query("SELECT COUNT(*) as count FROM users WHERE admin = 1").get() as { count: number };
  if (adminCount.count > 0) return;

  // No admins exist — generate a fresh bootstrap token
  // (replaces any previously consumed token)
  db.query("DELETE FROM bootstrap").run();

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
