import { randomBytes, createHash } from "crypto";
import { db } from "./db.ts";

let currentTokenHash: string | null = null;

export function initBootstrap() {
  // If there are admin users, no bootstrap needed
  const adminCount = db.query("SELECT COUNT(*) as count FROM users WHERE admin = 1").get() as { count: number };
  if (adminCount.count > 0) return;

  // Generate an ephemeral bootstrap token (lives only in memory)
  const token = randomBytes(32).toString("hex");
  currentTokenHash = createHash("sha256").update(token).digest("hex");

  console.log("=".repeat(60));
  console.log("BOOTSTRAP TOKEN (use once to create first admin user):");
  console.log(token);
  console.log("=".repeat(60));
}

export function consumeBootstrap(token: string): boolean {
  if (!currentTokenHash) return false;
  const hash = createHash("sha256").update(token).digest("hex");
  if (hash !== currentTokenHash) return false;
  currentTokenHash = null;
  return true;
}

export function isBootstrapConsumed(): boolean {
  return currentTokenHash === null;
}
