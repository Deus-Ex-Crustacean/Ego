import { randomBytes, createHash } from "crypto";
import { db } from "./db.ts";
import type { Workspace } from "./types.ts";

// In-memory bootstrap token — generated on startup if no admin workspaces exist
let bootstrapTokenHash: string | null = null;

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function initBootstrap() {
  const admin = db.query("SELECT id FROM workspaces WHERE admin = 1 LIMIT 1").get() as Workspace | null;
  if (admin) return;

  const token = randomBytes(32).toString("hex");
  bootstrapTokenHash = hashToken(token);

  console.log("=".repeat(60));
  console.log("BOOTSTRAP TOKEN (use once to create first admin workspace):");
  console.log(token);
  console.log("=".repeat(60));
}

export function consumeBootstrap(token: string): boolean {
  if (!bootstrapTokenHash) return false;
  if (hashToken(token) !== bootstrapTokenHash) return false;
  bootstrapTokenHash = null;
  return true;
}

export function isBootstrapAvailable(): boolean {
  return bootstrapTokenHash !== null;
}
