import { randomBytes, createHash } from "crypto";

// Per-tenant bootstrap tokens (in-memory only, single-use)
const tenantBootstrapTokens = new Map<string, string>(); // tokenHash -> tenantId

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function createTenantBootstrapToken(tenantId: string): string {
  const token = randomBytes(32).toString("hex");
  const hash = hashToken(token);
  tenantBootstrapTokens.set(hash, tenantId);
  return token;
}

export function consumeTenantBootstrapToken(token: string): string | null {
  const hash = hashToken(token);
  const tenantId = tenantBootstrapTokens.get(hash);
  if (!tenantId) return null;
  tenantBootstrapTokens.delete(hash);
  return tenantId;
}
