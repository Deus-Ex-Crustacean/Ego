import { createHash, createSign, createVerify, generateKeyPairSync, type KeyObject } from "crypto";
import { db } from "./db.ts";
import { TOKEN_EXPIRY_SECONDS } from "./config.ts";
import type { SigningKey } from "./types.ts";

export function generateKeyPair(): { id: string; privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const kid = createHash("sha256")
    .update(publicKey as string)
    .digest("base64url")
    .slice(0, 16);

  return { id: kid, privateKey: privateKey as string, publicKey: publicKey as string };
}

export async function hashSecret(plain: string): Promise<string> {
  return Bun.password.hash(plain, { algorithm: "argon2id" });
}

export async function verifySecret(plain: string, hash: string): Promise<boolean> {
  return Bun.password.verify(plain, hash);
}

function base64urlEncode(data: string | Buffer): string {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return buf.toString("base64url");
}

export function signJwt(payload: Record<string, unknown>): string {
  const key = db.query("SELECT * FROM signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1").get() as SigningKey | null;
  if (!key) throw new Error("No active signing key");

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: key.id };
  const fullPayload = { ...payload, iat: now, exp: now + TOKEN_EXPIRY_SECONDS };

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(fullPayload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sign = createSign("RSA-SHA256");
  sign.update(signingInput);
  const signature = sign.sign(key.private_key, "base64url");

  return `${signingInput}.${signature}`;
}

export function verifyJwt(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    const kid = header.kid;

    const key = db.query("SELECT * FROM signing_keys WHERE id = ?").get(kid) as SigningKey | null;
    if (!key) return null;

    const verify = createVerify("RSA-SHA256");
    verify.update(`${parts[0]}.${parts[1]}`);
    if (!verify.verify(key.public_key, parts[2], "base64url")) return null;

    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

function pemToJwk(pem: string, kid: string) {
  const keyObj = require("crypto").createPublicKey(pem);
  const jwk = keyObj.export({ format: "jwk" });
  return { ...jwk, kid, use: "sig", alg: "RS256" };
}

export function getJwks(): { keys: object[] } {
  const keys = db.query("SELECT * FROM signing_keys").all() as SigningKey[];
  return {
    keys: keys.map((k) => pemToJwk(k.public_key, k.id)),
  };
}
