import { db } from "../db.ts";
import { verifySecret, signJwt } from "../crypto.ts";
import { TOKEN_EXPIRY_SECONDS } from "../config.ts";
import type { Workspace, User } from "../types.ts";

export async function handleToken(req: Request): Promise<Response> {
  const contentType = req.headers.get("content-type") || "";
  let clientId: string | null = null;
  let clientSecret: string | null = null;
  let grantType: string | null = null;

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const body = new URLSearchParams(await req.text());
    grantType = body.get("grant_type");
    clientId = body.get("client_id");
    clientSecret = body.get("client_secret");
  } else if (contentType.includes("application/json")) {
    const body = await req.json();
    grantType = body.grant_type;
    clientId = body.client_id;
    clientSecret = body.client_secret;
  } else {
    return Response.json({ error: "unsupported_content_type" }, { status: 400 });
  }

  if (grantType !== "client_credentials") {
    return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
  }
  if (!clientId || !clientSecret) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  // Check workspaces first, then users
  const ws = db.query("SELECT * FROM workspaces WHERE name = ? AND active = 1").get(clientId) as Workspace | null;
  const user = !ws ? db.query("SELECT * FROM users WHERE username = ? AND active = 1").get(clientId) as User | null : null;
  const entity = ws || user;

  if (!entity) {
    return Response.json({ error: "invalid_client" }, { status: 401 });
  }

  const valid = await verifySecret(clientSecret, entity.client_secret);
  if (!valid) {
    return Response.json({ error: "invalid_client" }, { status: 401 });
  }

  const sub = entity.id;
  const name = ws ? ws.name : (user as User).username;
  const admin = ws ? !!ws.admin : false;

  const token = signJwt({ sub, name, admin });

  return Response.json({
    access_token: token,
    token_type: "Bearer",
    expires_in: TOKEN_EXPIRY_SECONDS,
  });
}
