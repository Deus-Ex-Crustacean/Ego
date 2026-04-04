import { db } from "../db.ts";
import { verifySecret, signJwt } from "../crypto.ts";
import type { User } from "../types.ts";

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

  const user = db.query("SELECT * FROM users WHERE username = ? AND active = 1").get(clientId) as User | null;
  if (!user) {
    return Response.json({ error: "invalid_client" }, { status: 401 });
  }

  const valid = await verifySecret(clientSecret, user.client_secret);
  if (!valid) {
    return Response.json({ error: "invalid_client" }, { status: 401 });
  }

  const groups = db.query(
    "SELECT g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?"
  ).all(user.id) as { name: string }[];

  const token = signJwt({
    sub: user.id,
    username: user.username,
    admin: !!user.admin,
    groups: groups.map((g) => g.name),
  });

  return Response.json({
    access_token: token,
    token_type: "Bearer",
    expires_in: parseInt(process.env.TOKEN_EXPIRY_SECONDS || "3600", 10),
  });
}
