import { getJwks } from "../crypto.ts";
import { PORT } from "../config.ts";

function getIssuer(req: Request): string {
  const host = req.headers.get("host") || `localhost:${PORT}`;
  const proto = req.headers.get("x-forwarded-proto") || "http";
  return `${proto}://${host}`;
}

export function handleOpenIdConfig(req: Request): Response {
  const issuer = getIssuer(req);
  return Response.json({
    issuer,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: [],
    grant_types_supported: ["client_credentials"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  });
}

export function handleJwks(): Response {
  return Response.json(getJwks());
}
