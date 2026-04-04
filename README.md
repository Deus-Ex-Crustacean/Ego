# Ego
A machine-to-machine identity provider with SCIM push support.

## Status
- All 34 tests passing
- Core flows implemented: bootstrap, client_credentials token, OIDC discovery, JWKS, admin CRUD (users, groups, SCIM targets, signing keys), SCIM push, key rotation
- Zero external runtime dependencies (Bun-native SQLite, crypto, HTTP)

## Running
```bash
bun run src/index.ts
```

## Testing
```bash
bun test
```
