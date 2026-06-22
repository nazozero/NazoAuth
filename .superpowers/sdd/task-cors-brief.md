# CORS Restructuring — Implementation Brief

## Scope
Rewrite the unified CORS middleware into 5 per-route CORS policies. Then update routes.rs to apply each policy to the correct scope/resource.

## Files to Modify

### `src/bootstrap/cors.rs` — Rewrite
Replace the current single `build()` function with 5 named constructors:

```rust
pub(crate) fn cors_well_known(settings: &Settings) -> Cors;        // /.well-known/*, /jwks.json
pub(crate) fn cors_browser_oauth(settings: &Settings) -> Cors;      // /token, /revoke, /userinfo
pub(crate) fn cors_auth_api(settings: &Settings) -> Cors;           // /auth/me/*, /auth/sessions, etc.
pub(crate) fn cors_admin(settings: &Settings) -> Cors;              // /admin/*
pub(crate) fn cors_scim(settings: &Settings) -> Cors;               // /scim/v2/*
```

### `src/bootstrap/routes.rs` — Per-scope CORS mounting
Remove the global `.wrap(cors)` from the App builder. Apply per-scope:
- `/.well-known` → `cors_well_known`
- `/jwks.json` → `cors_well_known`
- `/authorize` → NO CORS
- `/par` → NO CORS
- `/introspect` → NO CORS
- `/logout` → NO CORS
- `/auth/login`, `/auth/register`, `/auth/consent`, `/auth/federation/*` etc → NO CORS
- `/token`, `/revoke`, `/userinfo` → `cors_browser_oauth`
- `/auth/me`, `/auth/sessions`, `/auth/mfa`, `/auth/applications`, `/auth/access-requests` → `cors_auth_api`
- `/admin/*` → `cors_admin`
- `/scim/v2/*` → `cors_scim`

## CORS Policy Details

| Function | Methods | Headers | Credentials | Expose Headers | Max-Age |
|---|---|---|---|---|---|
| cors_well_known | GET, HEAD | Accept | false | — | 3600 |
| cors_browser_oauth | GET, POST | Authorization, Content-Type, dpop, x-csrf-token | false (no cookies) | WWW-Authenticate, dpop-nonce, Retry-After | 0 |
| cors_auth_api | GET, POST, PATCH, DELETE | Authorization, Content-Type, x-csrf-token | depends | — | 3600 |
| cors_admin | GET, POST, PATCH, DELETE | Authorization, Content-Type | depends | — | 3600 |
| cors_scim | GET, POST, PATCH, DELETE | Authorization, Content-Type | depends | — | 3600 |

All policies should apply the existing `cors_allowed_origins` allowlist via `.allowed_origin(&origin)` loop. Actix 0.7 API uses `Cors::default()` builder pattern — existing code imports from `actix_cors::Cors`.

## Global Constraints
- /authorize, /par, /introspect, /logout (backchannel), and all auth UI pages (/auth/login, /auth/register, /auth/consent, /auth/federation/*, /auth/passkey/*, /auth/send-code) MUST NOT have CORS middleware
- Only browser-based OAuth API (/token, /revoke, /userinfo) and auth API (/auth/me/* etc.) get CORS
- Keep the `cors_allowed_origins` allowlist validation in ALL policies
- /token and /revoke are POST-only; /userinfo is both GET and POST
