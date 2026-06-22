# CORS Restructuring — Implementation Report

## What was implemented

### `src/bootstrap/cors.rs` — Rewrote from unified `build()` to 5 named constructors

| Constructor | Methods | Allowed Headers | Credentials | Expose Headers | Max-Age |
|---|---|---|---|---|---|
| `cors_well_known` | GET, HEAD | Accept | false | — | 3600 |
| `cors_browser_oauth` | GET, POST | Authorization, Content-Type, dpop, x-csrf-token | **false** | WWW-Authenticate, dpop-nonce, Retry-After | **0** |
| `cors_auth_api` | GET, POST, PATCH, DELETE | Authorization, Content-Type, x-csrf-token | true | — | 3600 |
| `cors_admin` | GET, POST, PATCH, DELETE | Authorization, Content-Type | true | — | 3600 |
| `cors_scim` | GET, POST, PATCH, DELETE | Authorization, Content-Type | true | — | 3600 |

All policies apply the `cors_allowed_origins` allowlist via the shared `apply_allowed_origins` helper.

### `src/bootstrap/routes.rs` — Per-scope CORS mounting

Removed global CORS; applied CORS only where specified:

| CORS Policy | Routes |
|---|---|
| `cors_well_known` | `/.well-known/*` (scope), `/jwks.json` |
| `cors_browser_oauth` | `/token`, `/revoke`, `/userinfo` |
| `cors_auth_api` | `/auth/me/*` (nested scope) |
| `cors_admin` | `/admin/*` (scope) |
| `cors_scim` | `/scim/v2/*` (scope) |
| **NO CORS** | `/health`, `/authorize`, `/authorize/consent`, `/authorize/decision`, `/par`, `/logout`, `/introspect`, `/fapi/resource`, `/auth/captcha-config`, `/auth/send-code`, `/auth/register`, `/auth/login`, `/auth/federation/*`, `/auth/passkey/*`, `/auth/mfa/verify`, `/auth/csrf`, `/auth/logout` |

### `src/bootstrap/mod.rs`
- Removed `.wrap(cors::build(&state.settings))` (global CORS middleware)
- Changed `.configure(routes::configure)` to `.configure(\|cfg\| routes::configure(cfg, &state.settings))` to pass Settings into the route configuration closure

### `tests/in_source/src/bootstrap/tests/cors.rs`
- Updated existing tests to use `cors_browser_oauth` instead of removed `build()`
- Changed assertion from `ALLOW_CREDENTIALS == "true"` to `is_none()` for browser_oauth (per spec: no cookies)
- Added new test `cors_well_known_allows_get_and_head_only`

## Files changed

| File | Status |
|---|---|
| `src/bootstrap/cors.rs` | Rewritten |
| `src/bootstrap/routes.rs` | Modified (per-scope CORS, settings parameter) |
| `src/bootstrap/mod.rs` | Modified (removed global wrap, pass settings) |
| `tests/in_source/src/bootstrap/tests/cors.rs` | Modified (updated to new constructors, added test) |

## Testing

`cargo check` and `cargo test` cannot run in this environment — missing system dependencies:
- `openssl-sys` requires OpenSSL development libraries
- `aws-lc-sys` requires NASM assembler

These are pre-existing environment limitations unrelated to this change. The code was verified through manual review of types, API usage pattern, and route path correctness.

## Self-review findings

1. **Duplicate `/me/` prefix in inner scope routes (FIXED)**: The `/auth/me` sub-scope mfa routes originally kept the `/me/` prefix inside `web::scope("/me")`, which would have produced paths like `/auth/me/me/mfa/totp/begin`. Corrected by removing the redundant prefix.

2. **`cors_browser_oauth` drops `supports_credentials()`**: Intentionally per spec — browser OAuth endpoints must not support credentials (no cookies in token/revoke/userinfo flows). The old unified CORS had `supports_credentials()`, which was too permissive.

3. **`cors_browser_oauth` max_age = 0**: Per spec, prevents browser caching of preflight responses for security-sensitive token endpoints. Previously was 3600.

4. **Missing `/auth/sessions` route**: The brief mentions `/auth/sessions` but this route doesn't exist in routes.rs. No change needed.

5. **`web::scope` vs `web::resource`**: Used `web::scope` for path-grouped routes (`/.well-known`, `/scim/v2`, `/admin`, `/auth/me`) and `web::resource` for standalone routes (`/token`, `/revoke`, `/userinfo`, `/jwks.json`). Both support `.wrap()` but scope is cleaner for multiple routes sharing a prefix.

## Issues / Concerns

- **No compilation verification**: Blocked by missing OpenSSL/NASM. The code follows established patterns (same `actix_cors::Cors` builder API, same `Settings` access pattern, same actix-web route/scope wrapping patterns), so type correctness is expected.
- **Feature Gate dependency**: The brief mentions the Feature Gates module is already committed and these changes are independent — confirmed, no feature gate dependency in these files.
- **`cors_auth_api` / `cors_admin` / `cors_scim` credentials**: Set to `supports_credentials()` ("depends" in brief). If cookie-less operation is desired, these can be removed with a config flag later. Current behavior matches the old unified CORS default.
