# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Implement P0 Feature Gates + P1 CORS Restructuring + P1 Pairwise Subject for NazoAuth.

**Architecture:** Three independent subsystems modifying settings/config, HTTP handlers, and OIDC/OAuth logic. Feature Gates add early-rejection checks at authorize/PAR/token endpoints. CORS splits single middleware into per-route policies. Pairwise Subject adds full OIDC sector_identifier_uri support with HMAC-SHA256 subject calculation.

**Tech Stack:** Rust 2024, actix-web/cors, diesel-async (PostgreSQL), fred (Valkey), hmac/sha2, reqwest (SSRF-safe fetch)

## Global Constraints

- All feature gates default false (closed). FAPI2 Message Signing profile auto-enables PAR request object only.
- CORS: default deny. /authorize, /par, /introspect never get CORS middleware.
- Pairwise Subject: HMAC-SHA256, issuer+host+user_id in material, sector_identifier_host = host(sector_identifier_uri), not from redirect_uri array.
- SSRF protection for sector_identifier_uri fetch: https-only, no private/link-local/metadata IPs, 5s connect/10s total timeout, 128KB max body.
- pairwise_subject_secret >= 32 bytes validated at config load, not at runtime.

---

### Task 1: Feature Gates — Settings + Profile Methods

**Files:**
- Modify: `src/settings.rs` — add 5 bool fields + from_config()
- Modify: `src/settings/profile.rs` — add profile query methods
- Modify: `src/config.rs` — add env var allowlist entries
- Modify: `README.md` or `.env.yaml.example` — document new config

**Interfaces:**
- Consumes: `AuthorizationServerProfile` enum
- Produces: `Settings { enable_request_object, enable_request_uri_parameter, enable_par_request_object, enable_authorization_details, enable_legacy_audience_param }` all `bool`, plus `authorization_server_profile.requires_par()` / `.requires_signed_request_object_at_par()`

- [ ] **Step 1: Add profile methods**

In `src/settings/profile.rs`, add to `impl AuthorizationServerProfile`:

```rust
impl AuthorizationServerProfile {
    pub(crate) fn requires_par(&self) -> bool {
        matches!(self, Self::Fapi2Security | Self::Fapi2MessageSigningAuthzRequest)
    }

    pub(crate) fn requires_signed_request_object_at_par(&self) -> bool {
        matches!(self, Self::Fapi2MessageSigningAuthzRequest)
    }
}
```

- [ ] **Step 2: Add Settings fields**

In `src/settings.rs`, add to `Settings` struct:

```rust
pub(crate) enable_request_object: bool,
pub(crate) enable_request_uri_parameter: bool,
pub(crate) enable_par_request_object: bool,
pub(crate) enable_authorization_details: bool,
pub(crate) enable_legacy_audience_param: bool,
```

In `from_config()`, parse from config source:

```rust
enable_request_object: config_source.read_bool("enable_request_object")?.unwrap_or(false),
enable_request_uri_parameter: config_source.read_bool("enable_request_uri_parameter")?.unwrap_or(false),
enable_par_request_object: config_source.read_bool("enable_par_request_object")?.unwrap_or(false),
enable_authorization_details: config_source.read_bool("enable_authorization_details")?.unwrap_or(false),
enable_legacy_audience_param: config_source.read_bool("enable_legacy_audience_param")?.unwrap_or(false),
```

- [ ] **Step 3: Add env var allowlist entries**

In `src/config.rs`, add to `ALLOWLIST_KEYS`:

```rust
"enable_request_object",
"enable_request_uri_parameter",
"enable_par_request_object",
"enable_authorization_details",
"enable_legacy_audience_param",
```

- [ ] **Step 4: Compile and test**

```bash
cargo check 2>&1
```
Expected: compilation succeeds.

---

### Task 2: Feature Gates — /authorize Gate

**Files:**
- Modify: `src/http/authorization/request.rs` — add gate checks before deep parsing
- Test: relevant test file

**Interfaces:**
- Consumes: `settings.enable_request_object`, `settings.enable_request_uri_parameter`, `settings.enable_authorization_details`
- Produces: early 400 errors for disabled features

- [ ] **Step 1: Read and understand current code**

```bash
Select-String -Path "src/http/authorization/request.rs" -Pattern "fn authorize_request" 2>&1
```

Find the location where `query` parameters are parsed, before request object processing begins.

- [ ] **Step 2: Add gate checks**

In `authorize_request()`, after parameter deduplication and before `request`/`request_uri`/`authorization_details` processing:

```rust
if q.contains_key("request") && !state.settings.enable_request_object {
    return authorization_oauth_error_redirect(&state.settings, "invalid_request", "request parameter is not enabled");
}
if q.contains_key("request_uri") && !state.settings.enable_request_uri_parameter {
    return authorization_oauth_error_redirect(&state.settings, "invalid_request", "request_uri parameter is not enabled");
}
if q.contains_key("authorization_details") && !state.settings.enable_authorization_details {
    return authorization_oauth_error_redirect(&state.settings, "invalid_request", "authorization_details is not enabled");
}
```

- [ ] **Step 3: Run existing tests**

```bash
cargo test 2>&1
```
Expected: all tests pass.

---

### Task 3: Feature Gates — /par Gate

**Files:**
- Modify: `src/http/authorization/par.rs` — add gate checks for request object and authorization_details inside PAR body

**Interfaces:**
- Consumes: `enable_par_request_object`, `.requires_signed_request_object_at_par()`, `enable_authorization_details`

- [ ] **Step 1: Read PAR handler**

```bash
Select-String -Path "src/http/authorization/par.rs" -Pattern "fn par_after_rate_limit" 2>&1
```

- [ ] **Step 2: Add gate checks after PAR body parsing**

After the PAR payload is parsed and before request object processing:

```rust
if payload.request.is_some()
    && !state.settings.enable_par_request_object
    && !state.settings.authorization_server_profile.requires_signed_request_object_at_par()
{
    return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "request object at PAR is not enabled");
}
if payload.authorization_details.is_some() && !state.settings.enable_authorization_details {
    return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "authorization_details is not enabled");
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test 2>&1
```

---

### Task 4: Feature Gates — Token Audience Gate

**Files:**
- Modify: `src/http/token/forms.rs` or `src/http/token/dispatch.rs` — gate legacy `audience` parameter

**Interfaces:**
- Consumes: `enable_legacy_audience_param`

- [ ] **Step 1: Find where audience is parsed**

```bash
Select-String -Path "src/http/token/forms.rs" -Pattern "audience" 2>&1
Select-String -Path "src/http/token/dispatch.rs" -Pattern "audience" 2>&1
```

- [ ] **Step 2: Add gate check**

Where `audience` is extracted from the token request form:

```rust
if form.audience.is_some() && !state.settings.enable_legacy_audience_param {
    return oauth_token_error(StatusCode::BAD_REQUEST, "invalid_request", "legacy audience parameter is not enabled", false);
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test 2>&1
```

---

### Task 5: Feature Gates — Discovery Dynamic Exposure

**Files:**
- Modify: `src/http/well_known.rs` — gate-dependent metadata

**Interfaces:**
- Consumes: all 5 gate bools + profile methods

- [ ] **Step 1: Read well_known.rs**

```bash
Get-Content src/http/well_known.rs -Head 180 2>&1
```

- [ ] **Step 2: Gate `request_parameter_supported`**

```rust
if settings.enable_request_object {
    map.insert("request_parameter_supported".to_string(), json!(true));
}
```

- [ ] **Step 3: Gate `request_uri_parameter_supported` (always explicit)**

```rust
// OIDC Discovery: omitted defaults to true, so we must be explicit
map.insert("request_uri_parameter_supported".to_string(), json!(settings.enable_request_uri_parameter));
if settings.enable_request_uri_parameter {
    map.insert("require_request_uri_registration".to_string(), json!(true));
}
```

- [ ] **Step 4: Gate `request_object_signing_alg_values_supported`**

Expose when any relevant gate is enabled. Never include "none".

```rust
let expose_request_object_algs = settings.enable_request_object
    || settings.enable_request_uri_parameter
    || settings.enable_par_request_object
    || settings.authorization_server_profile.requires_signed_request_object_at_par();
if expose_request_object_algs {
    // Use the existing REQUEST_OBJECT_SIGNING_ALGS const, but filter out "none"
    let algs: Vec<&str> = REQUEST_OBJECT_SIGNING_ALGS.iter()
        .filter(|a| **a != "none")
        .copied()
        .collect();
    map.insert("request_object_signing_alg_values_supported".to_string(), json!(algs));
}
```

- [ ] **Step 5: Gate `authorization_details_types_supported`**

```rust
if settings.enable_authorization_details {
    // existing logic to expose types
}
```

- [ ] **Step 6: Run tests**

```bash
cargo test 2>&1
```

---

### Task 6: CORS — Rewrite cors.rs

**Files:**
- Rewrite: `src/bootstrap/cors.rs` — 5 constructor functions
- Modify: `src/bootstrap/routes.rs` — remove global CORS, apply per-scope

**Interfaces:**
- Produces: `cors_well_known(&Settings) -> Cors`, `cors_browser_oauth(&Settings) -> Cors`, `cors_auth_api(&Settings) -> Cors`, `cors_admin(&Settings) -> Cors`, `cors_scim(&Settings) -> Cors`

- [ ] **Step 1: Read current cors.rs**

```bash
Get-Content src/bootstrap/cors.rs 2>&1
```

- [ ] **Step 2: Rewrite with 5 constructor functions**

```rust
pub(crate) fn cors_well_known(settings: &Settings) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "HEAD"])
        .allowed_headers(vec![http::header::ACCEPT])
        .max_age(3600);
    for origin in &settings.cors_allowed_origins {
        cors = cors.allowed_origin(&origin);
    }
    cors
}

pub(crate) fn cors_browser_oauth(settings: &Settings) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST"])
        .allowed_headers(vec![
            http::header::AUTHORIZATION,
            http::header::CONTENT_TYPE,
            http::header::HeaderName::from_static("dpop"),
            http::header::HeaderName::from_static("x-csrf-token"),
        ])
        .expose_headers(vec![
            http::header::HeaderName::from_static("www-authenticate"),
            http::header::HeaderName::from_static("dpop-nonce"),
            http::header::HeaderName::from_static("retry-after"),
        ])
        .max_age(0);
    for origin in &settings.cors_allowed_origins {
        cors = cors.allowed_origin(&origin);
    }
    cors
}

pub(crate) fn cors_auth_api(settings: &Settings) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![
            http::header::AUTHORIZATION,
            http::header::CONTENT_TYPE,
            http::header::HeaderName::from_static("x-csrf-token"),
        ])
        .max_age(3600);
    for origin in &settings.cors_allowed_origins {
        cors = cors.allowed_origin(&origin);
    }
    cors
}

pub(crate) fn cors_admin(settings: &Settings) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::CONTENT_TYPE])
        .max_age(3600);
    for origin in &settings.cors_allowed_origins {
        cors = cors.allowed_origin(&origin);
    }
    cors
}

pub(crate) fn cors_scim(settings: &Settings) -> Cors {
    cors_admin(settings) // same policy
}
```

- [ ] **Step 3: Remove old build() function from cors.rs**

Delete the old `pub(crate) fn build(settings: &Settings) -> Cors` that returned a single unified CORS.

- [ ] **Step 4: Run tests**

```bash
cargo check 2>&1
```
Expected: compilation succeeds.

---

### Task 7: CORS — routes.rs Per-Scope CORS

**Files:**
- Modify: `src/bootstrap/routes.rs` — apply per-resource CORS middleware

**Interfaces:**
- Consumes: 5 Cors constructors from cors.rs

- [ ] **Step 1: Read current routes.rs**

```bash
Get-Content src/bootstrap/routes.rs 2>&1
```

- [ ] **Step 2: Find and remove global CORS middleware**

Look for `.wrap(cors)` in the App builder. Remove it.

- [ ] **Step 3: Apply CORS per scope/resource**

```rust
// Public endpoints
.scope("/.well-known")
    .wrap(cors_well_known(&state.settings))
    .service(web::resource("/openid-configuration").to(discovery))
    .service(web::resource("/oauth-authorization-server").to(oauth_authorization_server_metadata))
.service(web::resource("/jwks.json").wrap(cors_well_known(&state.settings)).to(jwks))

// /authorize — no CORS
.service(web::resource("/authorize").route(web::get().to(authorize_get)).route(web::post().to(authorize_post)))

// /par — no CORS
.service(web::resource("/par").route(web::post().to(par)))

// Browser OAuth API
.service(web::resource("/token").wrap(cors_browser_oauth(&state.settings)).route(web::post().to(token)))
.service(web::resource("/revoke").wrap(cors_browser_oauth(&state.settings)).route(web::post().to(revoke)))
.service(web::resource("/userinfo").wrap(cors_browser_oauth(&state.settings)).route(web::get().to(userinfo)).route(web::post().to(userinfo)))

// Auth UI — no CORS for login/register/consent/federation
// Auth API — with CORS
.scope("/auth/me").wrap(cors_auth_api(&state.settings)).service(...)

// Admin — with CORS
.scope("/admin").wrap(cors_admin(&state.settings)).service(...)

// SCIM — with CORS
.scope("/scim/v2").wrap(cors_scim(&state.settings)).service(...)
```

- [ ] **Step 4: Run tests**

```bash
cargo check 2>&1
```

---

### Task 8: Pairwise Subject — DB Migration + ClientRow

**Files:**
- Create: `migrations/<timestamp>_add_pairwise_subject_fields/up.sql`
- Create: `migrations/<timestamp>_add_pairwise_subject_fields/down.sql`
- Modify: `src/domain/rows.rs` — ClientRow fields
- Modify: `src/schema.rs` — regenerate or manual update

**Interfaces:**
- Produces: `ClientRow { subject_type: SubjectType, sector_identifier_uri: Option<String>, sector_identifier_host: Option<String> }`

- [ ] **Step 1: Create migration up.sql**

```sql
ALTER TABLE clients ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'public'
    CHECK (subject_type IN ('public', 'pairwise'));
ALTER TABLE clients ADD COLUMN sector_identifier_uri TEXT;
ALTER TABLE clients ADD COLUMN sector_identifier_host TEXT;
```

- [ ] **Step 2: Create migration down.sql**

```sql
ALTER TABLE clients DROP COLUMN subject_type;
ALTER TABLE clients DROP COLUMN sector_identifier_uri;
ALTER TABLE clients DROP COLUMN sector_identifier_host;
```

- [ ] **Step 3: Add fields to ClientRow**

In `src/domain/rows.rs`, add to `ClientRow`:

```rust
pub(crate) subject_type: String,  // "public" or "pairwise"
pub(crate) sector_identifier_uri: Option<String>,
pub(crate) sector_identifier_host: Option<String>,
```

- [ ] **Step 4: Update schema.rs**

```bash
cd NazoAuth && cargo run --bin nazo-oauth-migrate 2>&1
```
Or manually add the columns to the `clients` table definition in `src/schema.rs`.

- [ ] **Step 5: Run tests**

```bash
cargo check 2>&1
```

---

### Task 9: Pairwise Subject — Client Registration/Update + SSRF

**Files:**
- Modify: client create/update handler (likely under `src/http/admin/clients/`)
- Create or modify validation logic

**Interfaces:**
- Consumes: `ClientRow` with sector fields
- Produces: validated `sector_identifier_host` during registration/update

- [ ] **Step 1: Find client registration handler**

```bash
Get-ChildItem -Recurse src/http/admin/clients/ 2>&1
```

- [ ] **Step 2: Add SSRF-safe fetch function in support/**

Create or use existing HTTP fetch with strict constraints in `src/support/`:

```rust
pub(crate) fn fetch_sector_identifier_uri(
    uri: &str,
) -> Result<Vec<String>, SectorIdentifierError> {
    let url = url::Url::parse(uri).map_err(|_| SectorIdentifierError::InvalidUri)?;

    // SSRF check: https only
    if url.scheme() != "https" {
        return Err(SectorIdentifierError::SchemeNotHttps);
    }

    // SSRF check: no private/link-local/metadata hosts
    let host = url.host_str().ok_or(SectorIdentifierError::InvalidHost)?;
    validate_ssrf_host(host)?;

    // Fetch with timeouts and size limits
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().scheme() != "https" {
                attempt.error("redirect to non-https");
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|_| SectorIdentifierError::HttpClient)?;

    let response = client.get(uri)
        .send()
        .map_err(|_| SectorIdentifierError::FetchFailed)?;

    // Check content type
    let content_type = response.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.contains("application/json") {
        return Err(SectorIdentifierError::InvalidContentType);
    }

    // Size limit
    let body = response.bytes()
        .map_err(|_| SectorIdentifierError::ReadFailed)?;
    if body.len() > 128 * 1024 {
        return Err(SectorIdentifierError::ResponseTooLarge);
    }

    // Parse JSON array of strings
    let uris: Vec<String> = serde_json::from_slice(&body)
        .map_err(|_| SectorIdentifierError::InvalidJson)?;

    // Validate each entry is a valid URI
    for entry in &uris {
        url::Url::parse(entry)
            .map_err(|_| SectorIdentifierError::InvalidEntry(entry.clone()))?;
    }

    Ok(uris)
}

fn validate_ssrf_host(host: &str) -> Result<(), SectorIdentifierError> {
    // Skip if IP-based
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
            || matches!(ip, std::net::IpAddr::V4(v) if v.octets()[0] == 0)
            || matches!(ip, std::net::IpAddr::V6(v) if v.segments()[0] == 0)
        {
            return Err(SectorIdentifierError::BlockedHost);
        }
        return Ok(());
    }

    // Domain-based
    let lower = host.to_lowercase();
    if lower == "localhost" || lower == "127.0.0.1" || lower.ends_with(".local") {
        return Err(SectorIdentifierError::BlockedHost);
    }

    Ok(())
}
```

- [ ] **Step 3: Add validation in client create/update**

```rust
// During client create or update, if subject_type == "pairwise":
let sector_identifier_host = match input.sector_identifier_uri {
    Some(uri) => {
        let uris = fetch_sector_identifier_uri(&uri)?;
        // Verify all registered redirect URIs are in the fetched list
        for redirect_uri in &client.redirect_uris {
            if !uris.iter().any(|u| u == redirect_uri) {
                return Err("sector_identifier_uri does not contain all registered redirect_uris");
            }
        }
        // sector_identifier_host = host(uri), not the fetched list
        let parsed = url::Url::parse(&uri).map_err(|_| "invalid sector_identifier_uri")?;
        parsed.host_str().ok_or("invalid sector_identifier_uri host")?.to_string()
    }
    None => {
        // Fallback: all redirect_uris must share the same host
        let hosts: std::collections::HashSet<&str> = client.redirect_uris.iter()
            .filter_map(|u| url::Url::parse(u).ok())
            .filter_map(|u| u.host_str().map(|h| h))
            .collect();
        if hosts.len() != 1 {
            return Err("multiple redirect_uri hosts require sector_identifier_uri");
        }
        hosts.into_iter().next().unwrap().to_string()
    }
};
```

- [ ] **Step 4: Run tests**

```bash
cargo check 2>&1
```

---

### Task 10: Pairwise Subject — Rewrite oidc_subject

**Files:**
- Modify: `src/support/oidc_claims.rs` — HMAC-SHA256, new signature

**Interfaces:**
- Produces: `oidc_subject(pairwise_subject_secret: &[u8], issuer: &str, sector_identifier_host: &str, user_id: Uuid) -> String`

- [ ] **Step 1: Read current oidc_subject**

```bash
Select-String -Path "src/support/oidc_claims.rs" -Pattern "oidc_subject" 2>&1
```

- [ ] **Step 2: Rewrite with HMAC-SHA256**

```rust
pub(crate) fn oidc_subject(
    pairwise_subject_secret: &[u8],
    issuer: &str,
    sector_identifier_host: &str,
    user_id: Uuid,
) -> String {
    debug_assert!(pairwise_subject_secret.len() >= 32);
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(pairwise_subject_secret)
        .expect("pairwise_subject_secret should be valid");
    mac.update(issuer.as_bytes());
    mac.update(b"\x1f");
    mac.update(sector_identifier_host.as_bytes());
    mac.update(b"\x1f");
    mac.update(user_id.to_string().as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, mac.finalize().into_bytes())
}
```

- [ ] **Step 3: Update callers of oidc_subject within oidc_claims.rs**

Update `oidc_user_claims()` to pass `pairwise_subject_secret`, `issuer`, and `sector_identifier_host` from caller context.

- [ ] **Step 4: Run tests**

```bash
cargo check 2>&1
```

---

### Task 11: Pairwise Subject — Update Callers

**Files:**
- Modify: `src/http/token/issue.rs` — pass sector_identifier_host to oidc_user_claims
- Modify: `src/http/token/userinfo.rs` — pass sector_identifier_host to oidc_user_claims

**Interfaces:**
- Consumes: `ClientRow.sector_identifier_host`, `ClientRow.subject_type`, new `oidc_subject` signature

- [ ] **Step 1: Update token issue**

Find where `oidc_user_claims()` is called in issue.rs. Pass `client.sector_identifier_host` (or the fallback from redirect_uri host if none).

- [ ] **Step 2: Update userinfo**

Same pattern in userinfo.rs.

- [ ] **Step 3: Run tests**

```bash
cargo check 2>&1
```

---

### Task 12: Pairwise Subject — Discovery Dynamic Exposure

**Files:**
- Modify: `src/http/well_known.rs` — subject_types_supported based on config

**Interfaces:**
- Consumes: `settings.pairwise_subject_secret`, `settings.subject_type`

- [ ] **Step 1: Update subject_types_supported in discovery**

```rust
let subject_types = match (&settings.pairwise_subject_secret, &settings.subject_type) {
    (None, _) => vec!["public"],
    (Some(_), SubjectType::Pairwise) => vec!["pairwise"],
    (Some(_), _) => vec!["public", "pairwise"],
};
map.insert("subject_types_supported".to_string(), json!(subject_types));
```

- [ ] **Step 2: Run tests**

```bash
cargo test 2>&1
```

---

### Task 13: Final Validation

- [ ] **Step 1: Full compile check**

```bash
cargo check 2>&1
```
Expected: 0 errors, 0 warnings.

- [ ] **Step 2: Run full test suite**

```bash
cargo test 2>&1
```
Expected: all tests pass (or pre-existing failures only).

- [ ] **Step 3: Update .env.yaml.example**

Commit the example config with all new gates documented.
