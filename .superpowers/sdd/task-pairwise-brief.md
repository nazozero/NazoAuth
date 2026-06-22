# Pairwise Subject — Implementation Brief

## Scope
Implement full OIDC pairwise subject support with sector_identifier_uri, SSRF-protected fetch, HMAC-SHA256 sub algorithm, client-level subject_type.

## Files to Modify

### Migration
Create `migrations/<timestamp>_add_pairwise_subject_fields/up.sql`:
```sql
ALTER TABLE clients ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'public'
    CHECK (subject_type IN ('public', 'pairwise'));
ALTER TABLE clients ADD COLUMN sector_identifier_uri TEXT;
ALTER TABLE clients ADD COLUMN sector_identifier_host TEXT;
```

And corresponding `down.sql` reverting all three columns.

### `src/domain/rows.rs` — ClientRow
Add fields:
```rust
pub(crate) subject_type: String,  // "public" or "pairwise"
pub(crate) sector_identifier_uri: Option<String>,
pub(crate) sector_identifier_host: Option<String>,
```

### New file: `src/support/sector_identifier.rs`
SSRF-protected sector_identifier_uri fetch:

```rust
pub(crate) fn fetch_sector_identifier_uris(uri: &str) -> Result<Vec<String>, SectorIdentifierError>
```

Rules:
- scheme must be "https"
- host must not be: localhost, 127.0.0.1, 10.x, 172.16-31.x, 192.168.x, 169.254.x, 0.0.0.0, ::1, fc00::/7, fe80::/10, ::, ::ffff:0:0/96, 169.254.169.254
- DNS resolved IP must also be checked against the same blocklist
- No automatic redirect following, or revalidate on each redirect
- Connect timeout 5s, total timeout 10s
- Max response body 128KB
- Content-Type must contain "application/json"
- Response must be a JSON array of strings (each a valid URI)

Error type:
```rust
pub(crate) enum SectorIdentifierError {
    InvalidUri,
    SchemeNotHttps,
    BlockedHost,
    DnsResolutionFailed,
    HttpError,
    Timeout,
    InvalidContentType,
    ResponseTooLarge,
    InvalidJson,
    InvalidEntry(String),
}
```

### Client Registration/Update Handler
Find the handler(s) where clients are created/updated. Add validation:

```
If subject_type == "pairwise" AND sector_identifier_uri is provided:
  1. Call fetch_sector_identifier_uris(uri)
  2. Verify ALL client.redirect_uris are in the returned list
  3. sector_identifier_host = host(sector_identifier_uri) — NOT from redirect URI
  4. Store both sector_identifier_uri and sector_identifier_host

If subject_type == "pairwise" AND sector_identifier_uri is NOT provided:
  1. If ALL redirect_uris share the same host → sector_identifier_host = that host
  2. If redirect_uris have multiple hosts → reject (require sector_identifier_uri)

If pairwise_subject_secret is not configured in settings → reject pairwise registration

sector_identifier_uri of an existing pairwise client CANNOT be modified
  (would break existing pairwise sub values)
```

### `src/support/oidc_claims.rs` — Rewrite oidc_subject

New signature:
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
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        mac.finalize().into_bytes(),
    )
}
```

Update `oidc_user_claims()` to accept and pass `sector_identifier_host`.

### `src/http/token/issue.rs` — Pass sector_identifier_host
Where oidc_user_claims is called, pass `client.sector_identifier_host` or compute the fallback from redirect_uri host.

### `src/http/token/userinfo.rs` — Pass sector_identifier_host
Same pattern.

### `src/settings.rs` — pairwise_subject_secret length validation
In `from_config()`, add:
```rust
if let Some(secret) = &pairwise_subject_secret {
    if secret.len() < 32 {
        return Err("pairwise_subject_secret must be at least 32 bytes");
    }
}
```

### `src/http/well_known.rs` — subject_types_supported
Already modified by Feature Gates. The discovery metadata currently uses:
```rust
"subject_types_supported": [settings.subject_type.as_str()],
```
This is the current behavior and changes with the Pairwise Subject module. You need to read the current well_known.rs (which was already modified by Feature Gates) and update subject_types_supported:

```rust
let subject_types = match (&settings.pairwise_subject_secret, &settings.subject_type) {
    (None, _) => vec!["public"],
    (Some(_), SubjectType::Pairwise) => vec!["pairwise"],
    (Some(_), _) => vec!["public", "pairwise"],
};
```

Note: `SubjectType` enum is in `src/settings/profile.rs`.

## Global Constraints
- sector_identifier_host = host(sector_identifier_uri), NOT the redirect_uri from the fetched JSON array
- sector_identifier_uri fetch must be SSRF-protected
- HMAC-SHA256 for pairwise sub calculation, not bare SHA256
- Issuer MUST be included in HMAC material
- pairwise_subject_secret length ≥ 32 validated at config load, not runtime
- Empty/absent pairwise_subject_secret must reject pairwise subject type registration
- Existing pairwise client's sector_identifier_uri must NOT be modifiable
