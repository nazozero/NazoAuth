# passkey-auth

[![CI](https://github.com/marirs/passkey-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/passkey-auth/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/passkey-auth.svg)](https://crates.io/crates/passkey-auth)
[![docs.rs](https://img.shields.io/docsrs/passkey-auth)](https://docs.rs/passkey-auth)
[![License](https://img.shields.io/crates/l/passkey-auth.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://blog.rust-lang.org/)
[![Dependencies](https://deps.rs/repo/github/marirs/passkey-auth/status.svg)](https://deps.rs/repo/github/marirs/passkey-auth)

Pure-Rust WebAuthn server library focused on the passkey ceremony.
Verifies registration + authentication responses from browsers/OS
authenticators (Touch ID, Windows Hello, Android, iCloud Keychain,
hardware keys).

## Installation

```toml
[dependencies]
passkey-auth = "0.1"
```

MSRV: **Rust 1.85** (edition 2024).

## Why this exists

The reference Rust server library, `webauthn-rs`, hard-depends on
`openssl`. This crate is the alternative for projects that ship
rustcrypto end-to-end:

| Concern                | This crate                                                     | webauthn-rs              |
|------------------------|----------------------------------------------------------------|--------------------------|
| ECDSA P-256 verify     | [`p256`](https://crates.io/crates/p256)                        | openssl                  |
| Ed25519 verify         | [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek)      | openssl                  |
| SHA-256                | [`sha2`](https://crates.io/crates/sha2)                        | openssl                  |
| CBOR                   | [`ciborium`](https://crates.io/crates/ciborium)                | serde_cbor (deprecated)  |
| Attestation chain      | x5c sig verified, root NOT validated                           | full X.509 + FIDO MDS    |

## Scope

- Registration ceremony (parse `AuthenticatorAttestationResponse`, verify origin/challenge, extract public key)
- Authentication ceremony (parse `AuthenticatorAssertionResponse`, verify signature)
- Algorithms: **ES256** (COSE alg -7, P-256 ECDSA) and **EdDSA** (-8, Ed25519); the credential's alg is enforced at registration against the advertised `pubKeyCredParams` (WebAuthn-3 §7.1 step 19)
- Attestation formats:
  - `none` (fully)
  - `packed` self-attestation (no cert chain)
  - `packed` with `x5c` cert chain (cert sig verified; chain NOT validated to a root)
  - `fido-u2f` (legacy Yubikeys; cert sig verified, chain NOT validated)
- Replay protection via the authenticator counter
- Opt-in **user-verification enforcement** for production passkey deployments (`.require_user_verification(true)`)
- Opt-in **user-handle enforcement** for username-first flows (`start_authentication_for_user` + `.require_user_handle(true)`) — verifies the assertion's `userHandle` matches the expected user (WebAuthn-3 §7.2 step 6)
- Configurable **authenticator attachment** (platform / cross-platform / any) — see [`Attachment`](https://docs.rs/passkey-auth/latest/passkey_auth/enum.Attachment.html)
- Base64 decoding: lenient by default (accepts url-safe / standard / padded / unpadded inputs); flip `.strict_base64(true)` to require spec-compliant url-safe-no-pad

Not in scope:

- **Cert chain validation against a trusted root.** Without the FIDO
  Metadata Service we cannot tell whether an `x5c` cert really came
  from Yubico / Feitian / etc.; we only confirm the attestation `sig`
  was produced by whoever owns the leaf cert's private key. For "only
  these specific authenticator models" enterprise policy, you need
  full MDS — this crate is not the right pick.
- Conditional UI / discoverable credentials beyond what the server needs to know
- RSA / RS256 (rare for passkeys; reject with a clear error)
- TPM / Android-Key / Android-SafetyNet / Apple attestation formats

## Usage

```rust,ignore
use passkey_auth::{
    AuthenticationResponse, PasskeyCredential, RegistrationResponse, Webauthn,
};

// Construct once at boot. Cheap to clone. Production-tightening
// builders:
//   .require_user_verification(true)  reject UV-less assertions
//   .require_user_handle(true)        reject assertions missing the
//                                     userHandle in for_user flows
//   .strict_base64(true)              reject non-spec base64 on wire
let wa = Webauthn::new("example.com", "Example", "https://example.com")
    .require_user_verification(true);

// ── 1. Registration ───────────────────────────────────────────────
let user_id: &[u8] = b"user-handle-bytes"; // stable opaque user id
let (challenge, state) = wa.start_registration(
    user_id,
    "alice@example.com",   // user.name  (RP-facing)
    "Alice",               // user.displayName
    &[],                   // credentials already registered (for excludeCredentials)
);
// → serialise `challenge` to JSON, send to the browser
// ← browser POSTs back a RegistrationResponse JSON
let response: RegistrationResponse = todo!();

let credential: PasskeyCredential = wa.finish_registration(&state, &response)?;
// Persist: credential.id, credential.public_key_cose,
//          credential.counter, credential.transports, credential.aaguid

// ── 2. Authentication (username-first flow) ───────────────────────
// `_for_user` records the user_handle on the state so
// finish_authentication can verify the assertion is FOR this user
// (WebAuthn-3 §7.2 step 6) — defence in depth against credential-id
// collisions in a multi-user store.
//
// Use plain `start_authentication_with_creds(&creds)` for
// discoverable / passwordless flows where the user is unknown
// until the response arrives — see examples/axum_passwordless.rs.
let (challenge, state) = wa.start_authentication_with_creds_for_user(
    user_id,
    &[credential.clone()],
);
let response: AuthenticationResponse = todo!();

let outcome = wa.finish_authentication(&state, &response, &credential)?;
// Update stored counter: credential.counter = outcome.new_counter
```

### RP ID parsing from URLs

`Webauthn::new` takes the bare domain (no scheme, no port). If the
value might be a full URL (config file, env var pasted by an operator),
validate it first:

```rust,ignore
use passkey_auth::RpId;

let rp = RpId::try_from_url("https://example.com:8443/auth")?;
assert_eq!(rp.as_str(), "example.com");
```

`RpId::new` itself stores its input verbatim — pass a bare hostname
or call `try_from_url` first.

### Client-side encoding

The browser's `AuthenticatorResponse` fields (`attestationObject`,
`authenticatorData`, `clientDataJSON`, `signature`) are
`ArrayBuffer`s; the JS layer must base64-encode them before posting.

By default this crate is **lenient**: it accepts url-safe-base64
**or** standard-base64, **with or without** padding — so the obvious
`btoa(...)` pattern works without a separate url-safe-conversion
step. Convenient for getting started.

Production deployments that control their own client JS should flip
the strict toggle:

```rust,ignore
let wa = Webauthn::new("example.com", "Example", "https://example.com")
    .strict_base64(true);
```

Strict mode accepts only the spec-compliant url-safe-no-pad
encoding (WebAuthn §6.1). Any other variant returns
`Error::Base64`, surfacing client-side encoding bugs instead of
papering over them.

## Working examples

Five runnable HTTP-server examples live under [`examples/`](examples/),
covering the most common passkey-app patterns. All bind to
<http://localhost:3000> — run **one at a time** in a passkey-capable
browser (Touch ID, Windows Hello, iCloud Keychain, Yubikey, etc.).

| Example | Framework | What it shows |
|---|---|---|
| [`axum_server`](examples/axum_server.rs) | Axum 0.7 | Minimal single-user register + authenticate |
| [`rocket_server`](examples/rocket_server.rs) | Rocket 0.5 | Same as above, Rocket variant |
| [`axum_passwordless`](examples/axum_passwordless.rs) | Axum 0.7 | **Multi-user** with **usernameless** sign-in (Gmail-style "tap to sign in", discoverable credentials, browser shows account picker) |
| [`rocket_credential_manager`](examples/rocket_credential_manager.rs) | Rocket 0.5 | **Multiple devices per user**: register additional passkeys while signed in, list them, remove individual ones (refuses to remove the last) |
| [`axum_sqlite`](examples/axum_sqlite.rs) | Axum 0.7 + rusqlite | **Persistent storage**: same as `axum_server` but credentials survive process restart in `passkeys.db` |

```bash
cargo run --example axum_server                # start here
cargo run --example axum_passwordless          # then try the Gmail flow
cargo run --example rocket_credential_manager  # then try multi-device
cargo run --example axum_sqlite                # then try persistence
```

All five are explicitly **not for production** (in-memory sessions
where applicable, single hard-coded user in the manager variant, no
CSRF protection on the start endpoints) — read them as references for
wiring the crate into your own server, not as copy-paste starters.

## Testing

```bash
cargo test            # unit + integration + doc-tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI exercises Linux x86_64 + aarch64, macOS Apple Silicon, and
Windows x86_64 on every push.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](APACHE-LICENSE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE](LICENSE) or <https://opensource.org/licenses/MIT>)
