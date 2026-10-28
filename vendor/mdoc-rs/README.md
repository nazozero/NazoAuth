# mdoc-rs

A Rust library for **ISO/IEC 18013-5** mobile documents (mdoc) — the credential
format behind the **mobile driving licence (mDL)** and the **EUDI Wallet PID**.

`mdoc-rs` covers the full credential lifecycle:

- **Parsing** a CBOR-encoded `DeviceResponse` (or hex) into a typed model
- **Verification** — issuer trust, data integrity, and holder binding
- **Selective disclosure** digest checking
- **Issuance** — building and signing documents, with deterministic (canonical)
  CBOR output, and re-encoding back to a wire-format `DeviceResponse` (feature
  `issue`)

> **Status:** `0.2.0`. The verification pipeline enforces the load-bearing trust
> checks of the ISO 18013-5 model (see [Security model](#security-model)). The
> API is pre-1.0 and may change.

---

## Features at a glance

| Capability | Notes |
|------------|-------|
| Parse `DeviceResponse` → `MDoc` | `parser::parse` (bytes) / `parser::parse_hex` (hex, whitespace-tolerant) |
| IACA X.509 chain validation | Leaf Document-Signer cert path-validated to a trusted IACA anchor (feature `tsp`) |
| Issuer / device signatures (COSE_Sign1) | ES256 (P-256) / ES384 (P-384) / ES512 (P-521) / EdDSA (Ed25519) |
| Data integrity / selective disclosure | Digests over Tag-24-wrapped `IssuerSignedItemBytes` (ISO §9.1.2.5) |
| Device authentication | `deviceSignature` (COSE_Sign1) and `deviceMac` (COSE_Mac0) over `DeviceAuthentication` |
| Fail-closed verdict | `is_valid` requires every required check to have run and passed |
| Issuance | `DocumentBuilder` + a pluggable `CoseSigner`; canonical CBOR, auto-tagged dates, random `digestID`s, status-list support (feature `issue`) |
| Re-encoding | `MDoc` / document → `DeviceResponse` CBOR via `to_device_response_cbor` (feature `issue`) |
| CBOR diagnostics | Diagnostic-notation pretty printer for interop triage (feature `debug`) |

### Cargo features

| Feature | Default | What it does |
|---------|:-------:|--------------|
| `tsp` | ✅ | IACA certificate-chain validation via [`tsp-ltv`](https://crates.io/crates/tsp-ltv). **Without it, chain validation fails closed.** |
| `issue` | ✅ | Document building/signing/encoding (`builder`, `response_builder`, `encoder`). |
| `blocking` | ✅ | Reserved for synchronous API wrappers. |
| `engagement` | — | Reserved: device engagement (QR/NFC/BLE) + session encryption. |
| `status` | — | Reserved: credential revocation / status-list checking. |
| `debug` | — | CBOR diagnostic-notation pretty printer (`diagnostic`) for interop triage. |
| `pkcs11-example` | — | Builds the PKCS#11 (HSM) issuance example; pulls the `cryptoki` C bindings. |

```toml
[dependencies]
mdoc-rs = "0.2"

# Verification only, no issuance:
mdoc-rs = { version = "0.2", default-features = false, features = ["tsp"] }
```

MSRV: **Rust 1.81**. License: **BSD-2-Clause**.

---

## Verifying a credential

```rust
use mdoc_rs::{Verifier, VerifyOptions};

// IACA trust anchors (DER-encoded), out-of-band from your trust list.
let iaca_roots: Vec<Vec<u8>> = load_iaca_roots();

let verifier = Verifier::new(iaca_roots);

// `encoded` is the CBOR DeviceResponse received from the holder's wallet.
let result = verifier.verify(encoded, &VerifyOptions::default())?;

if result.is_valid {
    println!("credential is valid");
} else {
    // Inspect exactly which checks failed.
    for a in &result.assessments {
        if a.status != mdoc_rs::verifier::VerificationStatus::Passed {
            println!("{:?}: {} — {:?}", a.status, a.check, a.reason);
        }
    }
}
```

### Verifying a device-bound presentation

To verify holder binding (anti-cloning), supply the **session transcript** that
both parties agreed on. Without it, a device-bound document fails closed.

```rust
use mdoc_rs::{Verifier, VerifyOptions};
use mdoc_rs::session::SessionTranscript;

let opts = VerifyOptions {
    // ISO 18013-5 proximity, ISO 18013-7 OpenID4VP, WebAPI, or pre-encoded Raw.
    session_transcript: Some(SessionTranscript::Oid4vp {
        mdoc_nonce: mdoc_nonce.into(),
        client_id: client_id.into(),
        response_uri: response_uri.into(),
        verifier_nonce: verifier_nonce.into(),
    }),
    // Required only for MAC-mode (COSE_Mac0) device auth — the reader's
    // ephemeral private key (raw P-256 scalar) for ECDH key agreement.
    ephemeral_reader_key: None,
    ..Default::default()
};

let result = verifier.verify(encoded, &opts)?;
assert!(result.is_valid);
```

`VerifiedMDoc` gives you the parsed `mdoc`, the full list of `assessments`, and
the overall `is_valid` verdict. Each `VerificationAssessment` carries a
`status` (`Passed` / `Failed` / `Warning`), a human-readable `check`, an optional
`reason`, a `category`, and a stable `CheckId`.

---

## Issuing a credential (feature `issue`)

Signing is abstracted behind the `CoseSigner` trait, so the private key can live
anywhere — in memory, in an HSM, or behind PKCS#11.

```rust
use chrono::{Duration, Utc};
use mdoc_rs::builder::{CoseSigner, DocumentBuilder};
use mdoc_rs::error::MdocError;
use mdoc_rs::model::types::{DigestAlgorithm, ValidityInfo};

struct MySigner { /* signing key + X.509 cert (DER) */ }

impl CoseSigner for MySigner {
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, MdocError> {
        // Return a raw r‖s COSE signature (64 bytes for ES256).
        todo!()
    }
    fn algorithm(&self) -> i64 { -7 } // ES256
    fn certificate_der(&self) -> &[u8] { todo!() }
}

let now = Utc::now();
let doc = DocumentBuilder::new("org.iso.18013.5.1.mDL")
    .add_namespace("org.iso.18013.5.1", vec![
        ("family_name", ciborium::Value::Text("Lindqvist".into())),
        ("age_over_21", ciborium::Value::Bool(true)),
        // Well-known date fields are auto-tagged as CBOR Tag 1004 (full-date);
        // pass a plain string and the builder wraps it for you.
        ("birth_date", ciborium::Value::Text("1990-01-15".into())),
    ])
    .validity(ValidityInfo {
        signed: now,
        valid_from: now,
        valid_until: now + Duration::days(365),
        expected_update: None,
    })
    .digest_algorithm(DigestAlgorithm::Sha256)
    // Optional: embed an IETF Token Status List reference in the signed MSO.
    .status_list(42, "https://issuer.example/statuslists/1")
    .sign(&MySigner { /* … */ })?;

// Re-encode the signed document as a wire-format DeviceResponse.
let response_cbor: Vec<u8> = doc.to_device_response_cbor()?;
```

The builder applies ISO 18013-5 / EUDIW issuance conventions automatically:

- **Auto-tagging** — `birth_date`, `issue_date`, `expiry_date`, `issuance_date`
  are wrapped in CBOR Tag 1004 and `effective_from_date` in Tag 0, recursing
  into `driving_privileges`. Disable with `.auto_tag(false)` to tag values
  yourself.
- **Random `digestID`s** — non-sequential, to avoid cross-presentation
  correlation.
- **Deterministic output** — `IssuerSignedItem`s and the MSO are encoded as
  canonical CBOR (RFC 8949 §4.2.1), so issuance is reproducible.
- **Status** — `.status_list(idx, uri)` (IETF Token Status List) or
  `.status_raw(value)` embeds revocation status into the signed MSO.

`DeviceResponseBuilder` (also `issue`) assembles a presentation with selective
disclosure and device authentication.

### HSM-backed issuance (PKCS#11)

Because signing goes through `CoseSigner`, the issuer key can live in an HSM.
`examples/pkcs11_issuer.rs` implements the trait against a PKCS#11 token (tested
conceptually against SoftHSM2 and Kryoptic):

```sh
cargo run --example pkcs11_issuer --features pkcs11-example
```

---

## Security model

`mdoc-rs` enforces the three pillars of the ISO 18013-5 trust model. `is_valid`
is **fail-closed**: it is `true` only when every *required* check actually ran
and passed — a skipped or downgraded security check makes the result invalid.

- **Issuer authentication** — the leaf Document-Signer certificate from the
  credential's `x5chain` is path-validated up to a caller-supplied **IACA trust
  anchor** (feature `tsp`), and the `issuerAuth` COSE_Sign1 is verified against
  that leaf key. A self-signed/forged certificate is rejected.
- **Data integrity** — every disclosed attribute is hashed (over the
  **Tag-24-wrapped** `IssuerSignedItemBytes`) and matched against the digest
  committed in the signed MSO; the document `docType` must match the MSO.
- **Holder binding** — `deviceSignature` / `deviceMac` is cryptographically
  verified against the device key bound in the MSO, over the
  `DeviceAuthentication` structure built from the session transcript;
  `keyAuthorizations` are enforced over device-asserted elements.

`disable_certificate_chain_validation` exists for **testing only**: it is an
explicit, loudly-logged opt-out that records in the assessment that issuer trust
was *not* verified.

> Verification is only as strong as your IACA trust list. A `Verifier` built with
> no anchors rejects everything.

---

## Crate layout

| Module | Purpose |
|--------|---------|
| `parser` | CBOR `DeviceResponse` → `MDoc` |
| `verifier` | Full verification pipeline, `Verifier` / `VerifyOptions` / `VerifiedMDoc` |
| `disclosure` | Selective-disclosure digest verification |
| `device_auth` | Device authentication (COSE_Sign1 + COSE_Mac0) |
| `session` | Session transcript + `DeviceAuthentication` construction |
| `cose` | COSE key conversion and signature verification (incl. SEC1/PEM key import) |
| `cbor` | CBOR helpers (Tag 24 encoded data items, Tag 1004 full-dates, canonical encoding) |
| `model` | ISO 18013-5 data model (MSO, IssuerSigned, DeviceSigned, MSO status, …) |
| `builder` / `response_builder` / `encoder` | Issuance and DeviceResponse encoding (feature `issue`) |
| `diagnostic` | CBOR diagnostic-notation pretty printer (feature `debug`) |

---

## Building and testing

```sh
cargo build
cargo test                       # default features
cargo test --all-features
cargo test --no-default-features --features tsp   # verification-only build
```

---

## Standards

- **ISO/IEC 18013-5** — mDL data model, MSO, device engagement, presentation
- **ISO/IEC 18013-7** — online (OpenID4VP) presentation
- **RFC 8152 / RFC 9052** — COSE (`COSE_Sign1`, `COSE_Mac0`)
- **RFC 8949** — CBOR (Tag 24 encoded data items, deterministic encoding)
- **RFC 8943** — CBOR Tag 1004 full-dates
- **IETF Token Status List** — credential revocation status (MSO `status`)

## License

BSD-2-Clause.
