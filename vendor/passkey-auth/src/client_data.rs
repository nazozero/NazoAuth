//! Parse + validate `clientDataJSON`.
//!
//! Format (UTF-8 JSON, NOT to be transformed before SHA-256ing):
//! ```text
//! {
//!   "type":      "webauthn.create" | "webauthn.get",
//!   "challenge": "<base64url>",
//!   "origin":    "https://example.com",
//!   "crossOrigin": false,
//!   ...
//! }
//! ```
//! We deserialize the typed shape *for validation* but keep the raw
//! bytes around because the spec hashes those exact bytes into the
//! signed message (any pretty-printing or field reordering would
//! break verification).

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::types::{Challenge, b64url_decode, b64url_decode_strict};

/// Type tags the spec puts in `clientDataJSON.type`.
pub(crate) const TYPE_REGISTER: &str = "webauthn.create";
pub(crate) const TYPE_AUTHENTICATE: &str = "webauthn.get";

#[derive(Debug, Deserialize)]
struct Parsed {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    _cross_origin: bool,
}

/// Decode the base64url envelope, parse the JSON, then enforce the
/// invariants: type matches, challenge matches what we issued,
/// origin matches what we configured.
///
/// `strict` selects the base64 decoder used for the envelope and the
/// inner `challenge` field. When `false` (default), the lenient
/// `b64url_decode` (multi-alphabet, padding-tolerant) is used. When
/// `true`, only spec-compliant url-safe-no-pad is accepted.
///
/// Returns the *raw decoded bytes* (the canonical UTF-8 JSON the
/// authenticator hashed) so callers can SHA-256 them for the signed
/// message in authentication.
pub(crate) fn validate(
    encoded: &str,
    expected_type: &str,
    expected_challenge: &Challenge,
    expected_origin: &str,
    strict: bool,
) -> Result<Vec<u8>> {
    let decode = if strict {
        b64url_decode_strict
    } else {
        b64url_decode
    };
    let raw = decode(encoded)?;
    let p: Parsed = serde_json::from_slice(&raw).map_err(|e| Error::ClientData(e.to_string()))?;

    if p.kind != expected_type {
        return Err(Error::ClientDataType {
            expected: if expected_type == TYPE_REGISTER {
                "webauthn.create"
            } else {
                "webauthn.get"
            },
            actual: p.kind,
        });
    }

    let got_challenge = decode(&p.challenge)?;
    if got_challenge != expected_challenge.as_bytes() {
        return Err(Error::ChallengeMismatch);
    }

    if p.origin != expected_origin {
        return Err(Error::OriginMismatch {
            expected: expected_origin.to_owned(),
            actual: p.origin,
        });
    }

    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    fn make_cdj(kind: &str, challenge_b64: &str, origin: &str) -> String {
        let json = format!(
            r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
        );
        B64URL.encode(json.as_bytes())
    }

    #[test]
    fn happy_path_register() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.create", &chal.to_b64url(), "https://example.com");
        let raw = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap();
        // Returned raw is the decoded JSON, suitable for hashing.
        assert!(raw.starts_with(b"{\"type\":\"webauthn.create\""));
    }

    #[test]
    fn wrong_type_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.get", &chal.to_b64url(), "https://example.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::ClientDataType { .. }));
    }

    #[test]
    fn wrong_challenge_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let bad = Challenge(vec![9, 9, 9]);
        let cdj = make_cdj("webauthn.create", &bad.to_b64url(), "https://example.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }

    #[test]
    fn wrong_origin_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.create", &chal.to_b64url(), "https://evil.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::OriginMismatch { .. }));
    }
}
