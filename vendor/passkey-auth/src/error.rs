//! Errors surfaced from registration / authentication ceremonies.
//!
//! All variants are deliberately specific (not "verification failed")
//! so callers can log/audit them - they don't leak data to the client
//! since the route layer is expected to translate any error into a
//! generic 401/400 before responding.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Invalid base64url encoding on a wire field (challenge, credential
    /// id, signature, etc.).
    #[error("invalid base64url: {0}")]
    Base64(String),

    /// `clientDataJSON` failed to parse as UTF-8 JSON, or was JSON but
    /// missing required fields.
    #[error("clientDataJSON parse failed: {0}")]
    ClientData(String),

    /// `clientDataJSON.type` was wrong for the ceremony in flight
    /// (expected `webauthn.create` / `webauthn.get`).
    #[error("clientDataJSON.type mismatch: expected {expected}, got {actual}")]
    ClientDataType {
        expected: &'static str,
        actual: String,
    },

    /// `clientDataJSON.challenge` did not match the challenge issued
    /// at the start of the ceremony.
    #[error("challenge mismatch")]
    ChallengeMismatch,

    /// `clientDataJSON.origin` was not exactly the configured RP origin.
    #[error("origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch { expected: String, actual: String },

    /// `authenticatorData.rpIdHash` did not match SHA-256(RP_ID).
    #[error("rpIdHash mismatch")]
    RpIdHashMismatch,

    /// The user-present (UP) bit was 0 - caller required UP.
    #[error("user-present flag not set")]
    UserNotPresent,

    /// The user-verified (UV) bit was 0 - caller required UV.
    #[error("user-verified flag not set")]
    UserNotVerified,

    /// Binary parse of `authenticatorData` failed at the byte level.
    #[error("authenticatorData parse failed: {0}")]
    AuthData(&'static str),

    /// CBOR parse of attestationObject or COSE key failed.
    #[error("CBOR decode failed: {0}")]
    Cbor(String),

    /// COSE key used an algorithm we don't support (only ES256 / EdDSA).
    #[error("unsupported COSE algorithm: {0}")]
    UnsupportedAlg(i64),

    /// Signature verification with the stored public key failed.
    #[error("signature verification failed")]
    BadSignature,

    /// The authenticator counter went backwards or did not increase
    /// when the spec requires it. Caller should treat this as a cloned
    /// credential and reject.
    #[error("counter went backwards (stored={stored}, new={new}): possible cloned credential")]
    CounterReplay { stored: u32, new: u32 },

    /// The ceremony state handed to `finish_*` is older than the
    /// allowed ceiling (default 5 minutes). Indicates the caller did
    /// not TTL their session store, or the response came back after
    /// the user walked away. Reject and restart the ceremony.
    #[error("ceremony state expired ({age_secs} seconds old, max {max_secs})")]
    CeremonyExpired { age_secs: u64, max_secs: u64 },

    /// The `userHandle` carried in the assertion response did not
    /// match the user handle recorded at `start_authentication_for_user`
    /// time (WebAuthn-3 §7.2 step 6). Indicates an attack — the
    /// assertion is for a different user than the ceremony was
    /// started for — or, when `require_user_handle(true)` is set, an
    /// authenticator that did not emit a user_handle at all.
    #[error(
        "user handle mismatch: assertion is for a different user than the ceremony was started for"
    )]
    UserHandleMismatch,

    /// Internal invariant violation (bug). Should never reach a user.
    #[error("internal: {0}")]
    Internal(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
