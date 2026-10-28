//! Wire types shared by registration + authentication ceremonies.
//!
//! All byte-array fields on the wire are base64url-encoded with no
//! padding (per the WebAuthn spec). The browser's `PublicKeyCredential`
//! is normally surfaced as JSON; we mirror that JSON shape in
//! [`RegistrationResponse`] / [`AuthenticationResponse`] so a Rocket
//! handler can deserialize directly off the request body.

use base64::Engine;
use base64::engine::general_purpose::{
    STANDARD as B64STD, STANDARD_NO_PAD as B64STD_NO_PAD, URL_SAFE as B64URL_PAD,
    URL_SAFE_NO_PAD as B64URL,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ---------- Challenge ----------------------------------------------------

/// 32 random bytes the browser signs (indirectly) to prove freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Challenge(pub Vec<u8>);

impl Challenge {
    /// Cryptographic random; uses `rand::thread_rng()` (OS CSPRNG).
    #[must_use]
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        Self(buf.to_vec())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Browser-friendly base64url encoding (no padding).
    #[must_use]
    pub fn to_b64url(&self) -> String {
        B64URL.encode(&self.0)
    }
}

// ---------- CredentialId -------------------------------------------------

/// Authenticator-assigned credential ID. Opaque, treat as raw bytes;
/// not a UUID. Up to 1023 bytes long per the spec, in practice ~64–256.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialId(pub Vec<u8>);

impl CredentialId {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[must_use]
    pub fn to_b64url(&self) -> String {
        B64URL.encode(&self.0)
    }
    pub fn from_b64url(s: &str) -> Result<Self> {
        b64url_decode(s).map(Self)
    }
}

// ---------- COSE / public-key blob --------------------------------------

/// COSE_Key-encoded public key (CBOR), exactly as carried in
/// `attestedCredentialData.credentialPublicKey`. Stored as-is so we can
/// re-verify signatures without re-parsing the COSE structure beyond
/// the alg + key params already extracted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CosePublicKey(pub Vec<u8>);

impl CosePublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ---------- Configuration -----------------------------------------------

/// Relying-party identifier. By spec this is a domain (no scheme, no
/// port). `example.com`, not `https://example.com`. The browser's
/// SHA-256 of this string is what the authenticator signs into
/// `authenticatorData.rpIdHash`.
#[derive(Debug, Clone)]
pub struct RpId(pub(crate) String);

impl RpId {
    /// Construct from a string that already IS a bare RP ID
    /// (`example.com`, `subdomain.example.com`). Use this in
    /// production code where the value comes from a config file or
    /// known constant.
    ///
    /// If you might receive a full URL, use [`Self::try_from_url`]
    /// instead - this constructor stores the input verbatim and does
    /// NOT strip scheme/port/path, so passing `"https://example.com"`
    /// here gives you a broken RP ID.
    pub fn new(rp_id: impl Into<String>) -> Self {
        Self(rp_id.into())
    }

    /// Try to extract an RP ID from a URL or URL-like input.
    /// Accepts:
    ///   - bare domains:        `"example.com"`
    ///   - full origins:        `"https://example.com:8443"`
    ///   - origins with a path: `"https://example.com/auth/start"`
    ///
    /// Returns `Err` if the input is neither parseable as a URL nor a
    /// plausible bare hostname (no whitespace, no userinfo, etc.).
    /// Use this when the input might be a URL the operator pasted.
    pub fn try_from_url(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::Internal("RP ID is empty"));
        }

        // First try a strict URL parse - works for "https://..." inputs.
        if let Ok(u) = url::Url::parse(trimmed) {
            if let Some(host) = u.host_str() {
                return Ok(Self(host.to_owned()));
            }
            return Err(Error::Internal("URL has no host component"));
        }

        // Fall back: treat as a bare hostname. Reject anything that
        // contains characters a hostname cannot legitimately have
        // (whitespace, `@` for userinfo, `:` for ports, `/` for paths)
        // rather than silently mangling them as the v1 implementation
        // did.
        if trimmed
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '@' | ':' | '/' | '?' | '#'))
        {
            return Err(Error::Internal(
                "RP ID is not a bare hostname (contains scheme/port/path/userinfo)",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------- Helpers ------------------------------------------------------

/// Decode a base64url-no-pad string the way the WebAuthn spec demands,
/// with permissive fallbacks for client serializers that emit:
///   - base64url WITH padding (some JSON helpers add `=`)
///   - standard base64 (`+`/`/` alphabet) with or without padding -
///     common when client JS uses `btoa(String.fromCharCode(...))`
///
/// We try strict url-safe-no-pad first (spec), then progressively
/// looser variants. All four alphabets are checked before giving up.
///
/// For strict spec-conformant decoding (rejects everything except
/// url-safe-no-pad), see [`b64url_decode_strict`]. Production
/// deployments that control the client JS should prefer the strict
/// form via [`Webauthn::strict_base64`].
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    // 1. spec-compliant: url-safe, no padding
    if let Ok(v) = B64URL.decode(s) {
        return Ok(v);
    }
    // 2. url-safe WITH padding
    if let Ok(v) = B64URL_PAD.decode(s) {
        return Ok(v);
    }
    // 3. standard alphabet, no padding
    if let Ok(v) = B64STD_NO_PAD.decode(s) {
        return Ok(v);
    }
    // 4. standard alphabet, with padding (last-ditch; report this error)
    B64STD.decode(s).map_err(|e| Error::Base64(e.to_string()))
}

/// Strict spec-conformant base64url decode: ONLY accepts the
/// url-safe alphabet with no padding. Any other variant is rejected.
///
/// WebAuthn §6.1 requires this exact encoding. Lenient decoding
/// ([`b64url_decode`]) silently accepts non-conformant client JS,
/// which is convenient during development but hides client-side bugs
/// and broadens the input surface. Strict mode forces the client to
/// emit the right thing.
pub(crate) fn b64url_decode_strict(s: &str) -> Result<Vec<u8>> {
    B64URL.decode(s).map_err(|e| Error::Base64(e.to_string()))
}

// ---------- Wire structs (request bodies) -------------------------------

/// JSON body posted by the client to finish a registration ceremony.
/// Mirrors the browser's `PublicKeyCredential` (registration variant)
/// after the standard "base64url every binary field" transformation
/// callers do in JS before posting.
#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    /// The base64url-encoded raw credential ID.
    pub id: String,
    /// Authenticator-attached transports (USB / NFC / BLE / internal).
    /// Optional; some browsers omit it.
    #[serde(default)]
    pub transports: Vec<String>,
    /// The attestation object (CBOR), base64url-encoded.
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// The clientDataJSON (UTF-8 JSON), base64url-encoded.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// JSON body posted by the client to finish an authentication ceremony.
#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    pub id: String,
    /// Raw authenticator data, base64url-encoded.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Signature over `authenticatorData || SHA-256(clientDataJSON)`,
    /// base64url-encoded.
    pub signature: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// User handle (the opaque user id we registered with). Optional;
    /// only present for discoverable credentials. Currently informational.
    #[serde(rename = "userHandle", default)]
    pub user_handle: Option<String>,
}

// ---------- Challenge JSON for the START side ---------------------------

/// What we send to the browser for `navigator.credentials.create()`.
/// All byte fields are base64url-encoded; the client JS is expected
/// to decode them before passing to the WebAuthn API.
#[derive(Debug, Serialize)]
pub struct RegistrationChallenge {
    pub challenge: String, // base64url
    pub rp: RpInfo,
    pub user: UserInfo,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// Credentials we already have for this user - browser SHOULD
    /// refuse to register a duplicate.
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    pub timeout: u32, // milliseconds
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: &'static str, // "none"
}

#[derive(Debug, Serialize)]
pub struct RpInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String, // base64url
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub kind: &'static str, // "public-key"
    pub alg: i64,
}

#[derive(Debug, Serialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub kind: &'static str, // "public-key"
    pub id: String, // base64url
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuthenticatorSelection {
    /// Pins the ceremony to a particular authenticator class. We set
    /// this to `"platform"` so the browser only offers built-in
    /// authenticators (Touch ID, Windows Hello, Android biometrics) -
    /// roaming/USB hardware keys aren't part of the supported flow.
    #[serde(
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_attachment: Option<&'static str>,
    #[serde(rename = "residentKey", skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<&'static str>,
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str, // "preferred"
}

/// What we send to the browser for `navigator.credentials.get()`.
#[derive(Debug, Serialize)]
pub struct AuthenticationChallenge {
    pub challenge: String, // base64url
    #[serde(rename = "rpId")]
    pub rp_id: String,
    pub timeout: u32,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
}

// ---------- Ceremony state (server-side, opaque to client) --------------

/// Per-ceremony state retained between start_* and finish_*. Caller
/// stores this server-side keyed by however they like (session cookie,
/// user id, in-memory map). Treat as secret-ish: contains the
/// challenge we issued.
///
/// The state carries a `created_at` (Unix seconds, UTC) so callers can
/// reject stale ceremonies without needing their own out-of-band TTL.
/// `finish_*` ALSO enforces a hard ceiling (see
/// `Webauthn::CEREMONY_MAX_AGE_SECS`) so a forgetful caller cannot
/// accept a registration response from yesterday.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    pub challenge: Challenge,
    pub user_id: Vec<u8>,
    /// Unix timestamp (seconds, UTC) when `start_registration` was
    /// called. Stable serialization-friendly form.
    #[serde(default)]
    pub created_at: u64,
}

impl RegistrationState {
    /// `true` if more than `max_age_secs` seconds have elapsed since
    /// the ceremony was started. Cheap helper for callers that want
    /// to evict stale state from their session store proactively;
    /// `finish_registration` ALSO enforces its own ceiling.
    #[must_use]
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        now_secs().saturating_sub(self.created_at) > max_age_secs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub challenge: Challenge,
    /// Credentials the browser was allowed to use, so finish_* can
    /// verify the asserted credential id is one of them.
    pub allow_credentials: Vec<CredentialId>,
    /// Unix timestamp (seconds, UTC) when `start_authentication` was
    /// called.
    #[serde(default)]
    pub created_at: u64,
    /// User handle the caller expects to authenticate. Populated by
    /// [`crate::Webauthn::start_authentication_for_user`] for
    /// username-first flows; left `None` for discoverable-credential
    /// (passwordless) flows where the user is not known until the
    /// response arrives.
    ///
    /// When `Some` AND the assertion response carries a `userHandle`,
    /// `finish_authentication` enforces equality (WebAuthn-3 §7.2 step
    /// 6). `#[serde(default)]` means states persisted by older
    /// versions of the crate deserialize cleanly with `None`.
    #[serde(default)]
    pub user_handle: Option<Vec<u8>>,
}

impl AuthenticationState {
    /// See [`RegistrationState::is_expired`].
    #[must_use]
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        now_secs().saturating_sub(self.created_at) > max_age_secs
    }
}

/// Current Unix time in seconds. Used to stamp ceremony states.
/// Saturates to 0 if the system clock is before the Unix epoch (which
/// will never happen on a sane host) so the helpers never panic.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- Outcomes ----------------------------------------------------

/// Stored after a successful registration. The caller persists this
/// (one row per credential per user) and looks it up at auth time.
///
/// `Serialize + Deserialize` are derived so callers can stash the
/// whole credential in a single column (e.g. a JSONB blob or a
/// `SecretString`-wrapped JSON string) without writing a wrapper struct.
/// The wire shape is the natural serde-of-struct mapping; field-level
/// derives on `CredentialId` and `CosePublicKey` produce base64-ish
/// transparent byte vecs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: CredentialId,
    pub public_key_cose: CosePublicKey,
    pub counter: u32,
    pub transports: Vec<String>,
    /// Authenticator AAGUID, as carried in attestedCredentialData.
    ///
    /// Informational only - this crate does NOT validate it against
    /// the FIDO Metadata Service or any allow/deny list. Callers who
    /// want authenticator-attestation policy (e.g. "reject Yubikeys
    /// older than firmware 5.2") must implement that check themselves
    /// using this field. With attestation "none" (our default), the
    /// AAGUID is all zeros anyway; meaningful values only appear when
    /// the client opts into a non-"none" attestation format.
    pub aaguid: [u8; 16],
}

/// Successful authentication outcome. Caller updates the stored
/// credential's `counter` to `new_counter` before responding.
///
/// `Serialize + Deserialize` are derived for symmetry with
/// [`PasskeyCredential`] — useful when an outer service wants to log
/// or forward the outcome as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSuccess {
    pub credential_id: CredentialId,
    pub new_counter: u32,
    pub user_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 5 bytes → 7 base64 chars + 1 pad char. Length is chosen so the
    /// padded variants actually carry a trailing `=`. The byte values
    /// include 0xFB which encodes to `+`/`-` (last alphabet slot) and
    /// 0xFF which encodes to `/`/`_`, so any alphabet confusion in the
    /// decoder surfaces here.
    const SAMPLE: &[u8] = &[0xFB, 0xEF, 0xBE, 0xFF, 0xCC];

    #[test]
    fn decodes_url_safe_no_pad() {
        // base64url-no-pad of SAMPLE
        let encoded = B64URL.encode(SAMPLE);
        assert_eq!(b64url_decode(&encoded).unwrap(), SAMPLE);
    }

    #[test]
    fn decodes_url_safe_with_pad() {
        let encoded = B64URL_PAD.encode(SAMPLE);
        assert!(encoded.ends_with('=')); // sanity
        assert_eq!(b64url_decode(&encoded).unwrap(), SAMPLE);
    }

    #[test]
    fn decodes_standard_no_pad() {
        let encoded = B64STD_NO_PAD.encode(SAMPLE);
        assert_eq!(b64url_decode(&encoded).unwrap(), SAMPLE);
    }

    #[test]
    fn decodes_standard_with_pad() {
        // The killer case: standard alphabet with padding, exactly
        // what `btoa(String.fromCharCode(...new Uint8Array(buf)))`
        // produces in browser JS.
        let encoded = B64STD.encode(SAMPLE);
        assert_eq!(b64url_decode(&encoded).unwrap(), SAMPLE);
    }

    #[test]
    fn rejects_garbage() {
        assert!(b64url_decode("!!!not-base64!!!").is_err());
    }

    // ---- RpId ----------------------------------------------------------

    #[test]
    fn rpid_new_stores_verbatim() {
        assert_eq!(RpId::new("example.com").as_str(), "example.com");
        // No magic stripping any more.
        assert_eq!(RpId::new("sub.example.com").as_str(), "sub.example.com");
    }

    #[test]
    fn rpid_try_from_url_bare_domain() {
        assert_eq!(
            RpId::try_from_url("example.com").unwrap().as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_https_origin() {
        assert_eq!(
            RpId::try_from_url("https://example.com").unwrap().as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_with_port_and_path() {
        assert_eq!(
            RpId::try_from_url("https://example.com:8443/auth/start")
                .unwrap()
                .as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_rejects_userinfo_in_bare() {
        // "user:pass@host" looks like a hostname but isn't one. The v1
        // implementation silently truncated to "user" - we reject.
        assert!(RpId::try_from_url("user:pass@example.com").is_err());
    }

    #[test]
    fn rpid_try_from_url_rejects_empty() {
        assert!(RpId::try_from_url("").is_err());
        assert!(RpId::try_from_url("   ").is_err());
    }

    // ── PasskeyCredential serde round-trip ────────────────────────────────
    // Callers persist a `PasskeyCredential` as a single JSON blob (e.g. a
    // SecretString-wrapped column on a `passkeys` row). The two tests
    // below pin the wire shape so a future field addition can't silently
    // break that storage contract.

    fn fixture_credential() -> PasskeyCredential {
        PasskeyCredential {
            id: CredentialId(vec![0x01, 0x02, 0x03, 0x04]),
            public_key_cose: CosePublicKey(vec![0xAA, 0xBB, 0xCC]),
            counter: 7,
            transports: vec!["usb".into(), "nfc".into()],
            aaguid: [0xFE; 16],
        }
    }

    #[test]
    fn passkey_credential_json_round_trips() {
        let original = fixture_credential();
        let wire = serde_json::to_string(&original).expect("serialise");
        let back: PasskeyCredential = serde_json::from_str(&wire).expect("deserialise");
        assert_eq!(back.id.0, original.id.0);
        assert_eq!(back.public_key_cose.0, original.public_key_cose.0);
        assert_eq!(back.counter, original.counter);
        assert_eq!(back.transports, original.transports);
        assert_eq!(back.aaguid, original.aaguid);
    }

    #[test]
    fn auth_success_json_round_trips() {
        let original = AuthSuccess {
            credential_id: CredentialId(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            new_counter: 42,
            user_verified: true,
        };
        let wire = serde_json::to_string(&original).expect("serialise");
        let back: AuthSuccess = serde_json::from_str(&wire).expect("deserialise");
        assert_eq!(back.credential_id.0, original.credential_id.0);
        assert_eq!(back.new_counter, original.new_counter);
        assert_eq!(back.user_verified, original.user_verified);
    }
}
