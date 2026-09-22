use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::OidcClaimRequest;

/// Versioned authentication and claim contract carried by a refresh family.
///
/// OIDC Core 12.2 requires a refreshed ID Token to retain the original
/// authentication context (notably `auth_time`) and the original claim
/// contract. The immutable subset is persisted once per family in
/// `oauth_refresh_contracts`; the per-generation `id_token_sid` rides on the
/// family row because a refresh may emit a fresh ID-token session id.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RefreshTokenAuthenticationContext {
    pub version: u16,
    pub issuer: String,
    pub audience: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub oidc_sid: Option<String>,
    pub id_token_sid: Option<String>,
    pub acr: Option<String>,
    /// The original authorization nonce. It is consumed by the first ID Token
    /// only: OIDC Core 12.2 says a refreshed ID Token SHOULD omit it, and no
    /// refresh-time reader exists, so persistence strips it (the audit ledger
    /// is the durable record of the authorization request).
    pub nonce: Option<String>,
    pub userinfo_claims: Vec<String>,
    pub userinfo_claim_requests: Vec<OidcClaimRequest>,
    pub id_token_claims: Vec<String>,
    pub id_token_claim_requests: Vec<OidcClaimRequest>,
}

impl RefreshTokenAuthenticationContext {
    pub const CURRENT_VERSION: u16 = 1;

    #[must_use]
    pub const fn is_supported_version(&self) -> bool {
        self.version == Self::CURRENT_VERSION
    }

    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.is_supported_version()
            && !self.issuer.trim().is_empty()
            && !self.audience.trim().is_empty()
            && self.auth_time > 0
            && !self.amr.is_empty()
            && self.amr.iter().all(|method| !method.trim().is_empty())
            && self
                .oidc_sid
                .as_deref()
                .is_none_or(|sid| !sid.trim().is_empty())
            && self
                .id_token_sid
                .as_deref()
                .is_none_or(|sid| !sid.trim().is_empty())
            && self.acr.as_deref().is_none_or(|acr| !acr.trim().is_empty())
    }
}

/// The immutable authorization contract shared by every generation of a
/// refresh family. Serialized canonically (struct field order plus
/// `serde_json`'s sorted map keys) and content-addressed by BLAKE3 so equal
/// contracts share one `oauth_refresh_contracts` row.
///
/// `nonce` and `id_token_sid` are deliberately absent from the persisted
/// context: no refresh-time reader consumes the nonce, and the ID-token
/// session id is per-generation family state.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RefreshContract {
    pub subject: String,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub authorization_details: Value,
    pub authentication_context: RefreshTokenAuthenticationContext,
}

impl RefreshContract {
    /// Canonical serialization feeding both the stored JSONB payload and the
    /// content digest. `serde_json::to_vec` emits struct fields in declaration
    /// order and object keys sorted (BTreeMap-backed `Map`), so the encoding is
    /// deterministic for equal content.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("refresh contract serialization is infallible")
    }

    /// 32-byte BLAKE3 content digest stored as `BYTEA` (never hex).
    #[must_use]
    pub fn blake3_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// The persisted payload: a clone whose per-generation fields are cleared
    /// so content addressing cannot diverge from the family-level authority.
    #[must_use]
    pub fn persisted(&self) -> Self {
        let mut persisted = self.clone();
        persisted.authentication_context.nonce = None;
        persisted.authentication_context.id_token_sid = None;
        persisted
    }
}

/// Maximum simultaneously active refresh families per
/// `(tenant_id, user_id, client_id)` scope. Reaching the cap retires the
/// deterministically oldest family inside the same authority mutation; the
/// limit bounds independent long-lived grants, never rotation generations.
pub const MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE: i64 = 10;

/// Maximum spent proofs retained per refresh family. Each rotation keeps the
/// newest proofs for lost-response edge recovery and replay detection, then
/// trims the tail, so spent state is bounded by
/// `live families × MAX_SPENT_PROOFS_PER_REFRESH_FAMILY` rather than by
/// family age or total rotations. A token replayed from beyond the retained
/// window resolves as an unknown grant — still fail-closed, though without
/// the compromise escalation the retained window provides.
pub const MAX_SPENT_PROOFS_PER_REFRESH_FAMILY: i64 = 64;

#[derive(Clone, Debug, PartialEq)]
pub struct RefreshToken {
    pub id: Uuid,
    /// BLAKE3 digest of the presented opaque token (binary, never hex).
    pub token_blake3: [u8; 32],
    pub tenant_id: Uuid,
    pub token_family_id: Uuid,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scopes: Value,
    pub audience: Value,
    pub authorization_details: Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub subject: String,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub client_attestation_jkt: Option<String>,
    pub authentication_context: RefreshTokenAuthenticationContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LostResponseRetry {
    pub original_id: Uuid,
    /// BLAKE3 digest of the spent token originally presented, so the retry can
    /// prove the direct-predecessor edge without carrying the raw token again.
    pub original_blake3: [u8; 32],
    pub retry_started_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewRefreshToken {
    pub raw_token: String,
    /// Identity of this generation. Assigned by issuance so the parent
    /// generation's spent proof can name its direct successor.
    pub member_id: Uuid,
    pub tenant_id: Uuid,
    pub family_id: Uuid,
    pub rotated_from_id: Option<Uuid>,
    pub lost_response_retry: Option<LostResponseRetry>,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub authorization_details: Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub subject: String,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub client_attestation_jkt: Option<String>,
    pub authentication_context: RefreshTokenAuthenticationContext,
}

impl NewRefreshToken {
    /// The immutable contract this generation shares with its family.
    #[must_use]
    pub fn contract(&self) -> RefreshContract {
        RefreshContract {
            subject: self.subject.clone(),
            scopes: self.scopes.clone(),
            audiences: self.audiences.clone(),
            authorization_details: self.authorization_details.clone(),
            authentication_context: self.authentication_context.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshTokenPersistResult {
    Inserted,
    RotationConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackchannelLogoutDelivery {
    pub id: Uuid,
    pub logout_uri: String,
    pub logout_token: String,
    pub attempts: i32,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBackchannelLogoutDelivery {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub client_public_id: String,
    pub logout_uri: String,
    pub logout_token: String,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
#[path = "../tests/unit/token.rs"]
mod tests;
