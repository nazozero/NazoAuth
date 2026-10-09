use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Versioned authentication and claim contract carried by a refresh family.
///
/// OIDC Core 12.2 preserves the original issuer, subject, audience and
/// authentication time. NazoAuth also preserves its original claim contract.
/// This context contains only original authentication facts. The current
/// ID-token session identifier belongs to the refresh generation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RefreshTokenAuthenticationContext {
    pub version: u16,
    pub issuer: String,
    pub audience: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub oidc_sid: Option<String>,

    pub acr: Option<String>,

    #[serde(flatten)]
    pub userinfo_claim_requests: crate::UserinfoClaimRequests,
    #[serde(flatten)]
    pub id_token_claim_requests: crate::IdTokenClaimRequests,
}

impl RefreshTokenAuthenticationContext {
    /// Version 2 encodes each authorized claim exactly once. Version 1 is read-only legacy.
    pub const CURRENT_VERSION: u16 = 2;

    #[must_use]
    pub const fn is_supported_version(&self) -> bool {
        matches!(self.version, 1 | Self::CURRENT_VERSION)
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
            && self.acr.as_deref().is_none_or(|acr| !acr.trim().is_empty())
    }
}

/// The immutable authorization contract shared by every refresh generation.
/// The adapter owns its storage representation and stable reference. Neither
/// the initial authorization nonce nor a current-generation SID belongs here.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RefreshContract {
    pub subject: String,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    #[serde(default)]
    pub authorization_details: Value,
    pub authentication_context: RefreshTokenAuthenticationContext,
}

/// Maximum simultaneously active refresh families per
/// `(tenant_id, user_id, client_id)` scope. Reaching the cap retires the
/// deterministically oldest family inside the same authority mutation; the
/// limit bounds independent long-lived grants, never rotation generations.
pub const MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE: i64 = 10;

/// Maximum spent proofs for authenticated confidential clients or families
/// protected by a persisted DPoP/mTLS sender constraint. This is a bounded
/// additional reuse signal, not a complete history guarantee.
pub const MAX_SPENT_PROOFS_PER_REFRESH_FAMILY: i64 = 64;

/// RFC 9700 section 4.14.2 requires unbound public clients to retain rotation
/// relationships throughout each token's acceptance lifetime. Client type must
/// come from the locked client authority; bindings must come from the locked
/// family, never from a requested AT binding or current client configuration.
/// Unknown unbound client classes conservatively retain all unexpired proofs.
#[must_use]
pub fn refresh_spent_proof_limit(
    client_type: &str,
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> Option<i64> {
    if client_type == "confidential" || dpop_jkt.is_some() || mtls_x5t_s256.is_some() {
        Some(MAX_SPENT_PROOFS_PER_REFRESH_FAMILY)
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RefreshToken {
    /// Current generation ID-token session, separate from original OP authentication.
    pub id_token_sid: Option<String>,
    pub id: Uuid,
    /// BLAKE3 digest of the presented opaque token (binary, never hex).
    pub token_blake3: [u8; 32],
    pub tenant_id: Uuid,
    pub token_family_id: Uuid,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    /// Stable persisted reference. Legacy families may use the migration's
    /// SQL content key; this value is not recomputed when rotating.
    pub contract_key: [u8; 32],
    /// Original grant resources, independent of this member's current audience.
    pub contract_audiences: Vec<String>,
    pub scopes: Vec<String>,
    pub audience: Vec<String>,
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

/// The source facts read before signing and revalidated at the durable commit.
/// The contract is original grant authority; `current_audiences` belongs to
/// the presented generation. Neither is rebuilt from the requested AT audience.
#[derive(Clone, Debug, PartialEq)]
pub struct RefreshTokenAuthority {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub family_id: Uuid,
    pub member_id: Uuid,
    pub token_blake3: [u8; 32],
    pub contract_key: [u8; 32],
    pub contract: RefreshContract,
    pub current_audiences: Vec<String>,
    pub id_token_sid: Option<String>,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub client_attestation_jkt: Option<String>,
}

impl RefreshToken {
    #[must_use]
    pub fn authority(&self) -> RefreshTokenAuthority {
        let authentication_context = self.authentication_context.clone();
        RefreshTokenAuthority {
            tenant_id: self.tenant_id,
            client_id: self.client_id,
            user_id: self.user_id,
            family_id: self.token_family_id,
            member_id: self.id,
            token_blake3: self.token_blake3,
            contract_key: self.contract_key,
            contract: RefreshContract {
                subject: self.subject.clone(),
                scopes: self.scopes.clone(),
                audiences: self.contract_audiences.clone(),
                authorization_details: self.authorization_details.clone(),
                authentication_context,
            },
            current_audiences: self.audience.clone(),
            id_token_sid: self.id_token_sid.clone(),
            dpop_jkt: self.dpop_jkt.clone(),
            mtls_x5t_s256: self.mtls_x5t_s256.clone(),
            client_attestation_jkt: self.client_attestation_jkt.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LostResponseRetry {
    pub original_id: Uuid,
    /// BLAKE3 digest of the spent token originally presented, so the retry can
    /// prove the direct-predecessor edge without carrying the raw token again.
    pub original_blake3: [u8; 32],
    pub retry_started_at: DateTime<Utc>,
}

#[derive(Clone, PartialEq)]
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
    pub audiences: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub id_token_sid: Option<String>,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub client_attestation_jkt: Option<String>,
}

impl std::fmt::Debug for NewRefreshToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NewRefreshToken([REDACTED])")
    }
}

/// The original contract has one owner in either issuance path. A preserved
/// refresh grant still carries its source even though it has no replacement.
// One request-owned commit value, not a collection of variants. Keep its
// authority and replacement inline rather than allocate on every rotation
// solely to equalize enum variant sizes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum RefreshTokenCommit {
    IssueNew {
        token: NewRefreshToken,
        contract: RefreshContract,
    },
    UseExisting {
        authority: RefreshTokenAuthority,
        rotation: Option<NewRefreshToken>,
    },
}

impl RefreshTokenCommit {
    #[must_use]
    pub fn token(&self) -> Option<&NewRefreshToken> {
        match self {
            Self::IssueNew { token, .. } => Some(token),
            Self::UseExisting { rotation, .. } => rotation.as_ref(),
        }
    }

    #[must_use]
    pub fn contract(&self) -> &RefreshContract {
        match self {
            Self::IssueNew { contract, .. } => contract,
            Self::UseExisting { authority, .. } => &authority.contract,
        }
    }

    #[must_use]
    pub fn family_id(&self) -> Uuid {
        match self {
            Self::IssueNew { token, .. } => token.family_id,
            Self::UseExisting { authority, .. } => authority.family_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshTokenPersistResult {
    Inserted,
    InvalidSource,
    RotationConflict,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BackchannelLogoutDelivery {
    pub id: Uuid,
    pub logout_uri: String,
    pub logout_token: String,
    pub attempts: i32,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for BackchannelLogoutDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BackchannelLogoutDelivery([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PendingBackchannelLogoutDelivery {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub client_public_id: String,
    pub logout_uri: String,
    pub logout_token: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for PendingBackchannelLogoutDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PendingBackchannelLogoutDelivery([REDACTED])")
    }
}

#[cfg(test)]
#[path = "../tests/unit/token.rs"]
mod tests;
