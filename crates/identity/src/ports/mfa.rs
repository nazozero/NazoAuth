use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{TenantId, UserId};

use super::common::{EncodedSecretHash, RepositoryError, RepositoryFuture};

pub type MfaHashFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, MfaHashError>> + Send + 'a>>;

#[derive(Clone, Eq, PartialEq)]
pub struct TotpEnrollment {
    pub secret_base32: String,
    pub confirmed: bool,
    pub last_used_step: Option<i64>,
}

impl std::fmt::Debug for TotpEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TotpEnrollment([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpVerificationOutcome {
    Accepted(Uuid),
    Invalid,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCodeCandidate {
    pub id: Uuid,
    pub hash: EncodedSecretHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaHashError {
    Busy,
    Failed,
}

pub trait MfaSecretHashPort: Send + Sync {
    fn hash_secrets(&self, secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>>;

    fn find_matching_secret(
        &self,
        secret: String,
        candidates: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>>;
}

pub trait MfaRepositoryPort: Send + Sync {
    fn totp_enrollment<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpEnrollment>>;

    fn begin_totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: String,
        label: String,
    ) -> RepositoryFuture<'_, ()>;

    fn verify_and_confirm_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome>;

    /// Confirm the pending generation, install its backup hashes and append
    /// canonical `mfa_totp_enabled` in one accepting transaction. Recheck the
    /// current active self principal before ACK; unknown never authorizes codes.
    /// A repository without this capability fails before any mutation.
    fn verify_and_confirm_totp_with_required_audit<'a>(
        &'a self,
        _tenant_id: TenantId,
        _user_id: UserId,
        _code: &'a str,
        _timestamp: i64,
        _hashes: Vec<EncodedSecretHash>,
        _source_ip_hash: String,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn record_invalid_totp_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()>;

    fn verify_and_consume_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome>;

    fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>>;

    fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: Uuid,
    ) -> RepositoryFuture<'_, Option<Uuid>>;

    fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()>;

    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, bool>;

    /// Replace only the proved current generation's backup hashes and append
    /// canonical `mfa_backup_codes_regenerated` in the same accepting commit.
    /// Lock/recheck the active self principal; release codes only after ACK.
    fn replace_backup_code_hashes_with_required_audit<'a>(
        &'a self,
        _tenant_id: TenantId,
        _user_id: UserId,
        _credential_id: Uuid,
        _hashes: Vec<EncodedSecretHash>,
        _source_ip_hash: String,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    /// Clear all MFA state only if the confirmed generation is still current.
    /// A retired proof returns false without modifying any MFA state. Checking
    /// the generation and clearing its dependent state are one atomic effect.
    fn clear_mfa_state_if_current<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
    ) -> RepositoryFuture<'a, bool>;

    /// Disable the exact confirmed generation and persist the complete Required
    /// `mfa_disabled` outcome in the same accepting transaction. A successful
    /// response follows its acknowledgement; unavailable/unknown never implies
    /// a known non-commit. Adapters cannot fall back to the unaudited clear.
    fn clear_mfa_state_if_current_with_required_audit<'a>(
        &'a self,
        _tenant_id: TenantId,
        _user_id: UserId,
        _credential_id: Uuid,
        _source_ip_hash: String,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> RepositoryFuture<'_, bool>;
}
