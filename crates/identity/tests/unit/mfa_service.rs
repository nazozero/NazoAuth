use std::sync::Mutex;

use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::{
    AccountIdentity, Principal, TenantContext, UserId, UserProfile, UserRole,
    ports::{BackupCodeCandidate, MfaHashFuture, RepositoryFuture, TotpEnrollment},
};

struct ConfirmRepository(Mutex<TotpVerificationOutcome>);

impl MfaRepositoryPort for ConfirmRepository {
    fn totp_enrollment<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpEnrollment>> {
        unreachable!()
    }

    fn begin_totp_enrollment(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _secret: String,
    ) -> RepositoryFuture<'_, ()> {
        unreachable!()
    }

    fn verify_and_confirm_totp<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _code: &'a str,
        _timestamp: i64,
        _hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        let outcome = *self.0.lock().unwrap();
        Box::pin(async move { Ok(outcome) })
    }

    fn record_invalid_totp_attempt(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        unreachable!()
    }

    fn verify_and_consume_totp<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _code: &'a str,
        _timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        unreachable!()
    }

    fn backup_code_candidates(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>> {
        unreachable!()
    }

    fn consume_backup_code_candidate(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _candidate_id: Uuid,
    ) -> RepositoryFuture<'_, Option<Uuid>> {
        unreachable!()
    }

    fn record_invalid_backup_code_attempt(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        unreachable!()
    }

    fn replace_backup_code_hashes<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _credential_id: Uuid,
        _hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, bool> {
        unreachable!()
    }

    fn clear_mfa_state_if_current<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        credential_id: Uuid,
    ) -> RepositoryFuture<'a, bool> {
        let current = *self.0.lock().unwrap();
        Box::pin(async move { Ok(current == TotpVerificationOutcome::Accepted(credential_id)) })
    }

    fn clear_mfa_state_if_current_with_required_audit<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        user_id: UserId,
        credential_id: Uuid,
        source_ip_hash: String,
    ) -> RepositoryFuture<'a, bool> {
        assert_eq!(source_ip_hash, "fixture-source-hash");
        self.clear_mfa_state_if_current(tenant_id, user_id, credential_id)
    }

    fn remember_device(
        &self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        _credential_id: Uuid,
        _token_hash: String,
        _user_agent_hash: Option<String>,
        _expires_at: DateTime<Utc>,
    ) -> RepositoryFuture<'_, bool> {
        unreachable!()
    }
}

struct UnusedHasher;

impl MfaSecretHashPort for UnusedHasher {
    fn hash_secrets(&self, _secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>> {
        unreachable!()
    }

    fn find_matching_secret(
        &self,
        _secret: String,
        _candidates: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>> {
        unreachable!()
    }
}

#[tokio::test]
async fn failed_or_replayed_confirmation_cannot_return_backup_code_secrets() {
    for expected in [
        TotpConfirmationOutcome::Invalid,
        TotpConfirmationOutcome::Replay,
    ] {
        let outcome = match &expected {
            TotpConfirmationOutcome::Invalid => TotpVerificationOutcome::Invalid,
            TotpConfirmationOutcome::Replay => TotpVerificationOutcome::Replay,
            TotpConfirmationOutcome::Accepted { .. } => unreachable!(),
        };
        let service = MfaService::new(
            Arc::new(ConfirmRepository(Mutex::new(outcome))),
            Arc::new(UnusedHasher),
        );
        let result = service
            .confirm_totp(
                &account(),
                PreparedTotpConfirmation {
                    code: "123456".to_owned(),
                    backup_codes: vec!["must-not-escape".to_owned()],
                    hashes: vec![EncodedSecretHash::new("encoded").unwrap()],
                },
                1_000,
            )
            .await
            .unwrap();
        assert_eq!(result, expected);
    }
}

fn account() -> PublicAccount {
    let now = Utc::now();
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::now_v7()).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "user".to_owned(),
            email: "user@example.com".to_owned(),
            email_verified: true,
            mfa_enabled: true,
        },
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn disable_reuses_verified_generation_without_consuming_another_factor() {
    let current = Uuid::now_v7();
    let service = MfaService::new(
        Arc::new(ConfirmRepository(Mutex::new(
            TotpVerificationOutcome::Accepted(current),
        ))),
        Arc::new(UnusedHasher),
    );
    for method in [
        MfaVerificationMethod::Totp,
        MfaVerificationMethod::BackupCode,
    ] {
        let stale = MfaVerificationProof {
            method,
            credential_id: Uuid::now_v7(),
        };
        assert_eq!(
            service
                .disable(&account(), &stale, "fixture-source-hash".to_owned())
                .await
                .unwrap_err()
                .kind(),
            MfaServiceErrorKind::InvalidCode,
        );
        service
            .disable(
                &account(),
                &MfaVerificationProof {
                    method,
                    credential_id: current,
                },
                "fixture-source-hash".to_owned(),
            )
            .await
            .expect("the current generation can be cleared with either consumed factor");
    }
}

#[tokio::test]
async fn required_confirmation_has_no_bare_repository_fallback_or_backup_code_disclosure() {
    let service = MfaService::new(
        Arc::new(ConfirmRepository(Mutex::new(
            TotpVerificationOutcome::Accepted(Uuid::now_v7()),
        ))),
        Arc::new(UnusedHasher),
    );
    let prepared = PreparedTotpConfirmation {
        code: "fixture".to_owned(),
        backup_codes: vec!["must-remain-undisclosed".to_owned()],
        hashes: Vec::new(),
    };
    let error = service
        .confirm_totp_with_required_audit(&account(), prepared, 0, "fixture-source-hash".to_owned())
        .await
        .unwrap_err();
    assert_eq!(
        error.repository_error(),
        Some(&RepositoryError::Unavailable)
    );
}
