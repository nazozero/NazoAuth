//! Actual MFA service/PG interleavings. Fixtures use formal confirmation,
//! production TOTP/backup verification and encryption, never confirmed_at SQL.

use super::*;
use diesel_async::SimpleAsyncConnection;
use futures_util::FutureExt as _;
use nazo_identity::ports::{MfaHashError, MfaHashFuture, MfaSecretHashPort};
use nazo_identity::{MfaService, MfaServiceErrorKind, PublicAccount, TotpConfirmationOutcome};
use std::{sync::Arc, time::Duration};

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const STEP: i64 = 56_666_666;

// Uses the production cryptographic API with inexpensive fixture parameters;
// it does not reimplement normalization, TOTP, generation or verification policy.
struct FixtureHasher;
impl MfaSecretHashPort for FixtureHasher {
    fn hash_secrets(&self, secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>> {
        Box::pin(async move {
            secrets
                .into_iter()
                .map(|secret| {
                    let hash = nazo_crypto::password::hash_argon2id(secret.as_bytes(), 64, 1, 1)
                        .map_err(|_| MfaHashError::Failed)?;
                    EncodedSecretHash::new(hash).map_err(|_| MfaHashError::Failed)
                })
                .collect()
        })
    }

    fn find_matching_secret(
        &self,
        secret: String,
        candidates: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>> {
        Box::pin(async move {
            Ok(candidates.iter().position(|hash| {
                nazo_crypto::password::verify_argon2_phc(hash.as_str(), secret.as_bytes())
            }))
        })
    }
}

fn service(repository: &MfaRepository) -> MfaService {
    MfaService::new(Arc::new(repository.clone()), Arc::new(FixtureHasher))
}

async fn account(
    pool: &nazo_postgres::DbPool,
    tenant: TenantContext,
    user: UserId,
) -> PublicAccount {
    UserRepository::new(pool.clone())
        .public_account_by_id(tenant.tenant_id, user)
        .await
        .unwrap()
        .unwrap()
}

fn totp(step: i64) -> String {
    nazo_identity::mfa::totp_for_step(b"12345678901234567890", step).unwrap()
}

#[derive(QueryableByName)]
struct Snapshot {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

async fn snapshot(
    pool: &nazo_postgres::DbPool,
    tenant: TenantContext,
    user: UserId,
) -> serde_json::Value {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query("SELECT jsonb_build_object( \
        'credential',(SELECT to_jsonb(t) FROM user_totp_credentials t WHERE tenant_id=$1 AND user_id=$2), \
        'enabled',(SELECT mfa_enabled FROM users WHERE tenant_id=$1 AND id=$2), \
        'backups',(SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY id),'[]'::jsonb) FROM user_mfa_backup_codes b WHERE tenant_id=$1 AND user_id=$2), \
        'remembered',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM user_mfa_remembered_devices d WHERE tenant_id=$1 AND user_id=$2)) AS value")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user.as_uuid())
        .get_result::<Snapshot>(&mut connection).await.unwrap().value
}

async fn install_generation(
    pool: &nazo_postgres::DbPool,
    repository: &MfaRepository,
    tenant: TenantContext,
    user: UserId,
    step: i64,
) -> (Uuid, String) {
    repository
        .begin_totp_enrollment(
            tenant.tenant_id,
            user,
            SECRET.to_owned(),
            "formal fixture".to_owned(),
        )
        .await
        .unwrap();
    let account = account(pool, tenant, user).await;
    let service = service(repository);
    let code = totp(step);
    let now = step * nazo_identity::mfa::MFA_TOTP_PERIOD_SECONDS;
    let prepared = service
        .prepare_totp_confirmation(&account, &code, now)
        .await
        .unwrap();
    let TotpConfirmationOutcome::Accepted { backup_codes } =
        service.confirm_totp(&account, prepared, now).await.unwrap()
    else {
        panic!("formal confirmation must install a credential and backups");
    };
    let installed = snapshot(pool, tenant, user).await;
    assert_eq!(installed["enabled"], true);
    assert!(!installed["credential"]["confirmed_at"].is_null());
    assert_eq!(installed["credential"]["secret_key_id"], "test-current");
    assert!(!installed["credential"]["secret_ciphertext"].is_null());
    assert_eq!(installed["credential"]["last_used_step"], step);
    assert_eq!(
        installed["backups"].as_array().unwrap().len(),
        nazo_identity::mfa::MFA_BACKUP_CODE_COUNT
    );
    (
        Uuid::parse_str(installed["credential"]["id"].as_str().unwrap()).unwrap(),
        backup_codes[0].clone(),
    )
}

async fn remember(
    repository: &MfaRepository,
    tenant: TenantContext,
    user: UserId,
    generation: Uuid,
) {
    assert!(
        repository
            .remember_device(
                tenant.tenant_id,
                user,
                generation,
                blake3::hash(generation.as_bytes()).to_hex().to_string(),
                None,
                chrono::Utc::now() + chrono::Duration::hours(1)
            )
            .await
            .unwrap()
    );
}

async fn assert_full_generation(
    pool: &nazo_postgres::DbPool,
    repository: &MfaRepository,
    tenant: TenantContext,
    user: UserId,
    generation: Uuid,
) -> serde_json::Value {
    let actual = snapshot(pool, tenant, user).await;
    assert_eq!(actual["credential"]["id"], generation.to_string());
    assert_eq!(actual["enabled"], true);
    assert_eq!(
        actual["backups"].as_array().unwrap().len(),
        nazo_identity::mfa::MFA_BACKUP_CODE_COUNT
    );
    assert_eq!(actual["remembered"].as_array().unwrap().len(), 1);
    assert!(account(pool, tenant, user).await.account.mfa_enabled);
    assert!(
        repository
            .remembered_device_valid(
                tenant.tenant_id,
                user,
                blake3::hash(generation.as_bytes()).to_hex().as_ref(),
                None,
                chrono::Utc::now()
            )
            .await
            .unwrap()
    );
    actual
}

#[tokio::test]
async fn mfa_verified_g1_disable_preserves_fully_installed_g2_after_barrier() {
    let Some((pool, tenant, user)) = database_fixture().await else {
        return;
    };
    let repository = mfa_repository(pool.clone());
    for backup_factor in [false, true] {
        let (g1, backup) = install_generation(&pool, &repository, tenant, user, STEP).await;
        let admitted_account = account(&pool, tenant, user).await;
        let a_service = service(&repository);
        let a_account = admitted_account.clone();
        let (verified_tx, verified_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let factor = if backup_factor {
            backup
        } else {
            totp(STEP + 1)
        };
        let mut a = tokio::spawn(async move {
            let proof = a_service
                .verify_factor(&a_account, &factor, (STEP + 1) * 30)
                .await
                .unwrap()
                .unwrap();
            verified_tx.send(proof).unwrap();
            resume_rx.await.unwrap();
            a_service
                .disable(&a_account, &proof, "fixture-source-hash".to_owned())
                .await
        });
        let body = std::panic::AssertUnwindSafe(async {
            let old_proof = tokio::time::timeout(Duration::from_secs(5), verified_rx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                old_proof.method(),
                if backup_factor {
                    nazo_identity::mfa::MfaVerificationMethod::BackupCode
                } else {
                    nazo_identity::mfa::MfaVerificationMethod::Totp
                }
            );
            assert_eq!(
                snapshot(&pool, tenant, user).await["credential"]["id"],
                g1.to_string()
            );
            // B independently authenticates using the current generation.
            let b_service = service(&repository);
            let b_proof = b_service
                .verify_factor(&admitted_account, &totp(STEP + 2), (STEP + 2) * 30)
                .await
                .unwrap()
                .unwrap();
            b_service
                .disable(
                    &admitted_account,
                    &b_proof,
                    "fixture-source-hash".to_owned(),
                )
                .await
                .unwrap();
            let (g2, _) = install_generation(&pool, &repository, tenant, user, STEP + 3).await;
            assert_ne!(g1, g2);
            remember(&repository, tenant, user, g2).await;
            let before = assert_full_generation(&pool, &repository, tenant, user, g2).await;
            resume_tx.send(()).unwrap();
            let error = tokio::time::timeout(Duration::from_secs(5), &mut a)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), MfaServiceErrorKind::InvalidCode);
            assert_eq!(snapshot(&pool, tenant, user).await, before);
            assert_eq!(
                b_service
                    .disable(
                        &admitted_account,
                        &old_proof,
                        "fixture-source-hash".to_owned()
                    )
                    .await
                    .unwrap_err()
                    .kind(),
                MfaServiceErrorKind::InvalidCode
            );
            assert_eq!(
                assert_full_generation(&pool, &repository, tenant, user, g2).await,
                before
            );
            assert!(
                repository
                    .clear_mfa_state_if_current(tenant.tenant_id, user, g2)
                    .await
                    .unwrap()
            );
        })
        .catch_unwind()
        .await;
        if !a.is_finished() {
            a.abort();
            let _ = tokio::time::timeout(Duration::from_secs(1), &mut a).await;
        }
        if let Err(error) = body {
            cleanup(&pool, user).await;
            std::panic::resume_unwind(error);
        }
    }
    cleanup(&pool, user).await;
}

#[derive(QueryableByName)]
struct Pid {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pid: i32,
}

async fn wait_clear_pid(pool: &nazo_postgres::DbPool, key: i64) -> i32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut connection = get_conn(pool).await.unwrap();
            let row = sql_query("SELECT COALESCE((SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=$1::oid AND NOT granted LIMIT 1),0)::integer AS pid")
                .bind::<diesel::sql_types::BigInt, _>(key).get_result::<Pid>(&mut connection).await.unwrap();
            if row.pid != 0 { return row.pid; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("clear reached the backup-delete barrier while owning G1's lock")
}

#[tokio::test]
async fn mfa_clear_generation_lock_orders_formal_g2_install_after_commit() {
    let Some((pool, tenant, user)) = database_fixture().await else {
        return;
    };
    let repository = mfa_repository(pool.clone());
    let (g1, _) = install_generation(&pool, &repository, tenant, user, STEP).await;
    remember(&repository, tenant, user, g1).await;
    let admitted = account(&pool, tenant, user).await;
    let service = service(&repository);
    let proof = service
        .verify_factor(&admitted, &totp(STEP + 1), (STEP + 1) * 30)
        .await
        .unwrap()
        .unwrap();
    let name = format!("mfa_clear_barrier_{}", Uuid::now_v7().simple());
    let key = i64::from(rand::random::<u32>() & 0x7fff_ffff);
    let mut blocker = get_conn(&pool).await.unwrap();
    blocker.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN OLD; END $$; CREATE TRIGGER {name} BEFORE DELETE ON user_mfa_backup_codes FOR EACH ROW WHEN (OLD.user_id='{}'::uuid) EXECUTE FUNCTION {name}();", user.as_uuid())).await.unwrap();
    // Commit the trigger before opening the blocker transaction so the
    // independent clear connection can see it and rollback cannot remove it.
    blocker
        .batch_execute(&format!("BEGIN; SELECT pg_advisory_xact_lock({key});"))
        .await
        .unwrap();
    let clear_service = service.clone();
    let clear_account = admitted.clone();
    let mut clear = tokio::spawn(async move {
        clear_service
            .disable(&clear_account, &proof, "fixture-source-hash".to_owned())
            .await
    });
    let mut install = None;
    let body = std::panic::AssertUnwindSafe(async {
        let clear_pid = wait_clear_pid(&pool, key).await;
        let g2_pool = pool.clone();
        let g2_repository = repository.clone();
        install = Some(tokio::spawn(async move { install_generation(&g2_pool, &g2_repository, tenant, user, STEP + 3).await }));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut connection = get_conn(&pool).await.unwrap();
                let row = sql_query("SELECT COALESCE((SELECT pid FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%user_totp_credentials%' AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1),0)::integer AS pid")
                    .bind::<diesel::sql_types::Integer, _>(clear_pid).get_result::<Pid>(&mut connection).await.unwrap();
                if row.pid != 0 { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("formal G2 enrollment waits for the production clear generation lock");
        assert!(!install.as_ref().unwrap().is_finished());
        blocker.batch_execute("COMMIT").await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut clear).await.unwrap().unwrap().unwrap();
        let (g2, _) = tokio::time::timeout(Duration::from_secs(5), install.as_mut().unwrap()).await.unwrap().unwrap();
        assert_ne!(g1, g2);
        remember(&repository, tenant, user, g2).await;
        let before = assert_full_generation(&pool, &repository, tenant, user, g2).await;
        assert_eq!(service.disable(&admitted, &proof, "fixture-source-hash".to_owned()).await.unwrap_err().kind(), MfaServiceErrorKind::InvalidCode);
        assert_eq!(assert_full_generation(&pool, &repository, tenant, user, g2).await, before);
    }).catch_unwind().await;
    let _ = blocker.batch_execute("ROLLBACK").await;
    if !clear.is_finished() {
        clear.abort();
        let _ = tokio::time::timeout(Duration::from_secs(1), &mut clear).await;
    }
    if let Some(handle) = install.as_mut()
        && !handle.is_finished()
    {
        handle.abort();
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
    }
    let fixture_cleanup = blocker
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON user_mfa_backup_codes; DROP FUNCTION {name}();"
        ))
        .await;
    drop(blocker);
    cleanup(&pool, user).await;
    if let Err(error) = body {
        std::panic::resume_unwind(error);
    }
    fixture_cleanup.expect("owned barrier trigger and function are removed");
}

#[tokio::test]
async fn mfa_clear_failure_after_dependent_deletes_rolls_back_every_generation_field() {
    let Some((pool, tenant, user)) = database_fixture().await else {
        return;
    };
    let repository = mfa_repository(pool.clone());
    let (generation, _) = install_generation(&pool, &repository, tenant, user, STEP).await;
    remember(&repository, tenant, user, generation).await;
    let admitted = account(&pool, tenant, user).await;
    let service = service(&repository);
    let proof = service
        .verify_factor(&admitted, &totp(STEP + 1), (STEP + 1) * 30)
        .await
        .unwrap()
        .unwrap();
    let before = assert_full_generation(&pool, &repository, tenant, user, generation).await;
    let name = format!("mfa_clear_failure_{}", Uuid::now_v7().simple());
    let mut connection = get_conn(&pool).await.unwrap();
    connection.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture clear failure'; END $$; CREATE TRIGGER {name} BEFORE UPDATE ON users FOR EACH ROW WHEN (OLD.id='{}'::uuid AND OLD.mfa_enabled AND NOT NEW.mfa_enabled) EXECUTE FUNCTION {name}();", user.as_uuid())).await.unwrap();
    let body = std::panic::AssertUnwindSafe(async {
        let error = service
            .disable(&admitted, &proof, "fixture-source-hash".to_owned())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), MfaServiceErrorKind::Repository);
        assert_eq!(
            assert_full_generation(&pool, &repository, tenant, user, generation).await,
            before
        );
    })
    .catch_unwind()
    .await;
    connection
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON users; DROP FUNCTION {name}();"
        ))
        .await
        .unwrap();
    drop(connection);
    cleanup(&pool, user).await;
    if let Err(error) = body {
        std::panic::resume_unwind(error);
    }
}

use chrono::{DateTime, Utc};
use nazo_identity::ports::{
    BackupCodeCandidate, RepositoryFuture, TotpEnrollment, TotpVerificationOutcome,
};

struct UnknownMfaCommitAck {
    inner: MfaRepository,
    lose_ack: std::sync::atomic::AtomicBool,
}

impl MfaRepositoryPort for UnknownMfaCommitAck {
    fn totp_enrollment<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpEnrollment>> {
        MfaRepositoryPort::totp_enrollment(&self.inner, tenant_id, user_id)
    }

    fn begin_totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: String,
        label: String,
    ) -> RepositoryFuture<'_, ()> {
        MfaRepositoryPort::begin_totp_enrollment(&self.inner, tenant_id, user_id, secret, label)
    }

    fn verify_and_confirm_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        MfaRepositoryPort::verify_and_confirm_totp(
            &self.inner,
            tenant_id,
            user_id,
            code,
            timestamp,
            hashes,
        )
    }

    fn verify_and_confirm_totp_with_required_audit<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
        source_ip_hash: String,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(async move {
            let outcome = MfaRepositoryPort::verify_and_confirm_totp_with_required_audit(
                &self.inner,
                tenant_id,
                user_id,
                code,
                timestamp,
                hashes,
                source_ip_hash,
            )
            .await?;
            if matches!(outcome, TotpVerificationOutcome::Accepted(_))
                && self
                    .lose_ack
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                Err(RepositoryError::Unavailable)
            } else {
                Ok(outcome)
            }
        })
    }

    fn record_invalid_totp_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        MfaRepositoryPort::record_invalid_totp_attempt(&self.inner, tenant_id, user_id)
    }

    fn verify_and_consume_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        MfaRepositoryPort::verify_and_consume_totp(&self.inner, tenant_id, user_id, code, timestamp)
    }

    fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>> {
        MfaRepositoryPort::backup_code_candidates(&self.inner, tenant_id, user_id)
    }

    fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: Uuid,
    ) -> RepositoryFuture<'_, Option<Uuid>> {
        MfaRepositoryPort::consume_backup_code_candidate(
            &self.inner,
            tenant_id,
            user_id,
            candidate_id,
        )
    }

    fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        MfaRepositoryPort::record_invalid_backup_code_attempt(&self.inner, tenant_id, user_id)
    }

    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, bool> {
        MfaRepositoryPort::replace_backup_code_hashes(
            &self.inner,
            tenant_id,
            user_id,
            credential_id,
            hashes,
        )
    }

    fn replace_backup_code_hashes_with_required_audit<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        hashes: Vec<EncodedSecretHash>,
        source_ip_hash: String,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let replaced = MfaRepositoryPort::replace_backup_code_hashes_with_required_audit(
                &self.inner,
                tenant_id,
                user_id,
                credential_id,
                hashes,
                source_ip_hash,
            )
            .await?;
            if replaced
                && self
                    .lose_ack
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                Err(RepositoryError::Unavailable)
            } else {
                Ok(replaced)
            }
        })
    }

    fn clear_mfa_state_if_current<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let cleared = MfaRepositoryPort::clear_mfa_state_if_current(
                &self.inner,
                tenant_id,
                user_id,
                credential_id,
            )
            .await?;
            if cleared
                && self
                    .lose_ack
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                Err(RepositoryError::Unavailable)
            } else {
                Ok(cleared)
            }
        })
    }

    fn clear_mfa_state_if_current_with_required_audit<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        source_ip_hash: String,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let cleared = MfaRepositoryPort::clear_mfa_state_if_current_with_required_audit(
                &self.inner,
                tenant_id,
                user_id,
                credential_id,
                source_ip_hash,
            )
            .await?;
            if cleared
                && self
                    .lose_ack
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                Err(RepositoryError::Unavailable)
            } else {
                Ok(cleared)
            }
        })
    }

    fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: Uuid,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> RepositoryFuture<'_, bool> {
        MfaRepositoryPort::remember_device(
            &self.inner,
            tenant_id,
            user_id,
            credential_id,
            token_hash,
            user_agent_hash,
            expires_at,
        )
    }
}

#[tokio::test]
async fn mfa_clear_committed_unknown_retry_cannot_clear_formal_g2() {
    let Some((pool, tenant, user)) = database_fixture().await else {
        return;
    };
    let repository = mfa_repository(pool.clone());
    let body = std::panic::AssertUnwindSafe(async {
        for backup_factor in [false, true] {
            let (g1, backup) = install_generation(&pool, &repository, tenant, user, STEP).await;
            remember(&repository, tenant, user, g1).await;
            let admitted = account(&pool, tenant, user).await;
            let factor = if backup_factor {
                backup
            } else {
                totp(STEP + 1)
            };
            let proof = service(&repository)
                .verify_factor(&admitted, &factor, (STEP + 1) * 30)
                .await
                .unwrap()
                .unwrap();
            let lost_ack = MfaService::new(
                Arc::new(UnknownMfaCommitAck {
                    inner: repository.clone(),
                    lose_ack: std::sync::atomic::AtomicBool::new(true),
                }),
                Arc::new(FixtureHasher),
            );
            let error = lost_ack
                .disable(&admitted, &proof, "fixture-source-hash".to_owned())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), MfaServiceErrorKind::Repository);
            assert_eq!(
                error.repository_error(),
                Some(&RepositoryError::Unavailable)
            );
            let ledger = disable_ledger(&pool, tenant, user, g1).await;
            assert_eq!(
                ledger.as_array().unwrap().len(),
                1,
                "the committed unknown effect must retain exactly one canonical outcome"
            );
            assert_eq!(ledger[0]["source_ip_hash"], "fixture-source-hash");
            let cleared = snapshot(&pool, tenant, user).await;
            assert!(cleared["credential"].is_null());
            assert_eq!(cleared["enabled"], false);
            assert_eq!(cleared["backups"], json!([]));
            assert_eq!(cleared["remembered"], json!([]));
            let (g2, _) = install_generation(&pool, &repository, tenant, user, STEP + 3).await;
            assert_ne!(g1, g2);
            remember(&repository, tenant, user, g2).await;
            let before = assert_full_generation(&pool, &repository, tenant, user, g2).await;
            assert_eq!(
                lost_ack
                    .disable(&admitted, &proof, "fixture-source-hash".to_owned())
                    .await
                    .unwrap_err()
                    .kind(),
                MfaServiceErrorKind::InvalidCode
            );
            assert_eq!(
                assert_full_generation(&pool, &repository, tenant, user, g2).await,
                before
            );
            assert_eq!(
                disable_ledger(&pool, tenant, user, g1).await,
                ledger,
                "a retired proof retry cannot append a second success outcome"
            );
            assert!(
                repository
                    .clear_mfa_state_if_current(tenant.tenant_id, user, g2)
                    .await
                    .unwrap()
            );
        }
    })
    .catch_unwind()
    .await;
    cleanup(&pool, user).await;
    if let Err(error) = body {
        std::panic::resume_unwind(error);
    }
}

async fn disable_ledger(
    pool: &nazo_postgres::DbPool,
    tenant: TenantContext,
    user: UserId,
    generation: Uuid,
) -> serde_json::Value {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query("SELECT COALESCE(jsonb_agg(payload ORDER BY event_id),'[]'::jsonb) AS value FROM security_audit_events WHERE event_type='mfa_disabled' AND payload->>'tenant_id'=$1 AND payload->>'user_id'=$2 AND payload->>'credential_id'=$3")
        .bind::<Text, _>(tenant.tenant_id.as_uuid().to_string())
        .bind::<Text, _>(user.as_uuid().to_string())
        .bind::<Text, _>(generation.to_string())
        .get_result::<Snapshot>(&mut connection).await.unwrap().value
}

#[tokio::test]
async fn mfa_disable_required_ledger_failure_rolls_back_current_generation_and_dependents() {
    let Some((pool, tenant, user)) = database_fixture().await else {
        return;
    };
    let repository = mfa_repository(pool.clone());
    let (generation, _) = install_generation(&pool, &repository, tenant, user, STEP).await;
    remember(&repository, tenant, user, generation).await;
    let admitted = account(&pool, tenant, user).await;
    let service = service(&repository);
    let proof = service
        .verify_factor(&admitted, &totp(STEP + 1), (STEP + 1) * 30)
        .await
        .unwrap()
        .unwrap();
    let before = assert_full_generation(&pool, &repository, tenant, user, generation).await;
    let name = format!("mfa_required_failure_{}", Uuid::now_v7().simple());
    let mut connection = get_conn(&pool).await.unwrap();
    connection.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture required ledger failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type='mfa_disabled' AND NEW.payload->>'user_id'='{}' AND NEW.payload->>'credential_id'='{generation}') EXECUTE FUNCTION {name}();", user.as_uuid())).await.unwrap();
    let body = std::panic::AssertUnwindSafe(async {
        let error = service.disable(&admitted, &proof, "fixture-source-hash".to_owned()).await.unwrap_err();
        assert_eq!(error.kind(), MfaServiceErrorKind::Repository);
        assert_eq!(assert_full_generation(&pool, &repository, tenant, user, generation).await, before,
            "ledger append failure rolls back the exact encrypted generation, backup rows, remembered devices and enabled flag");
        assert_eq!(disable_ledger(&pool, tenant, user, generation).await, json!([]));
    }).catch_unwind().await;
    let trigger_cleanup = connection
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();"
        ))
        .await;
    drop(connection);
    if let Err(error) = body {
        cleanup(&pool, user).await;
        std::panic::resume_unwind(error);
    }
    trigger_cleanup.expect("fixture-owned ledger trigger removed");
    // The consumed proof identifies this still-current generation. No second
    // factor is consumed just to retry after a known SQL rollback.
    service
        .disable(&admitted, &proof, "fixture-source-hash".to_owned())
        .await
        .unwrap();
    let after = snapshot(&pool, tenant, user).await;
    assert!(after["credential"].is_null());
    assert_eq!(after["enabled"], false);
    assert_eq!(after["backups"], json!([]));
    assert_eq!(after["remembered"], json!([]));
    let ledger = disable_ledger(&pool, tenant, user, generation).await;
    assert_eq!(ledger.as_array().unwrap().len(), 1);
    assert_eq!(
        ledger[0]["schema_version"],
        nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION
    );
    assert_eq!(ledger[0]["event_category"], "authentication");
    assert_eq!(ledger[0]["outcome"], "success");
    assert_eq!(ledger[0]["source_ip_hash"], "fixture-source-hash");
    assert!(ledger[0].get("secret").is_none());
    cleanup(&pool, user).await;
}

async fn required_mutation_ledger(
    pool: &nazo_postgres::DbPool,
    tenant: TenantContext,
    user: UserId,
    generation: Uuid,
    event: &str,
) -> serde_json::Value {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query(
        "SELECT COALESCE(jsonb_agg(payload ORDER BY event_id),'[]'::jsonb) AS value \
        FROM security_audit_events WHERE event_type=$1 AND payload->>'tenant_id'=$2 \
          AND payload->>'user_id'=$3 AND payload->>'credential_id'=$4",
    )
    .bind::<Text, _>(event)
    .bind::<Text, _>(tenant.tenant_id.as_uuid().to_string())
    .bind::<Text, _>(user.as_uuid().to_string())
    .bind::<Text, _>(generation.to_string())
    .get_result::<Snapshot>(&mut connection)
    .await
    .unwrap()
    .value
}

fn assert_required_mutation(
    event: &serde_json::Value,
    tenant: TenantContext,
    user: UserId,
    generation: Uuid,
) {
    assert_eq!(event.as_array().unwrap().len(), 1);
    assert_eq!(
        event[0]["schema_version"],
        nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION
    );
    assert_eq!(event[0]["event_category"], "authentication");
    assert_eq!(
        event[0]["tenant_id"],
        tenant.tenant_id.as_uuid().to_string()
    );
    assert_eq!(event[0]["actor_id"], user.as_uuid().to_string());
    assert_eq!(event[0]["target_user_id"], user.as_uuid().to_string());
    assert_eq!(event[0]["credential_id"], generation.to_string());
    assert_eq!(event[0]["source_ip_hash"], "fixture-source-hash");
    assert_eq!(event[0]["outcome"], "success");
    for secret in ["secret", "code", "backup_codes", "hashes", "cookie"] {
        assert!(event[0].get(secret).is_none());
    }
}

#[tokio::test]
async fn mfa_confirmation_required_ledger_and_inactive_actor_roll_back_before_code_disclosure() {
    let Some((pool, tenant, user)) = database_fixture().await else {
        return;
    };
    let repository = mfa_repository(pool.clone());
    repository
        .begin_totp_enrollment(
            tenant.tenant_id,
            user,
            SECRET.to_owned(),
            "required fixture".to_owned(),
        )
        .await
        .unwrap();
    let admitted = account(&pool, tenant, user).await;
    let service = service(&repository);
    let before = snapshot(&pool, tenant, user).await;
    let generation = Uuid::parse_str(before["credential"]["id"].as_str().unwrap()).unwrap();
    let name = format!("mfa_confirm_required_failure_{}", Uuid::now_v7().simple());
    let mut connection = get_conn(&pool).await.unwrap();
    connection.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture confirmation ledger failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type='mfa_totp_enabled' AND NEW.payload->>'user_id'='{}') EXECUTE FUNCTION {name}();",user.as_uuid())).await.unwrap();
    let rollback=std::panic::AssertUnwindSafe(async {
        let prepared=service.prepare_totp_confirmation(&admitted,&totp(STEP),STEP*30).await.unwrap();
        let error=service.confirm_totp_with_required_audit(&admitted,prepared,STEP*30,"fixture-source-hash".to_owned()).await.unwrap_err();
        assert_eq!(error.kind(),MfaServiceErrorKind::Repository);
        assert_eq!(snapshot(&pool,tenant,user).await,before,
            "canonical failure rolls back pending ciphertext, confirmation, step, backups and enabled flag");
        assert_eq!(required_mutation_ledger(&pool,tenant,user,generation,"mfa_totp_enabled").await,json!([]));
    }).catch_unwind().await;
    let removed = connection
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();"
        ))
        .await;
    if let Err(panic) = rollback {
        drop(connection);
        cleanup(&pool, user).await;
        std::panic::resume_unwind(panic);
    }
    removed.unwrap();
    let actor_check = std::panic::AssertUnwindSafe(async {
        let prepared = service
            .prepare_totp_confirmation(&admitted, &totp(STEP), STEP * 30)
            .await
            .unwrap();
        sql_query("UPDATE users SET is_active=FALSE WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid, _>(user.as_uuid())
            .execute(&mut connection)
            .await
            .unwrap();
        assert!(
            service
                .confirm_totp_with_required_audit(
                    &admitted,
                    prepared,
                    STEP * 30,
                    "fixture-source-hash".to_owned()
                )
                .await
                .is_err()
        );
        assert_eq!(snapshot(&pool, tenant, user).await, before);
        assert_eq!(
            required_mutation_ledger(&pool, tenant, user, generation, "mfa_totp_enabled").await,
            json!([])
        );
        sql_query("UPDATE users SET is_active=TRUE WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid, _>(user.as_uuid())
            .execute(&mut connection)
            .await
            .unwrap();
        let prepared = service
            .prepare_totp_confirmation(&admitted, &totp(STEP), STEP * 30)
            .await
            .unwrap();
        let TotpConfirmationOutcome::Accepted { backup_codes } = service
            .confirm_totp_with_required_audit(
                &admitted,
                prepared,
                STEP * 30,
                "fixture-source-hash".to_owned(),
            )
            .await
            .unwrap()
        else {
            panic!("active current owner must accept confirmation");
        };
        assert_eq!(
            backup_codes.len(),
            nazo_identity::mfa::MFA_BACKUP_CODE_COUNT
        );
        assert_required_mutation(
            &required_mutation_ledger(&pool, tenant, user, generation, "mfa_totp_enabled").await,
            tenant,
            user,
            generation,
        );
    })
    .catch_unwind()
    .await;
    drop(connection);
    cleanup(&pool, user).await;
    if let Err(panic) = actor_check {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn mfa_regeneration_required_ledger_and_inactive_actor_preserve_exact_old_backups() {
    let Some((pool, tenant, user)) = database_fixture().await else {
        return;
    };
    let repository = mfa_repository(pool.clone());
    let (generation, _) = install_generation(&pool, &repository, tenant, user, STEP).await;
    remember(&repository, tenant, user, generation).await;
    let admitted = account(&pool, tenant, user).await;
    let service = service(&repository);
    let proof = service
        .verify_factor(&admitted, &totp(STEP + 1), (STEP + 1) * 30)
        .await
        .unwrap()
        .unwrap();
    let before = snapshot(&pool, tenant, user).await;
    let name = format!("mfa_regen_required_failure_{}", Uuid::now_v7().simple());
    let mut connection = get_conn(&pool).await.unwrap();
    connection.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture regeneration ledger failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type='mfa_backup_codes_regenerated' AND NEW.payload->>'user_id'='{}') EXECUTE FUNCTION {name}();",user.as_uuid())).await.unwrap();
    let rollback = std::panic::AssertUnwindSafe(async {
        let error = service
            .regenerate_backup_codes_with_required_audit(
                &admitted,
                &proof,
                "fixture-source-hash".to_owned(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), MfaServiceErrorKind::Repository);
        assert_eq!(
            snapshot(&pool, tenant, user).await,
            before,
            "all old backup rows and current generation/dependents survive Required failure"
        );
        assert_eq!(
            required_mutation_ledger(
                &pool,
                tenant,
                user,
                generation,
                "mfa_backup_codes_regenerated"
            )
            .await,
            json!([])
        );
    })
    .catch_unwind()
    .await;
    let removed = connection
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();"
        ))
        .await;
    if let Err(panic) = rollback {
        drop(connection);
        cleanup(&pool, user).await;
        std::panic::resume_unwind(panic);
    }
    removed.unwrap();
    let actor_check = std::panic::AssertUnwindSafe(async {
        sql_query("UPDATE users SET is_active=FALSE WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid, _>(user.as_uuid())
            .execute(&mut connection)
            .await
            .unwrap();
        assert!(
            service
                .regenerate_backup_codes_with_required_audit(
                    &admitted,
                    &proof,
                    "fixture-source-hash".to_owned()
                )
                .await
                .is_err()
        );
        assert_eq!(snapshot(&pool, tenant, user).await, before);
        assert_eq!(
            required_mutation_ledger(
                &pool,
                tenant,
                user,
                generation,
                "mfa_backup_codes_regenerated"
            )
            .await,
            json!([])
        );
        sql_query("UPDATE users SET is_active=TRUE WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid, _>(user.as_uuid())
            .execute(&mut connection)
            .await
            .unwrap();
        let codes = service
            .regenerate_backup_codes_with_required_audit(
                &admitted,
                &proof,
                "fixture-source-hash".to_owned(),
            )
            .await
            .unwrap();
        assert_eq!(codes.len(), nazo_identity::mfa::MFA_BACKUP_CODE_COUNT);
        assert_ne!(
            snapshot(&pool, tenant, user).await["backups"],
            before["backups"]
        );
        assert_required_mutation(
            &required_mutation_ledger(
                &pool,
                tenant,
                user,
                generation,
                "mfa_backup_codes_regenerated",
            )
            .await,
            tenant,
            user,
            generation,
        );
    })
    .catch_unwind()
    .await;
    drop(connection);
    cleanup(&pool, user).await;
    if let Err(panic) = actor_check {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn mfa_confirm_and_regenerate_hidden_committed_ack_return_no_backup_codes() {
    let Some((pool, tenant, user)) = database_fixture().await else {
        return;
    };
    let repository = mfa_repository(pool.clone());
    let body = std::panic::AssertUnwindSafe(async {
        repository
            .begin_totp_enrollment(
                tenant.tenant_id,
                user,
                SECRET.to_owned(),
                "unknown fixture".to_owned(),
            )
            .await
            .unwrap();
        let admitted = account(&pool, tenant, user).await;
        let real = service(&repository);
        let before = snapshot(&pool, tenant, user).await;
        let generation = Uuid::parse_str(before["credential"]["id"].as_str().unwrap()).unwrap();
        let hidden = MfaService::new(
            Arc::new(UnknownMfaCommitAck {
                inner: repository.clone(),
                lose_ack: std::sync::atomic::AtomicBool::new(true),
            }),
            Arc::new(FixtureHasher),
        );
        let prepared = real
            .prepare_totp_confirmation(&admitted, &totp(STEP), STEP * 30)
            .await
            .unwrap();
        let error = hidden
            .confirm_totp_with_required_audit(
                &admitted,
                prepared,
                STEP * 30,
                "fixture-source-hash".to_owned(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.repository_error(),
            Some(&RepositoryError::Unavailable)
        );
        let committed = snapshot(&pool, tenant, user).await;
        assert_eq!(committed["enabled"], true);
        assert_eq!(
            committed["backups"].as_array().unwrap().len(),
            nazo_identity::mfa::MFA_BACKUP_CODE_COUNT
        );
        let ledger =
            required_mutation_ledger(&pool, tenant, user, generation, "mfa_totp_enabled").await;
        assert_required_mutation(&ledger, tenant, user, generation);
        assert_eq!(
            real.prepare_totp_confirmation(&admitted, &totp(STEP), STEP * 30)
                .await
                .unwrap_err()
                .kind(),
            MfaServiceErrorKind::AlreadyEnabled
        );
        assert_eq!(
            required_mutation_ledger(&pool, tenant, user, generation, "mfa_totp_enabled").await,
            ledger
        );
        let admitted = account(&pool, tenant, user).await;
        let proof = real
            .verify_factor(&admitted, &totp(STEP + 1), (STEP + 1) * 30)
            .await
            .unwrap()
            .unwrap();
        let before = snapshot(&pool, tenant, user).await;
        let hidden = MfaService::new(
            Arc::new(UnknownMfaCommitAck {
                inner: repository.clone(),
                lose_ack: std::sync::atomic::AtomicBool::new(true),
            }),
            Arc::new(FixtureHasher),
        );
        let error = hidden
            .regenerate_backup_codes_with_required_audit(
                &admitted,
                &proof,
                "fixture-source-hash".to_owned(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.repository_error(),
            Some(&RepositoryError::Unavailable)
        );
        let committed = snapshot(&pool, tenant, user).await;
        assert_ne!(committed["backups"], before["backups"]);
        assert_eq!(committed["credential"], before["credential"]);
        assert_required_mutation(
            &required_mutation_ledger(
                &pool,
                tenant,
                user,
                generation,
                "mfa_backup_codes_regenerated",
            )
            .await,
            tenant,
            user,
            generation,
        );
    })
    .catch_unwind()
    .await;
    cleanup(&pool, user).await;
    if let Err(panic) = body {
        std::panic::resume_unwind(panic);
    }
}
