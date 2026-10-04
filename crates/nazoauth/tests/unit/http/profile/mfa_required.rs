//! HTTP -> production profile -> actual PG commit with its ACK deliberately hidden.
use actix_web::{
    App,
    http::{StatusCode, header},
    test, web,
};
use chrono::{DateTime, Utc};
use diesel::{
    sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_http_actix::{
    ClientIpConfig, ClientIpHeaderMode, MfaProfileConfig, MfaProfileEndpoint,
    configure_mfa_profile_routes,
};
use nazo_identity::{
    MfaService, SessionId, SessionRotationOutcome, SessionService, SessionSnapshot,
    SessionUpdateOutcome, SessionVersion, TenantContext, TenantId, UserId,
    ports::{
        BackupCodeCandidate, EncodedSecretHash, MfaAttemptThrottleDecision, MfaAttemptThrottlePort,
        MfaHashError, MfaHashFuture, MfaRepositoryPort, MfaSecretHashPort, MfaTotpKey,
        MfaTotpKeyRing, RepositoryError, RepositoryFuture, SessionAccountPort, SessionStorePort,
        TotpCredential, TotpEnrollment, TotpVerificationOutcome,
    },
    session::SessionRecord,
};
use nazo_oauth_server::{
    contracts::local_registration::{
        AuthenticationRateLimit, AuthenticationRateLimitError, LocalRegistrationFuture,
    },
    domain::mfa_profile::ServerMfaProfileOperations,
    ports::audit::{AuditFuture, SecurityAudit},
};
use nazo_postgres::{MfaRepository, UserRepository, create_pool, get_conn};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

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

    fn totp_credential<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpCredential>> {
        MfaRepositoryPort::totp_credential(&self.inner, tenant_id, user_id)
    }

    fn compare_and_set_totp_step<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> RepositoryFuture<'a, bool> {
        MfaRepositoryPort::compare_and_set_totp_step(&self.inner, tenant_id, user_id, step)
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

#[derive(Default)]
struct MemorySessions {
    records: Mutex<HashMap<String, SessionSnapshot>>,
    rotations: Mutex<Vec<String>>,
    deleted: Mutex<Vec<String>>,
}
impl SessionStorePort for MemorySessions {
    fn load<'a>(&'a self, id: &'a SessionId) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        Box::pin(async move { Ok(self.records.lock().unwrap().get(id.as_str()).cloned()) })
    }
    fn delete<'a>(&'a self, id: &'a SessionId) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.deleted.lock().unwrap().push(id.as_str().to_owned());
            Ok(self.records.lock().unwrap().remove(id.as_str()).is_some())
        })
    }
    fn rotate<'a>(
        &'a self,
        old: &'a SessionId,
        expected: &'a SessionSnapshot,
        new: &'a SessionId,
        replacement: &'a SessionRecord,
        _ttl: u64,
    ) -> RepositoryFuture<'a, SessionRotationOutcome> {
        Box::pin(async move {
            let mut records = self.records.lock().unwrap();
            if records.get(old.as_str()) != Some(expected) {
                return Ok(SessionRotationOutcome::Conflict);
            }
            records.remove(old.as_str());
            records.insert(
                new.as_str().to_owned(),
                SessionSnapshot::new(
                    replacement.clone(),
                    SessionVersion::from_storage(b"fixture-rotated".to_vec().into_boxed_slice()),
                ),
            );
            self.rotations.lock().unwrap().push(new.as_str().to_owned());
            Ok(SessionRotationOutcome::Applied)
        })
    }
    fn compare_and_set<'a>(
        &'a self,
        id: &'a SessionId,
        expected: &'a SessionSnapshot,
        replacement: &'a SessionRecord,
    ) -> RepositoryFuture<'a, SessionUpdateOutcome> {
        Box::pin(async move {
            let mut records = self.records.lock().unwrap();
            if records.get(id.as_str()) != Some(expected) {
                return Ok(SessionUpdateOutcome::Conflict);
            }
            records.insert(
                id.as_str().to_owned(),
                SessionSnapshot::new(
                    replacement.clone(),
                    SessionVersion::from_storage(b"fixture-compared".to_vec().into_boxed_slice()),
                ),
            );
            Ok(SessionUpdateOutcome::Applied)
        })
    }
}
struct Accounts(UserRepository);
impl SessionAccountPort for Accounts {
    fn public_account_by_id(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        Box::pin(async move { self.0.public_account_by_id(tenant, user).await })
    }
}
struct AllowedAttempts;
impl AuthenticationRateLimit for AllowedAttempts {
    fn enforce<'a>(
        &'a self,
        _subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>> {
        Box::pin(async { Ok(()) })
    }
}
impl MfaAttemptThrottlePort for AllowedAttempts {
    fn reserve_attempt<'a>(
        &'a self,
        _tenant: TenantId,
        _user: UserId,
        _session: &'a str,
        _window: u64,
        _maximum: u64,
    ) -> RepositoryFuture<'a, MfaAttemptThrottleDecision> {
        Box::pin(async { Ok(MfaAttemptThrottleDecision::Allowed) })
    }
    fn clear_attempts<'a>(
        &'a self,
        _tenant: TenantId,
        _user: UserId,
        _session: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}
struct ReadyAudit;
impl SecurityAudit for ReadyAudit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        Box::pin(async { Ok(()) })
    }
    fn record(&self, _event: &str, _fields: serde_json::Map<String, serde_json::Value>) {}
    fn record_required<'a>(
        &'a self,
        _event: &'a str,
        _fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuditFuture<'a> {
        Box::pin(async {
            anyhow::bail!("unexpected separate Required writer in production MFA profile")
        })
    }
}
#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn unknown_ack_http_boundary(regenerate: bool) {
    let url = std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
    let url = match url {
        Ok(url) => url,
        Err(_) => {
            assert!(std::env::var_os("CI").is_none(), "CI requires PostgreSQL");
            return;
        }
    };
    let pool = create_pool(url, 4).unwrap();
    let tenant = TenantContext::default_system();
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO users (id,username,email,password_hash) VALUES ($1,$1::text,$1::text||'@example.test','fixture-only')")
        .bind::<SqlUuid,_>(user.as_uuid()).execute(&mut connection).await.unwrap();
    drop(connection);
    let users = UserRepository::new(pool.clone());
    let repository = MfaRepository::with_totp_key_ring(
        pool.clone(),
        Some(
            MfaTotpKeyRing::new(
                MfaTotpKey::new("http-fixture-current", [7; 32]).unwrap(),
                None,
            )
            .unwrap(),
        ),
    );
    let now = Utc::now().timestamp();
    let step = now / nazo_identity::mfa::MFA_TOTP_PERIOD_SECONDS;
    repository
        .begin_totp_enrollment(
            tenant.tenant_id,
            user,
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned(),
            "HTTP formal fixture".to_owned(),
        )
        .await
        .unwrap();
    if regenerate {
        let initial = MfaService::new(Arc::new(repository.clone()), Arc::new(FixtureHasher));
        let account = users
            .public_account_by_id(tenant.tenant_id, user)
            .await
            .unwrap()
            .unwrap();
        let old_now = (step - 2) * nazo_identity::mfa::MFA_TOTP_PERIOD_SECONDS;
        let old_code =
            nazo_identity::mfa::totp_for_step(b"12345678901234567890", step - 2).unwrap();
        let prepared = initial
            .prepare_totp_confirmation(&account, &old_code, old_now)
            .await
            .unwrap();
        assert!(matches!(
            initial
                .confirm_totp(&account, prepared, old_now)
                .await
                .unwrap(),
            nazo_identity::TotpConfirmationOutcome::Accepted { .. }
        ));
    }
    let hidden = Arc::new(UnknownMfaCommitAck {
        inner: repository.clone(),
        lose_ack: AtomicBool::new(true),
    });
    let sessions = Arc::new(MemorySessions::default());
    sessions.records.lock().unwrap().insert(
        "http-old-session".to_owned(),
        SessionSnapshot::new(
            SessionRecord::new(
                user,
                now,
                vec!["pwd".to_owned()],
                false,
                Some("fixture-oidc".to_owned()),
            ),
            SessionVersion::from_storage(b"fixture-original".to_vec().into_boxed_slice()),
        ),
    );
    let operations = ServerMfaProfileOperations::new(
        MfaService::new(hidden.clone(), Arc::new(FixtureHasher)),
        SessionService::new(
            sessions.clone(),
            Arc::new(Accounts(users.clone())),
            tenant.tenant_id,
        ),
        Arc::new(AllowedAttempts),
        Arc::new(AllowedAttempts),
        Arc::new(ReadyAudit),
        300,
        10,
        "https://issuer.example",
        600,
        600,
    );
    let endpoint = MfaProfileEndpoint::new(
        Arc::new(operations),
        ClientIpConfig::new(&[], ClientIpHeaderMode::None),
        MfaProfileConfig::new("session", "csrf", "remembered", 600, 600, true),
    );
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(endpoint))
            .service(web::scope("/auth/me/mfa").configure(configure_mfa_profile_routes)),
    )
    .await;
    let path = if regenerate {
        "/auth/me/mfa/backup-codes/regenerate"
    } else {
        "/auth/me/mfa/totp/confirm"
    };
    let code = nazo_identity::mfa::totp_for_step(
        b"12345678901234567890",
        Utc::now().timestamp() / nazo_identity::mfa::MFA_TOTP_PERIOD_SECONDS,
    )
    .unwrap();
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(path)
            .cookie(actix_web::cookie::Cookie::new(
                "session",
                "http-old-session",
            ))
            .cookie(actix_web::cookie::Cookie::new("csrf", "http-old-csrf"))
            .insert_header(("x-csrf-token", "http-old-csrf"))
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_json(serde_json::json!({"code": code}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let cookies = response.response().cookies().collect::<Vec<_>>();
    assert_eq!(
        cookies.len(),
        2,
        "only session/CSRF deletion cookies may be sent"
    );
    for cookie in cookies {
        assert!(matches!(cookie.name(), "session" | "csrf"));
        assert!(
            cookie.value().is_empty(),
            "no new session or CSRF value after Unknown"
        );
        assert_eq!(cookie.max_age().map(|age| age.whole_seconds()), Some(0));
    }
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["error"], "server_error");
    for field in [
        "backup_codes",
        "session_id",
        "csrf_token",
        "secret_base32",
        "otpauth_uri",
    ] {
        assert!(
            body.get(field).is_none(),
            "no {field} disclosure after Unknown"
        );
    }
    assert!(
        !AtomicBool::load(&hidden.lose_ack, Ordering::SeqCst),
        "test must reach a real accepting commit"
    );
    let rotations = sessions.rotations.lock().unwrap().clone();
    assert_eq!(
        rotations.len(),
        1,
        "real production profile prepared one rotation"
    );
    assert_eq!(
        *sessions.deleted.lock().unwrap(),
        rotations,
        "unpublished rotation is deleted"
    );
    assert!(sessions.records.lock().unwrap().is_empty());
    let account = users
        .public_account_by_id(tenant.tenant_id, user)
        .await
        .unwrap()
        .unwrap();
    assert!(
        account.account.mfa_enabled,
        "real committed effect exists despite HTTP failure"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    let event = if regenerate {
        "mfa_backup_codes_regenerated"
    } else {
        "mfa_totp_enabled"
    };
    let count = sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE event_type=$1 AND payload->>'user_id'=$2")
        .bind::<Text,_>(event).bind::<Text,_>(user.as_uuid().to_string())
        .get_result::<CountRow>(&mut connection).await.unwrap().count;
    assert_eq!(
        count, 1,
        "exactly one canonical outcome belongs to the hidden commit"
    );
    let count = sql_query("SELECT COUNT(*)::bigint AS count FROM user_mfa_backup_codes WHERE tenant_id=$1 AND user_id=$2")
        .bind::<SqlUuid,_>(tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(user.as_uuid())
        .get_result::<CountRow>(&mut connection).await.unwrap().count;
    assert_eq!(count, nazo_identity::mfa::MFA_BACKUP_CODE_COUNT as i64);
}

#[actix_web::test]
async fn mfa_confirm_committed_unknown_http_withholds_backup_codes_and_new_cookies() {
    unknown_ack_http_boundary(false).await;
}
#[actix_web::test]
async fn mfa_regenerate_committed_unknown_http_withholds_backup_codes_and_new_cookies() {
    unknown_ack_http_boundary(true).await;
}
