#![cfg(feature = "local-sqlite")]

use std::sync::{Arc, Barrier};

use futures_executor::block_on;
use jiff::Timestamp;
use nazo_identity::{
    TenantId, UserId,
    mfa::{MFA_BACKUP_CODE_COUNT, base32_encode, totp_for_step},
    ports::{
        EncodedSecretHash, MfaRepositoryPort, RememberedMfaDevicePort, RepositoryError,
        TotpEnrollmentCheck, TotpVerificationOutcome,
    },
};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::{D1Provider, Database};
use rusqlite::params;
use uuid::Uuid;

const TENANT: Uuid = Uuid::from_u128(1);
const USER: Uuid = Uuid::from_u128(2);
const AT: i64 = 1_800_000_000;

fn tenant() -> TenantId {
    TenantId::new(TENANT).unwrap()
}
fn user() -> UserId {
    UserId::new(USER).unwrap()
}
fn hashes() -> Vec<EncodedSecretHash> {
    (0..MFA_BACKUP_CODE_COUNT)
        .map(|index| EncodedSecretHash::new(format!("fixture-hash-{index}")).unwrap())
        .collect()
}

struct Fixture {
    path: std::path::PathBuf,
    database: Database,
    provider: D1Provider,
    inspector: rusqlite::Connection,
    seed: [u8; 20],
    secret: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with_legacy_schema(false)
    }

    fn with_legacy_schema(legacy: bool) -> Self {
        let path = std::env::temp_dir().join(format!("nazo-d1-mfa-{}.sqlite", Uuid::new_v4()));
        let database = Database::open(&path).unwrap();
        if legacy {
            for sql in [
                include_str!("../migrations/0001.sql"),
                include_str!("../migrations/0002_state.sql"),
                include_str!("../migrations/0003_passkeys.sql"),
                include_str!("../migrations/0004_dynamic_registration.sql"),
                include_str!("../migrations/0005_ciba_scim.sql"),
                include_str!("../migrations/0006_accounts.sql"),
                include_str!("../migrations/0007_digital_credentials.sql"),
            ] {
                database.execute_sql(sql).unwrap();
            }
        } else {
            database.execute_schema().unwrap();
        }
        let provider =
            D1Provider::new(database.clone(), tenant()).with_data_encryption_key(rand::random());
        let inspector = rusqlite::Connection::open(&path).unwrap();
        inspector.execute("INSERT INTO nazo_users(tenant_id,id,email,principal,claims,password_hash,epoch,active,created_at,updated_at) VALUES(?1,?2,'mfa@example.test','{}','{}','fixture',0,1,0,0)", params![TENANT.to_string(), USER.to_string()]).unwrap();
        // Avoid the rare equal adjacent six-digit values making a replay test
        // ambiguous inside the shared policy's permitted skew window.
        let seed = loop {
            let seed = rand::random::<[u8; 20]>();
            let codes = (-1..=4)
                .map(|offset| totp_for_step(&seed, AT / 30 + offset).unwrap())
                .collect::<std::collections::HashSet<_>>();
            if codes.len() == 6 {
                break seed;
            }
        };
        let secret = base32_encode(&seed);
        Self {
            path,
            database,
            provider,
            inspector,
            seed,
            secret,
        }
    }

    fn code(&self, offset: i64) -> String {
        totp_for_step(&self.seed, AT / 30 + offset).unwrap()
    }
    fn count(&self, table: &str) -> i64 {
        self.inspector
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE tenant_id=?1"),
                [TENANT.to_string()],
                |row| row.get(0),
            )
            .unwrap()
    }
    fn enabled(&self) -> bool {
        self.inspector
            .query_row(
                "SELECT mfa_enabled FROM nazo_users WHERE tenant_id=?1 AND id=?2",
                params![TENANT.to_string(), USER.to_string()],
                |row| row.get(0),
            )
            .unwrap()
    }
    fn audit_count(&self, event: &str) -> i64 {
        self.inspector
            .query_row(
                "SELECT count(*) FROM nazo_audit WHERE event_type=?1",
                [event],
                |row| row.get(0),
            )
            .unwrap()
    }
    async fn begin(&self) {
        assert!(
            self.provider
                .begin_totp_enrollment(tenant(), user(), &self.secret)
                .await
                .unwrap()
        );
    }
    async fn confirm(&self) -> Uuid {
        let outcome = self
            .provider
            .verify_and_confirm_totp_with_required_audit(
                tenant(),
                user(),
                &self.code(0),
                AT,
                hashes(),
                "source-hash".into(),
            )
            .await
            .unwrap();
        let TotpVerificationOutcome::Accepted(id) = outcome else {
            panic!("expected enrollment confirmation");
        };
        id
    }
    fn block_audit(&self, event: &str) {
        self.database.execute_sql(&format!("CREATE TRIGGER block_mfa_audit BEFORE INSERT ON nazo_audit WHEN NEW.event_type='{event}' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")).unwrap();
    }
    fn unblock_audit(&self) {
        self.database
            .execute_sql("DROP TRIGGER block_mfa_audit")
            .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn ignored_or_corrupted_pending_enrollment_never_returns_a_successful_view() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_mfa_totp BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER INSERT ON nazo_mfa_totp BEGIN UPDATE nazo_mfa_totp SET secret_ciphertext='corrupt' WHERE id=NEW.id;END;",
        ] {
            let fixture = Fixture::new();
            fixture.database.execute_sql(trigger).unwrap();
            assert!(
                fixture
                    .provider
                    .begin_totp_enrollment(tenant(), user(), &fixture.secret)
                    .await
                    .is_err()
            );
            assert_eq!(fixture.count("nazo_mfa_totp"), 0);
        }
        let fixture = Fixture::new();
        fixture.begin().await;
        let original: String = fixture
            .inspector
            .query_row("SELECT secret_ciphertext FROM nazo_mfa_totp", [], |row| {
                row.get(0)
            })
            .unwrap();
        fixture.database.execute_sql("CREATE TRIGGER suppress BEFORE UPDATE ON nazo_mfa_totp BEGIN SELECT RAISE(IGNORE);END;").unwrap();
        assert!(
            fixture
                .provider
                .begin_totp_enrollment(
                    tenant(),
                    user(),
                    &base32_encode(&rand::random::<[u8; 20]>())
                )
                .await
                .is_err()
        );
        assert_eq!(
            fixture
                .inspector
                .query_row("SELECT secret_ciphertext FROM nazo_mfa_totp", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            original
        );
    });
}

#[test]
fn ignored_confirmation_effects_roll_back_seed_backup_codes_account_and_all_audits() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE UPDATE ON nazo_mfa_totp BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='mfa_totp_attempt' BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='mfa_totp_enabled' BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_mfa_backup_codes WHEN NEW.code_hash='fixture-hash-3' BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE UPDATE ON nazo_users BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER UPDATE ON nazo_users WHEN NEW.mfa_enabled=1 BEGIN UPDATE nazo_users SET mfa_enabled=0 WHERE id=NEW.id;END;",
            "CREATE TRIGGER suppress AFTER INSERT ON nazo_mfa_backup_codes WHEN NEW.code_hash='fixture-hash-3' BEGIN UPDATE nazo_mfa_backup_codes SET code_hash='corrupt' WHERE id=NEW.id;END;",
        ] {
            let fixture = Fixture::new();
            fixture.begin().await;
            fixture.database.execute_sql(trigger).unwrap();
            assert!(
                fixture
                    .provider
                    .verify_and_confirm_totp_with_required_audit(
                        tenant(),
                        user(),
                        &fixture.code(0),
                        AT,
                        hashes(),
                        "source".into()
                    )
                    .await
                    .is_err(),
                "{trigger}"
            );
            assert!(!fixture.enabled());
            assert_eq!(fixture.count("nazo_mfa_backup_codes"), 0);
            assert_eq!(fixture.count("nazo_audit"), 0);
            assert!(
                fixture
                    .inspector
                    .query_row(
                        "SELECT confirmed_at IS NULL AND last_used_step IS NULL FROM nazo_mfa_totp",
                        [],
                        |row| row.get::<_, bool>(0)
                    )
                    .unwrap()
            );
            fixture
                .database
                .execute_sql("DROP TRIGGER suppress")
                .unwrap();
            fixture.confirm().await;
        }
    });
}

#[test]
fn ignored_totp_consumption_and_required_attempt_audit_leave_the_code_usable() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE UPDATE ON nazo_mfa_totp BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='mfa_totp_attempt' BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER UPDATE ON nazo_mfa_totp BEGIN UPDATE nazo_mfa_totp SET last_used_step=60000000 WHERE id=NEW.id;END;",
        ] {
            let fixture = Fixture::new();
            fixture.begin().await;
            let id = fixture.confirm().await;
            let audits = fixture.count("nazo_audit");
            fixture.database.execute_sql(trigger).unwrap();
            assert!(
                fixture
                    .provider
                    .verify_and_consume_totp(tenant(), user(), &fixture.code(1), AT + 30)
                    .await
                    .is_err(),
                "{trigger}"
            );
            assert_eq!(
                fixture
                    .inspector
                    .query_row("SELECT last_used_step FROM nazo_mfa_totp", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                AT / 30
            );
            assert_eq!(fixture.count("nazo_audit"), audits);
            fixture
                .database
                .execute_sql("DROP TRIGGER suppress")
                .unwrap();
            assert_eq!(
                fixture
                    .provider
                    .verify_and_consume_totp(tenant(), user(), &fixture.code(1), AT + 30)
                    .await
                    .unwrap(),
                TotpVerificationOutcome::Accepted(id)
            );
        }
        let fixture = Fixture::new();
        fixture.database.execute_sql("CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit BEGIN SELECT RAISE(IGNORE);END;").unwrap();
        assert!(
            fixture
                .provider
                .record_invalid_totp_attempt(tenant(), user())
                .await
                .is_err()
        );
        assert!(
            fixture
                .provider
                .record_invalid_backup_code_attempt(tenant(), user())
                .await
                .is_err()
        );
        assert_eq!(fixture.count("nazo_audit"), 0);
    });
}

#[test]
fn ignored_backup_regeneration_and_final_projection_changes_preserve_the_old_set() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_mfa_backup_codes BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_mfa_backup_codes WHEN NEW.code_hash='fixture-hash-3' BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='mfa_backup_codes_regenerated' BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER INSERT ON nazo_audit WHEN NEW.event_type='mfa_backup_codes_regenerated' BEGIN UPDATE nazo_mfa_backup_codes SET code_hash='corrupt';END;",
        ] {
            let fixture = Fixture::new();
            fixture.begin().await;
            let id = fixture.confirm().await;
            let before = fixture
                .provider
                .backup_code_candidates(tenant(), user())
                .await
                .unwrap();
            let audits = fixture.count("nazo_audit");
            fixture.database.execute_sql(trigger).unwrap();
            assert!(
                fixture
                    .provider
                    .replace_backup_code_hashes_with_required_audit(
                        tenant(),
                        user(),
                        id,
                        hashes(),
                        "source".into()
                    )
                    .await
                    .is_err(),
                "{trigger}"
            );
            assert_eq!(
                fixture
                    .provider
                    .backup_code_candidates(tenant(), user())
                    .await
                    .unwrap(),
                before
            );
            assert_eq!(fixture.count("nazo_audit"), audits);
        }
        let fixture = Fixture::new();
        fixture.begin().await;
        let id = fixture.confirm().await;
        fixture.database.execute_sql("CREATE TRIGGER suppress BEFORE DELETE ON nazo_mfa_backup_codes BEGIN SELECT RAISE(IGNORE);END;").unwrap();
        assert!(
            fixture
                .provider
                .replace_backup_code_hashes(tenant(), user(), id, Vec::new())
                .await
                .is_err()
        );
        assert_eq!(
            fixture.count("nazo_mfa_backup_codes"),
            MFA_BACKUP_CODE_COUNT as i64
        );
    });
}

#[test]
fn ignored_mfa_disable_or_foreign_key_retirement_cannot_commit_partial_disable() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='mfa_disabled' BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE UPDATE ON nazo_users BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_mfa_totp BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_mfa_backup_codes BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_mfa_devices BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER DELETE ON nazo_mfa_totp BEGIN UPDATE nazo_users SET mfa_enabled=1 WHERE id=OLD.user_id;END;",
        ] {
            let fixture = Fixture::new();
            fixture.begin().await;
            let id = fixture.confirm().await;
            assert!(
                fixture
                    .provider
                    .remember_device(
                        tenant(),
                        user(),
                        id,
                        "remembered".into(),
                        None,
                        Timestamp::now() + jiff::SignedDuration::from_secs(60)
                    )
                    .await
                    .unwrap()
            );
            let audits = fixture.count("nazo_audit");
            fixture.database.execute_sql(trigger).unwrap();
            assert!(
                fixture
                    .provider
                    .clear_mfa_state_if_current_with_required_audit(
                        tenant(),
                        user(),
                        id,
                        "source".into()
                    )
                    .await
                    .is_err(),
                "{trigger}"
            );
            assert!(fixture.enabled());
            assert_eq!(fixture.count("nazo_mfa_totp"), 1);
            assert_eq!(
                fixture.count("nazo_mfa_backup_codes"),
                MFA_BACKUP_CODE_COUNT as i64
            );
            assert_eq!(fixture.count("nazo_mfa_devices"), 1);
            assert_eq!(fixture.count("nazo_audit"), audits);
        }
    });
}

#[test]
fn ignored_backup_consumption_keeps_the_candidate_and_canonical_audit_atomic() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='mfa_backup_code_attempt' BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_mfa_backup_codes BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER DELETE ON nazo_mfa_backup_codes BEGIN INSERT INTO nazo_mfa_backup_codes(tenant_id,user_id,id,credential_id,code_hash) VALUES(OLD.tenant_id,OLD.user_id,OLD.id,OLD.credential_id,OLD.code_hash);END;",
        ] {
            let fixture = Fixture::new();
            fixture.begin().await;
            let id = fixture.confirm().await;
            let candidates = fixture
                .provider
                .backup_code_candidates(tenant(), user())
                .await
                .unwrap();
            let candidate = candidates[0].id;
            let audits = fixture.count("nazo_audit");
            fixture.database.execute_sql(trigger).unwrap();
            assert!(
                fixture
                    .provider
                    .consume_backup_code_candidate(tenant(), user(), candidate)
                    .await
                    .is_err(),
                "{trigger}"
            );
            assert_eq!(
                fixture
                    .provider
                    .backup_code_candidates(tenant(), user())
                    .await
                    .unwrap(),
                candidates
            );
            assert_eq!(fixture.count("nazo_audit"), audits);
            fixture
                .database
                .execute_sql("DROP TRIGGER suppress")
                .unwrap();
            assert_eq!(
                fixture
                    .provider
                    .consume_backup_code_candidate(tenant(), user(), candidate)
                    .await
                    .unwrap(),
                Some(id)
            );
        }
    });
}

#[test]
fn ignored_remembered_device_cleanup_insert_or_final_projection_rolls_back() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE DELETE ON nazo_mfa_devices BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_mfa_devices BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER INSERT ON nazo_mfa_devices BEGIN UPDATE nazo_mfa_devices SET user_agent_hash='corrupt' WHERE token_hash=NEW.token_hash;END;",
        ] {
            let fixture = Fixture::new();
            fixture.begin().await;
            let id = fixture.confirm().await;
            assert!(
                fixture
                    .provider
                    .remember_device(
                        tenant(),
                        user(),
                        id,
                        "expired".into(),
                        None,
                        Timestamp::now() - jiff::SignedDuration::from_secs(1)
                    )
                    .await
                    .unwrap()
            );
            fixture.database.execute_sql(trigger).unwrap();
            assert!(
                fixture
                    .provider
                    .remember_device(
                        tenant(),
                        user(),
                        id,
                        "fresh".into(),
                        Some("user-agent".into()),
                        Timestamp::now() + jiff::SignedDuration::from_secs(60)
                    )
                    .await
                    .is_err(),
                "{trigger}"
            );
            assert_eq!(fixture.count("nazo_mfa_devices"), 1);
            assert_eq!(
                fixture
                    .inspector
                    .query_row("SELECT token_hash FROM nazo_mfa_devices", [], |row| row
                        .get::<_, String>(
                        0
                    ))
                    .unwrap(),
                "expired"
            );
            fixture
                .database
                .execute_sql("DROP TRIGGER suppress")
                .unwrap();
            assert!(
                fixture
                    .provider
                    .remember_device(
                        tenant(),
                        user(),
                        id,
                        "fresh".into(),
                        Some("user-agent".into()),
                        Timestamp::now() + jiff::SignedDuration::from_secs(60)
                    )
                    .await
                    .unwrap()
            );
            assert_eq!(fixture.count("nazo_mfa_devices"), 1);
        }
    });
}

#[test]
fn encrypted_enrollment_rechecks_pending_seed_and_preserves_confirmed_generation() {
    block_on(async {
        let fixture = Fixture::new();
        let repository = fixture.provider.mfa_repository();
        assert_eq!(
            repository
                .check_totp_enrollment(tenant(), user(), &fixture.code(0), AT)
                .await
                .unwrap(),
            TotpEnrollmentCheck::Missing
        );
        fixture.begin().await;
        let protected: String = fixture
            .inspector
            .query_row("SELECT secret_ciphertext FROM nazo_mfa_totp", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(!protected.contains(&fixture.secret));
        assert_eq!(
            repository
                .check_totp_enrollment(tenant(), user(), &fixture.code(0), AT)
                .await
                .unwrap(),
            TotpEnrollmentCheck::ValidCode
        );
        assert_eq!(
            repository
                .check_totp_enrollment(tenant(), user(), "invalid", AT)
                .await
                .unwrap(),
            TotpEnrollmentCheck::InvalidCode
        );
        let replacement = base32_encode(&rand::random::<[u8; 20]>());
        assert!(
            repository
                .begin_totp_enrollment(tenant(), user(), &replacement)
                .await
                .unwrap()
        );
        assert_eq!(
            repository
                .check_totp_enrollment(tenant(), user(), &fixture.code(0), AT)
                .await
                .unwrap(),
            TotpEnrollmentCheck::InvalidCode
        );
        fixture.begin().await;
        assert_eq!(
            repository
                .verify_and_confirm_totp(tenant(), user(), &fixture.code(0), AT, Vec::new())
                .await,
            Err(RepositoryError::Conflict)
        );
        let id = fixture.confirm().await;
        assert!(fixture.enabled());
        assert_eq!(
            fixture.count("nazo_mfa_backup_codes"),
            MFA_BACKUP_CODE_COUNT as i64
        );
        assert!(
            !repository
                .begin_totp_enrollment(tenant(), user(), &replacement)
                .await
                .unwrap()
        );
        assert_eq!(
            repository
                .check_totp_enrollment(tenant(), user(), &fixture.code(0), AT)
                .await
                .unwrap(),
            TotpEnrollmentCheck::AlreadyConfirmed
        );
        assert_eq!(
            repository
                .verify_and_consume_totp(tenant(), user(), &fixture.code(0), AT)
                .await
                .unwrap(),
            TotpVerificationOutcome::Replay
        );
        assert_eq!(
            repository
                .verify_and_consume_totp(tenant(), user(), &fixture.code(1), AT + 30)
                .await
                .unwrap(),
            TotpVerificationOutcome::Accepted(id)
        );
        let payload: String = fixture
            .inspector
            .query_row(
                "SELECT payload FROM nazo_audit WHERE event_type='mfa_totp_enabled'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(payload["credential_id"], id.to_string());
        assert_eq!(payload["source_ip_hash"], "source-hash");
    });
}

#[test]
fn concurrent_confirmation_and_totp_consumption_have_one_accepting_commit() {
    let fixture = Fixture::new();
    block_on(fixture.begin());
    let code = fixture.code(0);
    let barrier = Arc::new(Barrier::new(6));
    let results = std::thread::scope(|scope| {
        (0..6)
            .map(|_| {
                let provider = fixture.provider.clone();
                let barrier = barrier.clone();
                let code = &code;
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.verify_and_confirm_totp_with_required_audit(
                        tenant(),
                        user(),
                        code,
                        AT,
                        hashes(),
                        "source".into(),
                    ))
                    .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|outcome| matches!(outcome, TotpVerificationOutcome::Accepted(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|outcome| **outcome == TotpVerificationOutcome::Replay)
            .count(),
        5
    );
    assert_eq!(fixture.audit_count("mfa_totp_enabled"), 1);
    assert_eq!(fixture.count("nazo_mfa_backup_codes"), 10);
    let code = fixture.code(1);
    let barrier = Arc::new(Barrier::new(8));
    let results = std::thread::scope(|scope| {
        (0..8)
            .map(|_| {
                let provider = fixture.provider.clone();
                let barrier = barrier.clone();
                let code = &code;
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.verify_and_consume_totp(tenant(), user(), code, AT + 30))
                        .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|outcome| matches!(outcome, TotpVerificationOutcome::Accepted(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|outcome| **outcome == TotpVerificationOutcome::Replay)
            .count(),
        7
    );
}

#[test]
fn required_audit_failure_rolls_back_confirmation_regeneration_and_disable() {
    block_on(async {
        let fixture = Fixture::new();
        fixture.begin().await;
        fixture.block_audit("mfa_totp_enabled");
        assert!(
            fixture
                .provider
                .verify_and_confirm_totp_with_required_audit(
                    tenant(),
                    user(),
                    &fixture.code(0),
                    AT,
                    hashes(),
                    "source".into()
                )
                .await
                .is_err()
        );
        assert!(!fixture.enabled());
        assert_eq!(fixture.count("nazo_mfa_backup_codes"), 0);
        assert_eq!(fixture.count("nazo_audit"), 0);
        fixture.unblock_audit();
        let id = fixture.confirm().await;
        let before = fixture
            .provider
            .backup_code_candidates(tenant(), user())
            .await
            .unwrap();
        fixture.block_audit("mfa_backup_codes_regenerated");
        assert!(
            fixture
                .provider
                .replace_backup_code_hashes_with_required_audit(
                    tenant(),
                    user(),
                    id,
                    hashes(),
                    "source".into()
                )
                .await
                .is_err()
        );
        assert_eq!(
            fixture
                .provider
                .backup_code_candidates(tenant(), user())
                .await
                .unwrap(),
            before
        );
        fixture.unblock_audit();
        assert!(
            fixture
                .provider
                .remember_device(
                    tenant(),
                    user(),
                    id,
                    "remembered".into(),
                    None,
                    Timestamp::now() + jiff::SignedDuration::from_secs(600)
                )
                .await
                .unwrap()
        );
        fixture.block_audit("mfa_disabled");
        assert!(
            fixture
                .provider
                .clear_mfa_state_if_current_with_required_audit(
                    tenant(),
                    user(),
                    id,
                    "source".into()
                )
                .await
                .is_err()
        );
        assert!(fixture.enabled());
        assert_eq!(fixture.count("nazo_mfa_devices"), 1);
        assert_eq!(
            fixture
                .provider
                .backup_code_candidates(tenant(), user())
                .await
                .unwrap(),
            before
        );
        fixture.unblock_audit();
        assert!(
            fixture
                .provider
                .clear_mfa_state_if_current_with_required_audit(
                    tenant(),
                    user(),
                    id,
                    "source".into()
                )
                .await
                .unwrap()
        );
        assert!(!fixture.enabled());
        assert_eq!(fixture.count("nazo_mfa_totp"), 0);
        assert_eq!(fixture.count("nazo_mfa_backup_codes"), 0);
        assert_eq!(fixture.count("nazo_mfa_devices"), 0);
        assert_eq!(fixture.audit_count("mfa_disabled"), 1);
    });
}

#[test]
fn backup_codes_are_one_use_and_audit_failure_preserves_the_candidate() {
    let fixture = Fixture::new();
    block_on(fixture.begin());
    let id = block_on(fixture.confirm());
    let candidates = block_on(fixture.provider.backup_code_candidates(tenant(), user())).unwrap();
    let candidate = candidates[0].id;
    fixture.block_audit("mfa_backup_code_attempt");
    assert!(
        block_on(
            fixture
                .provider
                .consume_backup_code_candidate(tenant(), user(), candidate)
        )
        .is_err()
    );
    assert_eq!(fixture.count("nazo_mfa_backup_codes"), 10);
    fixture.unblock_audit();
    let barrier = Arc::new(Barrier::new(6));
    let results = std::thread::scope(|scope| {
        (0..6)
            .map(|_| {
                let provider = fixture.provider.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.consume_backup_code_candidate(tenant(), user(), candidate))
                        .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results.iter().filter(|result| **result == Some(id)).count(),
        1
    );
    assert_eq!(results.iter().filter(|result| result.is_none()).count(), 5);
    assert_eq!(fixture.count("nazo_mfa_backup_codes"), 9);
    assert_eq!(fixture.audit_count("mfa_backup_code_attempt"), 6);
}

#[test]
fn inactive_accounts_and_retired_generations_cannot_commit_mfa_changes() {
    block_on(async {
        let fixture = Fixture::new();
        fixture.begin().await;
        fixture
            .database
            .execute_sql("UPDATE nazo_users SET active=0")
            .unwrap();
        assert!(
            fixture
                .provider
                .verify_and_confirm_totp_with_required_audit(
                    tenant(),
                    user(),
                    &fixture.code(0),
                    AT,
                    hashes(),
                    "source".into()
                )
                .await
                .is_err()
        );
        assert!(!fixture.enabled());
        fixture
            .database
            .execute_sql("UPDATE nazo_users SET active=1")
            .unwrap();
        let id = fixture.confirm().await;
        let candidate = fixture
            .provider
            .backup_code_candidates(tenant(), user())
            .await
            .unwrap()[0]
            .id;
        fixture
            .database
            .execute_sql("UPDATE nazo_users SET active=0")
            .unwrap();
        assert!(
            !fixture
                .provider
                .clear_mfa_state_if_current_with_required_audit(
                    tenant(),
                    user(),
                    id,
                    "source".into()
                )
                .await
                .unwrap()
        );
        assert!(
            !fixture
                .provider
                .replace_backup_code_hashes_with_required_audit(
                    tenant(),
                    user(),
                    id,
                    hashes(),
                    "source".into()
                )
                .await
                .unwrap()
        );
        assert_eq!(
            fixture
                .provider
                .consume_backup_code_candidate(tenant(), user(), candidate)
                .await
                .unwrap(),
            None
        );
        assert!(
            !fixture
                .provider
                .remember_device(
                    tenant(),
                    user(),
                    id,
                    "device".into(),
                    None,
                    Timestamp::now()
                )
                .await
                .unwrap()
        );
        assert_eq!(fixture.count("nazo_mfa_backup_codes"), 10);
        fixture
            .database
            .execute_sql("UPDATE nazo_users SET active=1")
            .unwrap();
        assert!(
            fixture
                .provider
                .clear_mfa_state_if_current(tenant(), user(), id)
                .await
                .unwrap()
        );
        fixture.begin().await;
        let next = fixture.confirm().await;
        assert_ne!(id, next);
        assert!(
            !fixture
                .provider
                .clear_mfa_state_if_current(tenant(), user(), id)
                .await
                .unwrap()
        );
        assert!(
            !fixture
                .provider
                .replace_backup_code_hashes(tenant(), user(), id, hashes())
                .await
                .unwrap()
        );
        assert!(
            !fixture
                .provider
                .remember_device(tenant(), user(), id, "stale".into(), None, Timestamp::now())
                .await
                .unwrap()
        );
        assert_eq!(
            fixture
                .provider
                .consume_backup_code_candidate(tenant(), user(), candidate)
                .await
                .unwrap(),
            None
        );
        assert!(fixture.enabled());
        assert_eq!(fixture.count("nazo_mfa_backup_codes"), 10);
    });
}

#[test]
fn seeds_require_the_right_key_account_and_tenant_and_corruption_fails_closed() {
    block_on(async {
        let fixture = Fixture::new();
        let no_key = D1Provider::new(fixture.database.clone(), tenant());
        assert!(
            no_key
                .begin_totp_enrollment(tenant(), user(), &fixture.secret)
                .await
                .is_err()
        );
        assert_eq!(fixture.count("nazo_mfa_totp"), 0);
        fixture.begin().await;
        let other_tenant = TenantId::new(Uuid::from_u128(99)).unwrap();
        assert!(
            fixture
                .provider
                .check_totp_enrollment(other_tenant, user(), &fixture.code(0), AT)
                .await
                .is_err()
        );
        assert!(
            fixture
                .provider
                .backup_code_candidates(other_tenant, user())
                .await
                .is_err()
        );
        assert!(
            fixture
                .provider
                .remembered_mfa_devices()
                .is_valid(other_tenant, user(), "token", None, Timestamp::now())
                .await
                .is_err()
        );
        let wrong_key = D1Provider::new(fixture.database.clone(), tenant())
            .with_data_encryption_key(rand::random());
        assert!(
            wrong_key
                .check_totp_enrollment(tenant(), user(), &fixture.code(0), AT)
                .await
                .is_err()
        );
        fixture.inspector.execute("INSERT INTO nazo_users(tenant_id,id,email,principal,claims,password_hash,epoch,active,created_at,updated_at) VALUES(?1,?2,'other@example.test','{}','{}','fixture',0,1,0,0)", params![TENANT.to_string(), Uuid::from_u128(3).to_string()]).unwrap();
        fixture
            .inspector
            .execute(
                "UPDATE nazo_mfa_totp SET user_id=?1",
                [Uuid::from_u128(3).to_string()],
            )
            .unwrap();
        assert!(
            fixture
                .provider
                .check_totp_enrollment(
                    tenant(),
                    UserId::new(Uuid::from_u128(3)).unwrap(),
                    &fixture.code(0),
                    AT
                )
                .await
                .is_err()
        );
        fixture
            .inspector
            .execute(
                "UPDATE nazo_mfa_totp SET user_id=?1,secret_ciphertext='invalid'",
                [USER.to_string()],
            )
            .unwrap();
        assert!(
            fixture
                .provider
                .check_totp_enrollment(tenant(), user(), &fixture.code(0), AT)
                .await
                .is_err()
        );
        assert!(!fixture.enabled());
    });
}

#[test]
fn remembered_devices_match_user_agent_expiry_and_current_generation_exactly() {
    block_on(async {
        let fixture = Fixture::new();
        fixture.begin().await;
        let id = fixture.confirm().await;
        let expiry = Timestamp::now() + jiff::SignedDuration::from_secs(60);
        assert!(
            fixture
                .provider
                .remember_device(
                    tenant(),
                    user(),
                    id,
                    "bound".into(),
                    Some("agent".into()),
                    expiry
                )
                .await
                .unwrap()
        );
        assert!(
            fixture
                .provider
                .remember_device(tenant(), user(), id, "unbound".into(), None, expiry)
                .await
                .unwrap()
        );
        let before = expiry - jiff::SignedDuration::from_micros(1);
        assert!(
            fixture
                .provider
                .is_valid(tenant(), user(), "bound", Some("agent"), before)
                .await
                .unwrap()
        );
        assert!(
            !fixture
                .provider
                .is_valid(tenant(), user(), "bound", None, before)
                .await
                .unwrap()
        );
        assert!(
            !fixture
                .provider
                .is_valid(tenant(), user(), "bound", Some("other"), before)
                .await
                .unwrap()
        );
        assert!(
            !fixture
                .provider
                .is_valid(tenant(), user(), "bound", Some("agent"), expiry)
                .await
                .unwrap()
        );
        assert!(
            fixture
                .provider
                .is_valid(tenant(), user(), "unbound", None, before)
                .await
                .unwrap()
        );
        fixture.inspector.execute(
            "INSERT INTO nazo_mfa_devices(tenant_id,user_id,credential_id,token_hash,expires_at) SELECT ?1,?2,?3,value,0 FROM json_each('[\"expired-a\",\"expired-b\",\"expired-c\"]')",
            params![TENANT.to_string(), USER.to_string(), id.to_string()],
        ).unwrap();
        assert_eq!(fixture.provider.prune_expired(2).await.unwrap(), 2);
        assert_eq!(fixture.provider.prune_expired(2).await.unwrap(), 1);
        assert_eq!(fixture.count("nazo_mfa_devices"), 2);
        assert!(
            !fixture
                .provider
                .is_valid(tenant(), user(), "unbound", Some("agent"), before)
                .await
                .unwrap()
        );
        fixture
            .database
            .execute_sql("UPDATE nazo_users SET active=0")
            .unwrap();
        assert!(
            !fixture
                .provider
                .is_valid(tenant(), user(), "bound", Some("agent"), before)
                .await
                .unwrap()
        );
        fixture
            .database
            .execute_sql("UPDATE nazo_users SET active=1")
            .unwrap();
        assert!(
            fixture
                .provider
                .clear_mfa_state_if_current(tenant(), user(), id)
                .await
                .unwrap()
        );
        assert!(
            !fixture
                .provider
                .is_valid(tenant(), user(), "bound", Some("agent"), before)
                .await
                .unwrap()
        );
    });
}

#[test]
fn backup_hash_bounds_reject_overflow_without_changing_the_current_codes() {
    block_on(async {
        let fixture = Fixture::new();
        fixture.begin().await;
        let id = fixture.confirm().await;
        let mut excessive = hashes();
        excessive.push(EncodedSecretHash::new("excess").unwrap());
        assert_eq!(
            fixture
                .provider
                .replace_backup_code_hashes(tenant(), user(), id, excessive)
                .await,
            Err(RepositoryError::Conflict)
        );
        assert_eq!(fixture.count("nazo_mfa_backup_codes"), 10);
        fixture.inspector.execute("INSERT INTO nazo_mfa_backup_codes(tenant_id,user_id,id,credential_id,code_hash) VALUES(?1,?2,?3,?4,'overflow')", params![TENANT.to_string(),USER.to_string(),Uuid::new_v4().to_string(),id.to_string()]).unwrap();
        assert!(matches!(
            fixture
                .provider
                .backup_code_candidates(tenant(), user())
                .await,
            Err(RepositoryError::Consistency(_))
        ));
    });
}

#[test]
fn migration_preserves_references_indexes_and_triggers_and_never_reinitializes_mfa() {
    let fixture = Fixture::with_legacy_schema(true);
    fixture.database.execute_sql("CREATE TABLE epoch_probe(value INTEGER); CREATE TRIGGER probe_user_epoch AFTER UPDATE OF epoch ON nazo_users BEGIN INSERT INTO epoch_probe VALUES(NEW.epoch); END;").unwrap();
    fixture
        .inspector
        .execute(
            "INSERT INTO nazo_subjects(tenant_id,subject,user_id) VALUES(?1,'subject',?2)",
            params![TENANT.to_string(), USER.to_string()],
        )
        .unwrap();
    fixture
        .inspector
        .execute(
            "INSERT INTO nazo_deleted_users(tenant_id,user_id,deleted_at) VALUES(?1,?2,0)",
            params![TENANT.to_string(), USER.to_string()],
        )
        .unwrap();
    fixture.database.execute_schema().unwrap();
    block_on(fixture.begin());
    block_on(fixture.confirm());
    fixture.database.execute_schema().unwrap();
    assert!(fixture.enabled());
    assert_eq!(fixture.count("nazo_mfa_backup_codes"), 10);
    // An exported D1 database has no offline receipt. Its complete new MFA
    // schema is baselined without executing the destructive column replacement.
    fixture
        .database
        .execute_sql("DROP TABLE nazo_local_migrations")
        .unwrap();
    fixture.database.execute_schema().unwrap();
    assert!(fixture.enabled());
    assert_eq!(fixture.count("nazo_subjects"), 1);
    assert_eq!(fixture.count("nazo_deleted_users"), 1);
    assert_eq!(fixture.count("nazo_mfa_backup_codes"), 10);
    fixture
        .database
        .execute_sql("UPDATE nazo_users SET epoch=1")
        .unwrap();
    assert_eq!(
        fixture
            .inspector
            .query_row("SELECT value FROM epoch_probe", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        fixture
            .inspector
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    let indexes: i64 = fixture.inspector.query_row("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name IN ('nazo_users_username','nazo_users_email_lower','nazo_users_created')", [], |row| row.get(0)).unwrap();
    assert_eq!(indexes, 3);
    assert_eq!(fixture.inspector.query_row("SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND name='nazo_vci_revoke_user'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
}

#[test]
fn incomplete_unreceipted_mfa_schema_is_rejected_without_resetting_the_account() {
    let fixture = Fixture::new();
    block_on(fixture.begin());
    block_on(fixture.confirm());
    fixture
        .database
        .execute_sql("DROP TABLE nazo_local_migrations; DROP TABLE nazo_mfa_devices")
        .unwrap();
    assert!(fixture.database.execute_schema().is_err());
    assert!(fixture.enabled());
    assert_eq!(fixture.count("nazo_mfa_backup_codes"), 10);
}
