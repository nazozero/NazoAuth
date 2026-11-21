#![cfg(feature = "local-sqlite")]

mod support;

use std::sync::{Arc, Barrier};

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AuthorizationRepositoryPort, DeviceAtomicResult, DeviceAuthorizationApproval,
    DeviceAuthorizationPayload, DeviceAuthorizationState, DeviceCreateResult, DeviceGrantPortError,
    DeviceGrantRepositoryPort, DeviceGrantService, DeviceGrantWrite, DevicePollCommit,
    DeviceStatePortError, DeviceStateReplacement, DeviceStateStorePort,
};
use nazo_identity::TenantId;
use nazo_identity::ports::AuthorizedApplicationRepositoryPort;
use nazo_oauth_server_d1::D1Provider;
use serde_json::json;
use support::{CLIENT, TENANT, USER, fixture};
use uuid::Uuid;

fn payload() -> DeviceAuthorizationPayload {
    let now = Timestamp::now();
    DeviceAuthorizationPayload {
        client_id: "client".into(),
        client_name: "Device client".into(),
        scopes: vec!["openid".into(), "profile".into()],
        resource_indicators: vec!["https://api.example".into()],
        authorization_details: json!([]),
        interval_seconds: 5,
        issued_at: now,
        expires_at: now + SignedDuration::from_secs(600),
    }
}

fn pending() -> DeviceAuthorizationState {
    DeviceAuthorizationState::Pending {
        payload: payload(),
        last_poll_at: None,
        slow_down_count: 0,
    }
}

fn hash(code: &str) -> String {
    blake3::hash(code.as_bytes()).to_hex().to_string()
}

fn grant<'a>(code: &'a str, payload: &'a DeviceAuthorizationPayload) -> DeviceGrantWrite<'a> {
    DeviceGrantWrite {
        device_code_hash: code,
        expires_at: payload.expires_at,
        tenant_id: TENANT,
        user_id: USER,
        client_id: CLIENT,
        scopes: &payload.scopes,
        resource_indicators: &payload.resource_indicators,
        authorization_details: &payload.authorization_details,
    }
}

#[test]
fn simultaneous_creation_preserves_both_unique_mappings_without_orphans() {
    let (_, provider) = block_on(fixture());
    let provider = Arc::new(provider);
    let state = Arc::new(pending());
    let barrier = Arc::new(Barrier::new(16));
    let results = std::thread::scope(|scope| {
        let joins = (0..16)
            .map(|index| {
                let provider = provider.clone();
                let state = state.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let device_code = format!("device-{index}");
                    let user_code = if index % 2 == 0 {
                        "user-code"
                    } else {
                        "UsEr CoDe"
                    };
                    barrier.wait();
                    let result =
                        block_on(provider.create(&device_code, user_code, &state, 600)).unwrap();
                    (device_code, result)
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| *result == DeviceCreateResult::Applied)
            .count(),
        1
    );
    for (code, result) in results {
        assert_eq!(
            block_on(provider.load_by_device_code(&code))
                .unwrap()
                .is_some(),
            result == DeviceCreateResult::Applied
        );
        if result == DeviceCreateResult::Applied {
            assert_eq!(
                block_on(provider.resolve_user_code("user-code")).unwrap(),
                Some(hash(&code))
            );
            assert_eq!(
                block_on(provider.create(&code, "unused-code", &state, 600)).unwrap(),
                DeviceCreateResult::DeviceCodeCollision
            );
            assert!(
                block_on(provider.resolve_user_code("unused-code"))
                    .unwrap()
                    .is_none()
            );
        } else {
            assert_eq!(result, DeviceCreateResult::UserCodeCollision);
        }
    }
}

#[test]
fn device_creation_and_completion_require_their_user_code_effects() {
    block_on(async {
        let (database, provider) = fixture().await;
        let state = pending();
        database.execute_sql("CREATE TRIGGER suppress BEFORE INSERT ON nazo_state WHEN NEW.kind='device_user' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .create("device", "user", &state, 600)
                .await
                .is_err()
        );
        assert!(
            provider
                .load_by_device_code("device")
                .await
                .unwrap()
                .is_none()
        );
        database.execute_sql("DROP TRIGGER suppress").unwrap();
        provider
            .create("device", "user", &state, 600)
            .await
            .unwrap();
        let snapshot = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        database.execute_sql("CREATE TRIGGER suppress BEFORE DELETE ON nazo_state WHEN OLD.kind='device_user' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .complete_decision(&hash("device"), "user", snapshot.version(), &state)
                .await
                .is_err()
        );
        assert_eq!(
            provider.resolve_user_code("user").await.unwrap(),
            Some(hash("device"))
        );
        assert_eq!(
            provider
                .load_by_device_code("device")
                .await
                .unwrap()
                .unwrap()
                .version(),
            snapshot.version()
        );
    });
}

#[test]
fn formatted_user_codes_share_lookup_claim_completion_and_delete_identity() {
    block_on(async {
        let (_, provider) = fixture().await;
        let state = pending();
        provider
            .create("device", "ABCD-EFGH", &state, 600)
            .await
            .unwrap();
        for user_code in ["ABCDEFGH", "abcd efgh", " aB-cD_eF.gH中 "] {
            assert_eq!(
                provider.resolve_user_code(user_code).await.unwrap(),
                Some(hash("device"))
            );
        }
        assert_eq!(
            provider
                .create("collision", "ab_cd efgh", &state, 600)
                .await
                .unwrap(),
            DeviceCreateResult::UserCodeCollision
        );
        assert!(
            provider
                .load_by_device_code("collision")
                .await
                .unwrap()
                .is_none()
        );
        let snapshot = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            provider
                .claim_decision(&hash("device"), "ab cd-efgh", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Applied
        );
        let snapshot = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            provider
                .complete_decision(&hash("device"), "ABCDEFGH", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Applied
        );
        assert!(
            provider
                .resolve_user_code("ABCD-EFGH")
                .await
                .unwrap()
                .is_none()
        );
        provider
            .create("delete-device", "AbCd-EfGh", &state, 600)
            .await
            .unwrap();
        assert_eq!(
            provider
                .delete_user_code_if_matches("ABCDEFGH", &hash("delete-device"))
                .await
                .unwrap(),
            DeviceAtomicResult::Applied
        );
        assert!(
            provider
                .resolve_user_code("abcd efgh")
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn replacement_is_versioned_preserves_expiry_and_is_tenant_scoped() {
    block_on(async {
        let (database, provider) = fixture().await;
        let state = pending();
        assert_eq!(
            provider
                .create("device", "user", &state, 600)
                .await
                .unwrap(),
            DeviceCreateResult::Applied
        );
        let snapshot = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        let other = D1Provider::new(
            database.clone(),
            TenantId::new(Uuid::from_u128(99)).unwrap(),
        );
        assert!(
            other
                .load_by_device_hash(&hash("device"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(other.resolve_user_code("user").await.unwrap().is_none());
        assert_eq!(
            other
                .replace_by_device_code("device", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Conflict
        );
        assert_eq!(
            other.create("device", "user", &state, 600).await.unwrap(),
            DeviceCreateResult::Applied
        );

        database.execute_sql("CREATE TRIGGER device_deadline_immutable BEFORE UPDATE ON nazo_state WHEN OLD.kind='device' AND NEW.expires_at<>OLD.expires_at BEGIN SELECT RAISE(ABORT,'device expiry changed'); END;").unwrap();
        let next = DeviceAuthorizationState::Pending {
            payload: payload(),
            last_poll_at: Some(Timestamp::now()),
            slow_down_count: 1,
        };
        let DeviceStateReplacement::Applied(version) = provider
            .replace_by_device_hash(&hash("device"), snapshot.version(), &next)
            .await
            .unwrap()
        else {
            panic!("expected replacement")
        };
        assert_eq!(
            provider
                .replace_by_device_code("device", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Conflict
        );
        let loaded = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.version(), &version);
        assert_eq!(loaded.state(), &next);
        database.execute_sql("DROP TRIGGER device_deadline_immutable; UPDATE nazo_state SET expires_at=unixepoch()-1 WHERE kind='device' OR kind='device_user';").unwrap();
        assert_eq!(
            provider
                .replace_by_device_code("device", &version, &state)
                .await
                .unwrap(),
            DeviceAtomicResult::DeadlineElapsed
        );
        assert!(
            provider
                .load_by_device_code("device")
                .await
                .unwrap()
                .is_none()
        );
        assert!(provider.resolve_user_code("user").await.unwrap().is_none());
        assert_eq!(
            provider
                .create("device", "user", &state, 600)
                .await
                .unwrap(),
            DeviceCreateResult::Applied
        );
        assert_eq!(
            provider
                .create("expired", "expired", &state, 0)
                .await
                .unwrap(),
            DeviceCreateResult::DeadlineElapsed
        );
    });
}

#[test]
fn concurrent_replacement_has_one_winner() {
    let (_, provider) = block_on(fixture());
    let provider = Arc::new(provider);
    let state = Arc::new(pending());
    block_on(provider.create("device", "user", &state, 600)).unwrap();
    let version = Arc::new(
        block_on(provider.load_by_device_code("device"))
            .unwrap()
            .unwrap()
            .version()
            .clone(),
    );
    let barrier = Arc::new(Barrier::new(16));
    let winners = std::thread::scope(|scope| {
        let joins = (0..16)
            .map(|_| {
                let provider = provider.clone();
                let state = state.clone();
                let version = version.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.replace_by_device_code("device", &version, &state)).unwrap()
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(|result| *result == DeviceAtomicResult::Applied)
            .count()
    });
    assert_eq!(winners, 1);
}

#[test]
fn decision_claim_and_completion_require_the_live_matching_user_code() {
    block_on(async {
        let (_, provider) = fixture().await;
        let state = pending();
        provider
            .create("device", "user", &state, 600)
            .await
            .unwrap();
        provider
            .create("second-device", "second-user", &state, 600)
            .await
            .unwrap();
        let snapshot = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            provider
                .claim_decision(&hash("device"), "second-user", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Conflict
        );
        assert_eq!(
            provider
                .delete_user_code_if_matches("user", &hash("second-device"))
                .await
                .unwrap(),
            DeviceAtomicResult::Conflict
        );
        assert_eq!(
            provider
                .claim_decision(&hash("device"), "user", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Applied
        );
        let snapshot = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            provider
                .complete_decision(&hash("device"), "user", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Applied
        );
        assert!(provider.resolve_user_code("user").await.unwrap().is_none());
        assert!(
            provider
                .resolve_user_code("second-user")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            provider
                .complete_decision(&hash("device"), "user", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Conflict
        );
        provider
            .create("third-device", "user", &state, 600)
            .await
            .unwrap();
        let snapshot = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            provider
                .claim_decision(&hash("device"), "user", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Conflict
        );
        assert_eq!(
            provider
                .delete_user_code_if_matches("user", &hash("device"))
                .await
                .unwrap(),
            DeviceAtomicResult::Conflict
        );
        assert_eq!(
            provider.resolve_user_code("user").await.unwrap(),
            Some(hash("third-device"))
        );
    });
}

#[test]
fn state_and_mapping_changes_roll_back_together() {
    block_on(async {
        let (database, provider) = fixture().await;
        let state = pending();
        database.execute_sql("CREATE TRIGGER reject_device_mapping BEFORE INSERT ON nazo_state WHEN NEW.kind='device_user' BEGIN SELECT RAISE(ABORT,'mapping unavailable'); END;").unwrap();
        assert_eq!(
            provider.create("device", "user", &state, 600).await,
            Err(DeviceStatePortError::Unavailable)
        );
        assert!(
            provider
                .load_by_device_code("device")
                .await
                .unwrap()
                .is_none()
        );
        database
            .execute_sql("DROP TRIGGER reject_device_mapping;")
            .unwrap();
        provider
            .create("device", "user", &state, 600)
            .await
            .unwrap();
        let snapshot = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        database.execute_sql("CREATE TRIGGER reject_device_completion BEFORE DELETE ON nazo_state WHEN OLD.kind='device_user' BEGIN SELECT RAISE(ABORT,'mapping unavailable'); END;").unwrap();
        assert_eq!(
            provider
                .complete_decision(&hash("device"), "user", snapshot.version(), &state)
                .await,
            Err(DeviceStatePortError::Unavailable)
        );
        let unchanged = provider
            .load_by_device_code("device")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.version(), unchanged.version());
        assert_eq!(
            provider.resolve_user_code("user").await.unwrap(),
            Some(hash("device"))
        );
        database
            .execute_sql("DROP TRIGGER reject_device_completion;")
            .unwrap();
        assert_eq!(
            provider
                .complete_decision(&hash("device"), "user", snapshot.version(), &state)
                .await
                .unwrap(),
            DeviceAtomicResult::Applied
        );
    });
}

#[test]
fn approval_receipt_cannot_recreate_a_revoked_grant_or_extend_its_deadline() {
    block_on(async {
        let (database, provider) = fixture().await;
        let mut request = payload();
        provider
            .upsert_grant(grant("device-hash", &request))
            .await
            .unwrap();
        assert_eq!(
            provider.grant(USER, CLIENT).await.unwrap().unwrap().scopes,
            serde_json::json!(request.scopes)
        );
        request.scopes = vec!["openid".into()];
        provider
            .upsert_grant(grant("device-hash", &request))
            .await
            .unwrap();
        assert_eq!(
            provider.grant(USER, CLIENT).await.unwrap().unwrap().scopes,
            serde_json::json!(["openid", "profile"])
        );
        database.execute_sql("DELETE FROM nazo_grants;").unwrap();
        provider
            .upsert_grant(grant("device-hash", &request))
            .await
            .unwrap();
        assert!(provider.grant(USER, CLIENT).await.unwrap().is_none());
        database
            .execute_sql("DELETE FROM nazo_state WHERE kind='device_decision';")
            .unwrap();
        request.expires_at = Timestamp::now() - SignedDuration::from_secs(1);
        assert_eq!(
            provider.upsert_grant(grant("device-hash", &request)).await,
            Err(DeviceGrantPortError::Conflict)
        );
        assert!(provider.grant(USER, CLIENT).await.unwrap().is_none());
    });
}

#[test]
fn grant_receipt_and_grant_are_atomic_with_current_principal_checks() {
    block_on(async {
        let (database, provider) = fixture().await;
        let request = payload();
        let mut wrong_tenant = grant("device-hash", &request);
        wrong_tenant.tenant_id = Uuid::from_u128(99);
        assert_eq!(
            provider.upsert_grant(wrong_tenant).await,
            Err(DeviceGrantPortError::CorruptData)
        );
        database
            .execute_sql("UPDATE nazo_users SET active=0;")
            .unwrap();
        assert_eq!(
            provider.upsert_grant(grant("device-hash", &request)).await,
            Err(DeviceGrantPortError::Unexpected)
        );
        database
            .execute_sql("UPDATE nazo_users SET active=1; UPDATE nazo_clients SET active=0;")
            .unwrap();
        assert_eq!(
            provider.upsert_grant(grant("device-hash", &request)).await,
            Err(DeviceGrantPortError::Unexpected)
        );
        database.execute_sql("UPDATE nazo_clients SET active=1; CREATE TRIGGER reject_device_grant BEFORE INSERT ON nazo_grants BEGIN SELECT RAISE(ABORT,'grant unavailable'); END;").unwrap();
        assert_eq!(
            provider.upsert_grant(grant("device-hash", &request)).await,
            Err(DeviceGrantPortError::Unavailable)
        );
        assert!(provider.grant(USER, CLIENT).await.unwrap().is_none());
        database
            .execute_sql("DROP TRIGGER reject_device_grant;")
            .unwrap();
        provider
            .upsert_grant(grant("device-hash", &request))
            .await
            .unwrap();
        let result = provider.grant(USER, CLIENT).await.unwrap().unwrap();
        assert_eq!(result.scopes, serde_json::json!(request.scopes));
        assert_eq!(
            result.resource_indicators,
            serde_json::json!(request.resource_indicators)
        );
        assert_eq!(result.authorization_details, request.authorization_details);
        database.execute_sql(&format!("CREATE TEMP TABLE valid_device_receipt(value INTEGER CHECK(value=1)); INSERT INTO valid_device_receipt SELECT expires_at*1000000>={} FROM nazo_state WHERE kind='device_decision';", request.expires_at.as_microsecond())).unwrap();
    });
}

#[test]
fn device_completion_records_history_once_and_rolls_back_ignored_effects() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER ignore_device_effect BEFORE INSERT ON nazo_audit WHEN NEW.event_type='device_grant_authorized' BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER ignore_device_effect BEFORE INSERT ON nazo_grants BEGIN SELECT RAISE(IGNORE); END;",
            "CREATE TRIGGER ignore_device_effect BEFORE INSERT ON nazo_grant_activity BEGIN SELECT RAISE(IGNORE); END;",
        ] {
            let (db, provider) = fixture().await;
            let request = payload();
            db.execute_sql(trigger).unwrap();
            assert!(
                provider
                    .upsert_grant(grant("device-history", &request))
                    .await
                    .is_err()
            );
            db.execute_sql(
                "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_grants)
                AND NOT EXISTS(SELECT 1 FROM nazo_state WHERE kind='device_decision')
                AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='device_grant_authorized')
                THEN 1 ELSE json_extract('device effects survived rollback','$') END;",
            )
            .unwrap();
            db.execute_sql("DROP TRIGGER ignore_device_effect").unwrap();
            provider
                .upsert_grant(grant("device-history", &request))
                .await
                .unwrap();
            provider
                .upsert_grant(grant("device-history", &request))
                .await
                .unwrap();
            let apps = provider
                .applications_for_user(TenantId::new(TENANT).unwrap(), USER)
                .await
                .unwrap();
            assert_eq!(apps.len(), 1);
            assert_eq!(apps[0].authorization_count, Some(1));
            assert!(apps[0].last_authorized_at.is_some());
            provider
                .upsert_grant(grant("different-device-history", &request))
                .await
                .unwrap();
            assert_eq!(
                provider
                    .applications_for_user(TenantId::new(TENANT).unwrap(), USER)
                    .await
                    .unwrap()[0]
                    .authorization_count,
                Some(2)
            );
        }
    });
}

#[test]
fn device_history_update_requires_the_exact_increment_even_at_the_same_timestamp() {
    block_on(async {
        let (db, provider) = fixture().await;
        let request = payload();
        provider
            .upsert_grant(grant("initial-history", &request))
            .await
            .unwrap();
        // Model two writes within SQLite's clock precision, while an ignored
        // counter update leaves the old positive count in place.
        db.execute_sql(
            "CREATE TRIGGER align_history_clock AFTER INSERT ON nazo_audit
            WHEN NEW.event_type='device_grant_authorized' BEGIN
              UPDATE nazo_grant_activity SET last_authorized_at=NEW.occurred_at;
            END;
            CREATE TRIGGER ignore_history_count BEFORE UPDATE ON nazo_grant_activity
            WHEN NEW.authorization_count<>OLD.authorization_count BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
        assert!(
            provider
                .upsert_grant(grant("next-history", &request))
                .await
                .is_err()
        );
        db.execute_sql("SELECT CASE WHEN (SELECT COUNT(*) FROM nazo_audit WHERE event_type='device_grant_authorized')=1
            AND (SELECT COUNT(*) FROM nazo_state WHERE kind='device_decision')=1
            THEN 1 ELSE json_extract('ignored history update committed','$') END;
            DROP TRIGGER align_history_clock; DROP TRIGGER ignore_history_count;").unwrap();
        provider
            .upsert_grant(grant("next-history", &request))
            .await
            .unwrap();
        assert_eq!(
            provider
                .applications_for_user(TenantId::new(TENANT).unwrap(), USER)
                .await
                .unwrap()[0]
                .authorization_count,
            Some(2)
        );
    });
}

#[test]
fn shared_device_service_preserves_approval_until_token_commit() {
    block_on(async {
        let (_, provider) = fixture().await;
        let service = DeviceGrantService::new(provider.clone());
        let request = payload();
        let (device_code, user_code) = service
            .create_unique(
                request.clone(),
                600,
                || "device".into(),
                || "ABCD-EFGH".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .poll(&device_code, "client", Timestamp::now)
                .await
                .unwrap(),
            DevicePollCommit::AuthorizationPending
        );
        assert_eq!(
            service
                .poll(&device_code, "client", Timestamp::now)
                .await
                .unwrap(),
            DevicePollCommit::SlowDown
        );
        // HTTP verification removes separators before calling the shared service.
        let prepared = service
            .prepare_decision("ABCDEFGH", Timestamp::now)
            .await
            .unwrap()
            .unwrap();
        let approval = DeviceAuthorizationApproval {
            user_id: USER,
            subject: USER.to_string(),
            auth_time: Timestamp::now().as_second(),
            amr: vec!["passkey".into(), "passkey_uv".into()],
            oidc_sid: Some("session".into()),
        };
        service
            .approve(
                &prepared,
                approval,
                &support::client(),
                &provider,
                Timestamp::now,
            )
            .await
            .unwrap();
        assert!(
            provider
                .resolve_user_code(&user_code)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            service
                .poll(&device_code, "client", Timestamp::now)
                .await
                .unwrap(),
            DevicePollCommit::Approved(_)
        ));
        assert!(matches!(
            service
                .poll(&device_code, "client", Timestamp::now)
                .await
                .unwrap(),
            DevicePollCommit::Approved(_)
        ));
        assert!(
            service
                .prepare_decision(&user_code, Timestamp::now)
                .await
                .unwrap()
                .is_none()
        );
        assert!(provider.grant(USER, CLIENT).await.unwrap().is_some());
    });
}
