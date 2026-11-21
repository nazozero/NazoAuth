#![cfg(feature = "local-sqlite")]

mod support;

use std::sync::{Arc, Barrier};

use futures_executor::block_on;
use nazo_identity::{
    SessionId, SessionResolution, SessionService, TenantId, UserId,
    passkey::{StoredPasskeyAuthentication, StoredPasskeyRegistration, passkey_user_handle},
    ports::{
        PasskeyAccountRepositoryPort, PasskeyAuthenticationUpdate, PasskeyCeremonyPort,
        PasskeyRepositoryPort, RepositoryError, SessionStorePort,
    },
};
use nazo_passkey::{
    AttestationEvidence, CosePublicKey, CredentialId, CredentialUpdate,
    PasskeyCredential as WebauthnCredential, RegistrationOptions, Webauthn,
};
use support::{TENANT, USER, fixture};

fn credential() -> WebauthnCredential {
    WebauthnCredential {
        id: CredentialId(vec![7, 8, 9, 10]),
        public_key_cose: CosePublicKey(vec![0xa5, 0x01, 0x02]),
        counter: 7,
        transports: vec!["internal".into()],
        aaguid: [0u8; 16],
        user_handle: Some(
            passkey_user_handle(TenantId::new(TENANT).unwrap(), UserId::new(USER).unwrap())
                .to_vec(),
        ),
        uv_initialized: Some(true),
        backup_eligible: Some(true),
        backup_state: Some(false),
        attestation: AttestationEvidence::Unknown,
    }
}

fn update() -> PasskeyAuthenticationUpdate {
    PasskeyAuthenticationUpdate {
        credential: CredentialUpdate {
            expected_counter: 7,
            new_counter: 8,
            expected_backup_eligible: Some(true),
            backup_eligible: true,
            expected_backup_state: Some(false),
            backup_state: false,
        },
        initialize_user_verification: false,
    }
}

fn webauthn() -> Webauthn {
    Webauthn::new("auth.example.com", "NazoAuth", "https://auth.example.com")
}

#[test]
fn credential_registration_cas_and_lifecycle_audit_are_atomic() {
    block_on(async {
        let (db, provider) = fixture().await;
        let tenant = TenantId::new(TENANT).unwrap();
        let user = UserId::new(USER).unwrap();

        let account = provider
            .by_email(tenant, "test@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(account.user_id(), user);
        assert!(provider.by_id(tenant, user).await.unwrap().is_some());
        assert!(
            provider
                .by_email(tenant, "no@example.com")
                .await
                .unwrap()
                .is_none()
        );

        let row = provider
            .insert(tenant, user, credential(), "Laptop".into())
            .await
            .unwrap();
        assert_eq!(row.credential.id.to_b64url(), credential().id.to_b64url());
        assert_eq!(provider.list(tenant, user).await.unwrap().len(), 1);
        assert_eq!(
            provider.list_summaries(tenant, user).await.unwrap()[0].sign_count,
            7
        );
        assert_eq!(
            provider.credential_ids(tenant, user).await.unwrap().len(),
            1
        );
        assert!(
            provider
                .by_credential_id(tenant, user, &credential().id.to_b64url())
                .await
                .unwrap()
                .is_some()
        );

        // No success audit may survive a rejected duplicate credential.
        assert_eq!(
            provider
                .insert(tenant, user, credential(), "Duplicate".into())
                .await
                .unwrap_err(),
            RepositoryError::Conflict
        );
        assert_eq!(provider.list(tenant, user).await.unwrap().len(), 1);

        let observed = provider
            .by_credential_id(tenant, user, &credential().id.to_b64url())
            .await
            .unwrap()
            .unwrap();
        provider
            .update_authentication(&observed, update())
            .await
            .unwrap();
        assert_eq!(
            provider.list_summaries(tenant, user).await.unwrap()[0].sign_count,
            8
        );
        assert_eq!(
            provider.update_authentication(&observed, update()).await,
            Err(RepositoryError::Conflict)
        );
        let current = provider
            .by_credential_id(tenant, user, &credential().id.to_b64url())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            provider
                .update_authentication(
                    &current,
                    PasskeyAuthenticationUpdate {
                        credential: CredentialUpdate {
                            expected_counter: 8,
                            new_counter: 9,
                            expected_backup_eligible: Some(false),
                            backup_eligible: false,
                            expected_backup_state: Some(false),
                            backup_state: false
                        },
                        initialize_user_verification: false,
                    }
                )
                .await,
            Err(RepositoryError::Conflict)
        );
        db.execute_sql("CREATE TRIGGER fail_passkey_delete_audit BEFORE INSERT ON nazo_audit WHEN NEW.event_type='passkey_deleted' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END").unwrap();
        assert!(
            PasskeyRepositoryPort::delete(&provider, tenant, user, row.id)
                .await
                .is_err()
        );
        assert_eq!(provider.list(tenant, user).await.unwrap().len(), 1);
        db.execute_sql("DROP TRIGGER fail_passkey_delete_audit")
            .unwrap();
        assert!(
            PasskeyRepositoryPort::delete(&provider, tenant, user, row.id)
                .await
                .unwrap()
        );
        assert!(
            !PasskeyRepositoryPort::delete(&provider, tenant, user, row.id)
                .await
                .unwrap()
        );
        assert!(provider.list(tenant, user).await.unwrap().is_empty());
    })
}

#[test]
fn concurrent_authentication_updates_have_one_cas_winner() {
    let (_, provider) = block_on(fixture());
    let tenant = TenantId::new(TENANT).unwrap();
    let user = UserId::new(USER).unwrap();
    block_on(provider.insert(tenant, user, credential(), "A".into())).unwrap();

    let observed = Arc::new(
        block_on(provider.by_credential_id(tenant, user, &credential().id.to_b64url()))
            .unwrap()
            .unwrap(),
    );
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(16));
    let winners = std::thread::scope(|scope| {
        let joins = (0..16)
            .map(|_| {
                let provider = Arc::clone(&provider);
                let barrier = Arc::clone(&barrier);
                let observed = Arc::clone(&observed);
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.update_authentication(&observed, update()))
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(Result::is_ok)
            .count()
    });
    assert_eq!(winners, 1);
    assert_eq!(
        block_on(provider.list_summaries(tenant, user)).unwrap()[0].sign_count,
        8
    );
}

#[test]
fn registration_and_authentication_challenges_are_single_use_and_expire() {
    let (db, provider) = block_on(fixture());
    let tenant = TenantId::new(TENANT).unwrap();
    let user = UserId::new(USER).unwrap();
    let handle = passkey_user_handle(tenant, user);
    let (_, registration) = webauthn().start_registration(
        &handle,
        "test@example.com",
        "Test",
        &[],
        RegistrationOptions::default(),
    );
    let stored = StoredPasskeyRegistration {
        user_id: user,
        tenant_id: tenant,
        label: "Test key".into(),
        state: registration,
    };
    block_on(provider.store_registration("registration-id", &stored, 300)).unwrap();
    assert_eq!(
        block_on(provider.store_registration("registration-id", &stored, 300)),
        Err(RepositoryError::Conflict)
    );
    assert!(
        block_on(provider.take_registration("registration-id"))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(provider.take_registration("registration-id"))
            .unwrap()
            .is_none()
    );

    let (_, state) = webauthn().start_authentication_for_user(&handle, &[credential().id]);
    let stored_login = StoredPasskeyAuthentication {
        user_id: user,
        tenant_id: tenant,
        state,
        dummy: false,
    };
    block_on(provider.store_authentication("auth-id", &stored_login, 300)).unwrap();
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(16));
    let winners = std::thread::scope(|scope| {
        let joins = (0..16)
            .map(|_| {
                let provider = Arc::clone(&provider);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.take_authentication("auth-id"))
                        .unwrap()
                        .is_some()
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(|won| *won)
            .count()
    });
    assert_eq!(winners, 1);
    block_on(provider.store_authentication("expired", &stored_login, 300)).unwrap();
    db.execute_sql(
        "UPDATE nazo_state SET expires_at=unixepoch()-1 WHERE kind='passkey_authentication'",
    )
    .unwrap();
    assert!(
        block_on(provider.take_authentication("expired"))
            .unwrap()
            .is_none()
    );
    block_on(provider.store_authentication("expired", &stored_login, 300)).unwrap();
    assert!(
        block_on(provider.take_authentication("expired"))
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        block_on(provider.store_authentication("invalid-ttl", &stored_login, 301)),
        Err(RepositoryError::Consistency(_))
    ));
}

#[test]
fn offline_setup_grant_is_single_use_and_rolls_back_on_audit_failure() {
    block_on(async {
        let (db, provider) = fixture().await;
        let tenant = TenantId::new(TENANT).unwrap();
        let user = UserId::new(USER).unwrap();
        let ticket = "a".repeat(64);
        let now = jiff::Timestamp::now();

        db.execute_sql(
            "CREATE TRIGGER reject_setup_audit BEFORE INSERT ON nazo_audit WHEN NEW.event_type='passkey_setup_claimed' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END",
        )
        .unwrap();
        assert!(
            provider
                .claim_passkey_setup(&ticket, user, "setup-1", now)
                .await
                .is_err()
        );
        assert!(
            provider
                .load(&SessionId::new("setup-1"))
                .await
                .unwrap()
                .is_none()
        );
        db.execute_sql("DROP TRIGGER reject_setup_audit").unwrap();

        assert!(
            provider
                .claim_passkey_setup(&ticket, user, "setup-2", now)
                .await
                .unwrap()
        );
        let session = provider
            .load(&SessionId::new("setup-2"))
            .await
            .unwrap()
            .unwrap();
        assert!(session.record().amr().contains(&"bootstrap".to_owned()));
        let service = SessionService::new(
            Arc::new(provider.clone()),
            Arc::new(provider.clone()),
            tenant,
        );
        assert!(matches!(
            service
                .current(&SessionId::new("setup-2"), now.as_second())
                .await
                .unwrap(),
            SessionResolution::Missing
        ));
        assert!(matches!(
            service
                .current_principal(&SessionId::new("setup-2"), now.as_second())
                .await
                .unwrap(),
            SessionResolution::Missing
        ));
        assert!(matches!(
            service
                .current_for_passkey_enrollment(&SessionId::new("setup-2"), now.as_second())
                .await
                .unwrap(),
            SessionResolution::Present(_)
        ));
        assert!(
            !service
                .bind_client(&SessionId::new("setup-2"), "oidc-client")
                .await
                .unwrap()
        );

        assert!(
            nazo_identity::session::recent_credential_management_authentication(
                session.record().auth_time(),
                session.record().amr(),
                false,
                now.as_second(),
            )
        );
        assert!(
            !provider
                .claim_passkey_setup(&ticket, user, "setup-replayed", now)
                .await
                .unwrap()
        );
        assert!(
            provider
                .load(&SessionId::new("setup-replayed"))
                .await
                .unwrap()
                .is_none()
        );
        // After first enrollment, no different setup ticket can issue a new login.
        provider
            .insert(tenant, user, credential(), "First".into())
            .await
            .unwrap();
        let other = "b".repeat(64);
        assert!(
            !provider
                .claim_passkey_setup(&other, user, "setup-after-registration", now)
                .await
                .unwrap()
        );
    });
}

#[test]
fn offline_setup_rolls_back_ignored_session_or_required_audit_writes() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER ignore_setup BEFORE INSERT ON nazo_state WHEN NEW.kind='session' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TRIGGER ignore_setup BEFORE INSERT ON nazo_audit WHEN NEW.event_type='passkey_setup_claimed' BEGIN SELECT RAISE(IGNORE); END",
        ] {
            let (db, provider) = fixture().await;
            let user = UserId::new(USER).unwrap();
            let ticket = "a".repeat(64);
            let now = jiff::Timestamp::now();
            db.execute_sql(trigger).unwrap();
            assert!(
                provider
                    .claim_passkey_setup(&ticket, user, "setup-failed", now)
                    .await
                    .is_err()
            );
            assert!(
                provider
                    .load(&SessionId::new("setup-failed"))
                    .await
                    .unwrap()
                    .is_none()
            );
            db.execute_sql("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_state WHERE kind='passkey_setup_claim') AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='passkey_setup_claimed') THEN 1 ELSE json('partial setup survived rollback') END").unwrap();
            db.execute_sql("DROP TRIGGER ignore_setup").unwrap();
            assert!(
                provider
                    .claim_passkey_setup(&ticket, user, "setup-retry", now)
                    .await
                    .unwrap()
            );
        }
    });
}

#[test]
fn offline_setup_session_collision_preserves_the_ticket_and_existing_session() {
    block_on(async {
        let (db, provider) = fixture().await;
        let user = UserId::new(USER).unwrap();
        let now = jiff::Timestamp::now();
        assert!(
            provider
                .claim_passkey_setup(&"a".repeat(64), user, "setup-existing", now)
                .await
                .unwrap()
        );
        let existing = provider
            .load(&SessionId::new("setup-existing"))
            .await
            .unwrap()
            .unwrap();
        let ticket = "b".repeat(64);
        assert!(
            provider
                .claim_passkey_setup(&ticket, user, "setup-existing", now)
                .await
                .is_err()
        );
        let retained = provider
            .load(&SessionId::new("setup-existing"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.version(), existing.version());
        db.execute_sql("SELECT CASE WHEN (SELECT count(*) FROM nazo_state WHERE kind='passkey_setup_claim')=1 AND (SELECT count(*) FROM nazo_audit WHERE event_type='passkey_setup_claimed')=1 THEN 1 ELSE json('colliding setup consumed its ticket') END").unwrap();
        assert!(
            provider
                .claim_passkey_setup(&ticket, user, "setup-retry", now)
                .await
                .unwrap()
        );
    });
}

#[test]
fn offline_setup_session_tracks_the_current_account_epoch() {
    block_on(async {
        let (db, provider) = fixture().await;
        let tenant = TenantId::new(TENANT).unwrap();
        let user = UserId::new(USER).unwrap();
        let now = jiff::Timestamp::now();
        db.execute_sql("UPDATE nazo_users SET epoch=7").unwrap();
        assert!(
            provider
                .claim_passkey_setup(&"a".repeat(64), user, "setup-epoch", now)
                .await
                .unwrap()
        );
        let session_id = SessionId::new("setup-epoch");
        let session = provider.load(&session_id).await.unwrap().unwrap();
        assert_eq!(session.record().authorization_epoch(), 7);
        let service = SessionService::new(
            Arc::new(provider.clone()),
            Arc::new(provider.clone()),
            tenant,
        );
        assert!(matches!(
            service
                .current_for_passkey_enrollment(&session_id, now.as_second())
                .await
                .unwrap(),
            SessionResolution::Present(_)
        ));
        db.execute_sql("UPDATE nazo_users SET epoch=8").unwrap();
        assert!(matches!(
            service
                .current_for_passkey_enrollment(&session_id, now.as_second())
                .await
                .unwrap(),
            SessionResolution::Invalidated
        ));
        assert!(provider.load(&session_id).await.unwrap().is_none());
    });
}
