#![cfg(feature = "local-sqlite")]

mod support;

use std::sync::{Arc, Barrier};

use futures_executor::block_on;
use nazo_identity::{
    SessionId, TenantId, UserId,
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

        provider
            .update_authentication(tenant, user, &credential().id.to_b64url(), update())
            .await
            .unwrap();
        assert_eq!(
            provider.list_summaries(tenant, user).await.unwrap()[0].sign_count,
            8
        );
        assert_eq!(
            provider
                .update_authentication(tenant, user, &credential().id.to_b64url(), update())
                .await,
            Err(RepositoryError::Conflict)
        );
        assert_eq!(
            provider
                .update_authentication(
                    tenant,
                    user,
                    &credential().id.to_b64url(),
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
        assert!(provider.delete(tenant, user, row.id).await.is_err());
        assert_eq!(provider.list(tenant, user).await.unwrap().len(), 1);
        db.execute_sql("DROP TRIGGER fail_passkey_delete_audit")
            .unwrap();
        assert!(provider.delete(tenant, user, row.id).await.unwrap());
        assert!(!provider.delete(tenant, user, row.id).await.unwrap());
        assert!(provider.list(tenant, user).await.unwrap().is_empty());
    })
}

#[test]
fn concurrent_authentication_updates_have_one_cas_winner() {
    let (_, provider) = block_on(fixture());
    let tenant = TenantId::new(TENANT).unwrap();
    let user = UserId::new(USER).unwrap();
    block_on(provider.insert(tenant, user, credential(), "A".into())).unwrap();

    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(16));
    let winners = std::thread::scope(|scope| {
        let joins = (0..16)
            .map(|_| {
                let provider = Arc::clone(&provider);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.update_authentication(
                        tenant,
                        user,
                        &credential().id.to_b64url(),
                        update(),
                    ))
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
        let ticket = blake3::hash(b"valid secret never persisted").to_hex().to_string();
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
        assert!(provider.load(&SessionId::new("setup-replayed")).await.unwrap().is_none());
        // After first enrollment, no different setup ticket can issue a new login.
        provider.insert(tenant, user, credential(), "First".into()).await.unwrap();
        let other = blake3::hash(b"another secret").to_hex().to_string();
        assert!(
            !provider
                .claim_passkey_setup(&other, user, "setup-after-registration", now)
                .await
                .unwrap()
        );
    });
}
