use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nazo_key_management::{PersistedSigningKeyset, SigningKeyWrappingKeyRing};
use nazo_server_worker::WorkerSecrets;
use serde_json::json;

fn random_key() -> String {
    STANDARD.encode(
        URL_SAFE_NO_PAD
            .decode(nazo_oauth_server::crypto::random_urlsafe_token())
            .unwrap(),
    )
}

fn transition(previous_id: &str) -> WorkerSecrets {
    serde_json::from_value(json!({
        "previous_signing_wrapping_key": {
            "id": previous_id,
        },
    }))
    .unwrap()
}

fn single_key(id: &str, key: &str) -> SigningKeyWrappingKeyRing {
    WorkerSecrets::default()
        .take_signing_wrapping_keys(id.into(), key.into(), None)
        .unwrap()
}

#[test]
fn previous_wrapping_key_is_optional_private_and_consumed_at_host_composition() {
    let current = random_key();
    let previous = random_key();
    let empty: WorkerSecrets = serde_json::from_str("{}").unwrap();
    assert!(empty.previous_signing_wrapping_key.is_none());
    assert_eq!(single_key("current", &current).current_id(), "current");

    let mut secrets = transition("previous");
    secrets.email_relay_token = Some(nazo_oauth_server::crypto::random_urlsafe_token());
    let ring = secrets
        .take_signing_wrapping_keys("current".into(), current, Some(previous.clone()))
        .unwrap();
    assert_eq!(ring.current_id(), "current");
    assert!(secrets.previous_signing_wrapping_key.is_none());
    assert!(secrets.email_relay_token.is_some());

    // This material is not accepted in the public services object.
    assert!(
        serde_json::from_value::<nazo_server_worker::WorkerServices>(json!({
            "previous_signing_wrapping_key": { "id": "previous", "key_base64": previous },
        }))
        .is_err()
    );
}

#[test]
fn wrapping_configuration_rejects_bad_encoding_lengths_and_key_identifiers() {
    let key = random_key();
    let bytes = STANDARD.decode(&key).unwrap();
    let mut oversized = bytes.clone();
    oversized.push(bytes[0]);
    for malformed in [
        String::new(),
        "not base64!".into(),
        STANDARD.encode(&bytes[..31]),
        STANDARD.encode(oversized),
        URL_SAFE_NO_PAD.encode(&bytes),
    ] {
        assert!(
            WorkerSecrets::default()
                .take_signing_wrapping_keys("current".into(), malformed.clone(), None)
                .is_err()
        );
        assert!(
            transition("previous")
                .take_signing_wrapping_keys("current".into(), key.clone(), Some(malformed))
                .is_err()
        );
    }
    for invalid_id in [String::new(), " ".into(), "x".repeat(129)] {
        assert!(
            WorkerSecrets::default()
                .take_signing_wrapping_keys(invalid_id.clone(), key.clone(), None)
                .is_err()
        );
        assert!(
            transition(&invalid_id)
                .take_signing_wrapping_keys("current".into(), key.clone(), Some(random_key()))
                .is_err()
        );
    }
    assert!(
        transition("current")
            .take_signing_wrapping_keys("current".into(), key.clone(), Some(random_key()))
            .is_err()
    );
    for malformed in [
        json!({}),
        json!({"key_base64": key}),
        json!({"id": "previous", "key_base64": key}),
        json!({"id": "previous", "unexpected": true}),
    ] {
        assert!(
            serde_json::from_value::<WorkerSecrets>(json!({
                "previous_signing_wrapping_key": malformed,
            }))
            .is_err()
        );
    }
}

#[test]
fn previous_wrapping_key_requires_both_fixed_binding_and_identifier() {
    let current = random_key();
    assert!(
        transition("previous")
            .take_signing_wrapping_keys("current".into(), current.clone(), None)
            .is_err()
    );
    assert!(
        WorkerSecrets::default()
            .take_signing_wrapping_keys("current".into(), current, Some(random_key()))
            .is_err()
    );
}

#[test]
fn wrong_or_missing_previous_key_cannot_authenticate_a_generation() {
    let tenant = uuid::Uuid::new_v4();
    let previous_key = random_key();
    let current_key = random_key();
    let previous = single_key("previous", &previous_key);
    let metadata = json!({"fixture": "wrapping key authentication"});
    let record = PersistedSigningKeyset {
        revision: 1,
        encrypted_private_material: previous
            .seal_generation(tenant, 1, &metadata, b"generation payload")
            .unwrap(),
        public_metadata: metadata,
        wrapping_key_id: "previous".into(),
    };
    for ring in [
        single_key("current", &current_key),
        transition("previous")
            .take_signing_wrapping_keys("current".into(), current_key.clone(), Some(random_key()))
            .unwrap(),
        transition("different-id")
            .take_signing_wrapping_keys(
                "current".into(),
                current_key.clone(),
                Some(previous_key.clone()),
            )
            .unwrap(),
    ] {
        assert!(ring.open_generation(tenant, &mut record.clone()).is_err());
    }
    let ring = transition("previous")
        .take_signing_wrapping_keys("current".into(), current_key, Some(previous_key))
        .unwrap();
    assert!(ring.open_generation(tenant, &mut record.clone()).is_ok());
    assert!(
        ring.open_generation(uuid::Uuid::new_v4(), &mut record.clone())
            .is_err()
    );
    let mut changed = record;
    changed.revision += 1;
    assert!(ring.open_generation(tenant, &mut changed).is_err());
}

#[cfg(feature = "provisioning")]
#[test]
fn d1_transition_reseals_without_rotating_signing_material_then_removes_old_read_authority() {
    use nazo_key_management::{KeyManager, KeySettings};
    use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
    use nazo_oauth_server_d1::{D1Provider, Database};

    futures_executor::block_on(async {
        let tenant = nazo_identity::TenantId::new(uuid::Uuid::new_v4()).unwrap();
        let database = Database::in_memory().unwrap();
        database.execute_schema().unwrap();
        let provider = D1Provider::new(database, tenant);
        let repository = provider.signing_key_repository(tenant.as_uuid());
        let settings = KeySettings {
            rotation_interval: jiff::SignedDuration::from_hours(24 * 30),
            prepublish_window: jiff::SignedDuration::from_hours(24),
            verification_grace: jiff::SignedDuration::from_hours(24),
        };
        let previous_key = random_key();
        let current_key = random_key();
        let previous = single_key("previous", &previous_key);
        let old_manager = KeyManager::load_or_create_database(
            settings.clone(),
            None,
            tenant.as_uuid(),
            repository.clone(),
            previous.clone(),
        )
        .await
        .unwrap();
        let original_jwks = old_manager.snapshot().jwks();
        let original = repository.load().await.unwrap().unwrap();
        let original_digest = blake3::hash(
            previous
                .open_generation(tenant.as_uuid(), &mut original.clone())
                .unwrap(),
        );

        for invalid in [
            single_key("current", &current_key),
            transition("previous")
                .take_signing_wrapping_keys(
                    "current".into(),
                    current_key.clone(),
                    Some(random_key()),
                )
                .unwrap(),
        ] {
            assert!(
                KeyManager::load_database(
                    settings.clone(),
                    tenant.as_uuid(),
                    repository.clone(),
                    invalid,
                )
                .await
                .is_err()
            );
            let unchanged = repository.load().await.unwrap().unwrap();
            assert_eq!(unchanged.revision, original.revision);
            assert_eq!(unchanged.wrapping_key_id, "previous");
            assert!(unchanged.encrypted_private_material == original.encrypted_private_material);
        }

        let rollover = transition("previous")
            .take_signing_wrapping_keys(
                "current".into(),
                current_key.clone(),
                Some(previous_key.clone()),
            )
            .unwrap();
        let manager = KeyManager::load_database(
            settings.clone(),
            tenant.as_uuid(),
            repository.clone(),
            rollover,
        )
        .await
        .unwrap();
        let resealed = repository.load().await.unwrap().unwrap();
        assert_eq!(resealed.revision, original.revision + 1);
        assert_eq!(resealed.wrapping_key_id, "current");
        assert_eq!(resealed.public_metadata, original.public_metadata);
        assert_eq!(manager.snapshot().jwks(), original_jwks);
        assert!(resealed.encrypted_private_material != original.encrypted_private_material);
        assert!(
            previous
                .open_generation(tenant.as_uuid(), &mut resealed.clone())
                .is_err()
        );

        let current = single_key("current", &current_key);
        assert_eq!(
            blake3::hash(
                current
                    .open_generation(tenant.as_uuid(), &mut resealed.clone())
                    .unwrap()
            ),
            original_digest,
        );
        let new_only = KeyManager::load_database(
            settings.clone(),
            tenant.as_uuid(),
            repository.clone(),
            current,
        )
        .await
        .unwrap();
        new_only.refresh().await.unwrap();
        assert_eq!(new_only.snapshot().jwks(), original_jwks);
        assert_eq!(
            repository.load().await.unwrap().unwrap().revision,
            resealed.revision
        );

        // Restore the original wrapping binding through the same authenticated
        // transition without changing the signing keys.
        let restoring = transition("current")
            .take_signing_wrapping_keys("previous".into(), previous_key, Some(current_key))
            .unwrap();
        KeyManager::load_database(
            settings.clone(),
            tenant.as_uuid(),
            repository.clone(),
            restoring,
        )
        .await
        .unwrap();
        let restored = repository.load().await.unwrap().unwrap();
        assert_eq!(restored.revision, resealed.revision + 1);
        assert_eq!(restored.wrapping_key_id, "previous");
        let original_only =
            KeyManager::load_database(settings, tenant.as_uuid(), repository, previous)
                .await
                .unwrap();
        assert_eq!(original_only.snapshot().jwks(), original_jwks);
    });
}
