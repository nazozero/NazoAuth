use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    KeyManager, KeySettings, PersistedSigningKeyset, SealedKeyMaterial, SigningKeyRepository,
    SigningKeyRepositoryFuture, SigningKeyWrappingKeyError, SigningKeyWrappingKeyRing,
    SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
    test_support::MemorySigningKeyRepository,
};
use uuid::Uuid;

#[test]
fn encrypted_key_material_is_bound_to_its_tenant_and_purpose() {
    let ring = SigningKeyWrappingKeyRing::new("current", [7_u8; 32], None)
        .expect("test wrapping ring should be valid");
    let tenant = Uuid::now_v7();
    let sealed = ring
        .seal(tenant, "credential", b"private-key-material")
        .expect("material should seal");

    assert_eq!(
        ring.open(tenant, "credential", &sealed)
            .expect("matching scope should open"),
        b"private-key-material"
    );
    assert!(ring.open(Uuid::now_v7(), "credential", &sealed).is_err());
    assert!(ring.open(tenant, "presentation_request", &sealed).is_err());
}

#[test]
fn encrypted_generation_rejects_swapped_public_metadata() {
    let ring = SigningKeyWrappingKeyRing::new("current", [9_u8; 32], None).unwrap();
    let tenant = Uuid::now_v7();
    let metadata = serde_json::json!({"active_kid":"one","keys":[{"kid":"one"}]});
    let sealed = ring
        .seal_generation(tenant, 4, &metadata, b"private-generation")
        .unwrap();
    assert!(
        ring.open_generation(
            tenant,
            4,
            &serde_json::json!({"active_kid":"two","keys":[{"kid":"two"}]}),
            &sealed,
        )
        .is_err()
    );
}

#[test]
fn wrapping_key_ring_rejects_invalid_ids_and_malformed_material() {
    assert_eq!(
        SigningKeyWrappingKeyRing::new("", [0_u8; 32], None).err(),
        Some(SigningKeyWrappingKeyError::EmptyId)
    );
    assert_eq!(
        SigningKeyWrappingKeyRing::new("x".repeat(129), [0_u8; 32], None).err(),
        Some(SigningKeyWrappingKeyError::IdTooLong)
    );
    assert_eq!(
        SigningKeyWrappingKeyRing::new("same", [0_u8; 32], Some(("same".to_owned(), [1_u8; 32])))
            .err(),
        Some(SigningKeyWrappingKeyError::DuplicateId)
    );

    let ring = SigningKeyWrappingKeyRing::new(
        "current",
        [2_u8; 32],
        Some(("previous".to_owned(), [3_u8; 32])),
    )
    .unwrap();
    let tenant = Uuid::now_v7();
    let sealed = ring.seal(tenant, "test", b"private-material").unwrap();
    assert_eq!(
        ring.open(tenant, "test", &sealed).unwrap(),
        b"private-material"
    );

    let unknown_key = SealedKeyMaterial {
        wrapping_key_id: "removed".to_owned(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext.clone(),
    };
    assert!(ring.open(tenant, "test", &unknown_key).is_err());

    let short_ciphertext = SealedKeyMaterial {
        wrapping_key_id: sealed.wrapping_key_id.clone(),
        nonce: sealed.nonce,
        ciphertext: vec![0_u8; 15],
    };
    assert!(ring.open(tenant, "test", &short_ciphertext).is_err());
    assert!(SealedKeyMaterial::from_persisted_bytes("current".to_owned(), &[0_u8; 11]).is_err());
    assert!(
        ring.open_generation(
            tenant,
            1,
            &serde_json::json!({"active_kid":"active"}),
            &short_ciphertext,
        )
        .is_err()
    );
}

struct DiagnosticRepository {
    inner: Arc<MemorySigningKeyRepository>,
    writes: AtomicUsize,
}

impl SigningKeyRepository for DiagnosticRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        self.inner.load()
    }

    fn create_if_absent(
        &self,
        _candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { anyhow::bail!("diagnostics cannot initialize keys") })
    }

    fn compare_and_swap(
        &self,
        _expected: i64,
        _candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { anyhow::bail!("diagnostics cannot maintain keys") })
    }
}

#[tokio::test]
async fn database_diagnostics_reject_missing_keys_without_initializing_them() {
    let repository = Arc::new(DiagnosticRepository {
        inner: Arc::new(MemorySigningKeyRepository::default()),
        writes: AtomicUsize::new(0),
    });
    assert!(
        KeyManager::inspect_database(
            None,
            Uuid::now_v7(),
            repository.clone(),
            SigningKeyWrappingKeyRing::new("current", [0x62; 32], None).unwrap(),
        )
        .await
        .is_err()
    );
    assert!(repository.inner.snapshot().is_none());
    assert_eq!(repository.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn database_diagnostics_reject_invalid_creation_times_without_writing() {
    let inner = Arc::new(MemorySigningKeyRepository::default());
    let tenant = Uuid::now_v7();
    let ring = SigningKeyWrappingKeyRing::new("current", [0x62; 32], None).unwrap();
    KeyManager::load_or_create_database(
        KeySettings {
            rotation_interval: chrono::Duration::days(90),
            prepublish_window: chrono::Duration::days(1),
            verification_grace: chrono::Duration::minutes(10),
        },
        None,
        tenant,
        inner.clone(),
        ring.clone(),
    )
    .await
    .unwrap();
    let valid = decrypted_payload(&inner, tenant, &ring);
    let active = valid["active_kid"].as_str().unwrap().to_owned();
    let repository = Arc::new(DiagnosticRepository {
        inner: inner.clone(),
        writes: AtomicUsize::new(0),
    });

    for created_at in [None, Some(serde_json::json!("bad")), Some(serde_json::json!(7))] {
        let mut payload = valid.clone();
        let entry = payload["keys"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["kid"].as_str() == Some(active.as_str()))
            .unwrap();
        match created_at {
            Some(value) => entry["created_at"] = value,
            None => {
                entry.as_object_mut().unwrap().remove("created_at");
            }
        }
        // Authenticate the malformed payload; this is not an AEAD failure.
        replace_payload(&inner, tenant, &ring, payload);
        let before = inner.snapshot().unwrap();
        let error = KeyManager::inspect_database(None, tenant, repository.clone(), ring.clone())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("created_at"));
        let after = inner.snapshot().unwrap();
        assert_eq!(after.revision, before.revision);
        assert!(after.public_metadata == before.public_metadata);
        assert!(after.encrypted_private_material == before.encrypted_private_material);
        assert_eq!(after.wrapping_key_id, before.wrapping_key_id);
        assert_eq!(repository.writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn database_diagnostics_leave_due_old_wrapping_generation_unchanged_and_reject_tampering() {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let inner = Arc::new(MemorySigningKeyRepository::default());
    let tenant = Uuid::now_v7();
    let old = SigningKeyWrappingKeyRing::new("old", [0x63; 32], None).unwrap();
    KeyManager::load_or_create_database(settings, None, tenant, inner.clone(), old.clone())
        .await
        .unwrap();
    let mut payload = decrypted_payload(&inner, tenant, &old);
    let active = payload["active_kid"].as_str().unwrap().to_owned();
    let entry = payload["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["kid"].as_str() == Some(active.as_str()))
        .unwrap();
    entry["created_at"] =
        serde_json::json!((chrono::Utc::now() - chrono::Duration::days(180)).to_rfc3339());
    replace_payload(&inner, tenant, &old, payload);
    let before = inner.snapshot().unwrap();
    let rollover =
        SigningKeyWrappingKeyRing::new("new", [0x64; 32], Some(("old".to_owned(), [0x63; 32])))
            .unwrap();
    let repository = Arc::new(DiagnosticRepository {
        inner: inner.clone(),
        writes: AtomicUsize::new(0),
    });
    let (first, second) = tokio::join!(
        KeyManager::inspect_database(None, tenant, repository.clone(), rollover.clone()),
        KeyManager::inspect_database(None, tenant, repository.clone(), rollover.clone()),
    );
    for result in [first, second] {
        let (records, revision) = result.unwrap();
        assert_eq!(revision, before.revision.to_string());
        assert!(records.iter().any(|record| record.kid == active));
    }
    let after = inner.snapshot().unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.public_metadata, before.public_metadata);
    assert_eq!(
        after.encrypted_private_material,
        before.encrypted_private_material
    );
    assert_eq!(after.wrapping_key_id, "old");
    assert_eq!(repository.writes.load(Ordering::SeqCst), 0);

    let mut tampered = before;
    tampered.public_metadata["active_kid"] = serde_json::json!("tampered");
    inner.replace(Some(tampered));
    assert!(
        KeyManager::inspect_database(None, tenant, repository.clone(), rollover)
            .await
            .is_err()
    );
    assert_eq!(repository.writes.load(Ordering::SeqCst), 0);
}

struct ConflictRepository {
    inner: MemorySigningKeyRepository,
    conflicts_remaining: AtomicUsize,
}

impl ConflictRepository {
    fn with_conflicts(conflicts: usize) -> Self {
        Self {
            inner: MemorySigningKeyRepository::default(),
            conflicts_remaining: AtomicUsize::new(conflicts),
        }
    }
}

impl SigningKeyRepository for ConflictRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        self.inner.load()
    }

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        self.inner.create_if_absent(candidate)
    }

    fn compare_and_swap(
        &self,
        expected: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            let current = self.inner.load().await?.expect("keyset exists before CAS");
            if self
                .conflicts_remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    if remaining > 0 {
                        Some(remaining - 1)
                    } else {
                        None
                    }
                })
                .is_ok()
            {
                return Ok(SigningKeysetCompareAndSwapResult::Conflict(current));
            }
            self.inner.compare_and_swap(expected, candidate).await
        })
    }
}

fn decrypted_payload(
    repository: &MemorySigningKeyRepository,
    tenant: Uuid,
    ring: &SigningKeyWrappingKeyRing,
) -> serde_json::Value {
    let record = repository.snapshot().unwrap();
    let sealed = SealedKeyMaterial::from_persisted_bytes(
        record.wrapping_key_id,
        &record.encrypted_private_material,
    )
    .unwrap();
    serde_json::from_slice(
        &ring
            .open_generation(tenant, record.revision, &record.public_metadata, &sealed)
            .unwrap(),
    )
    .unwrap()
}

fn replace_payload(
    repository: &MemorySigningKeyRepository,
    tenant: Uuid,
    ring: &SigningKeyWrappingKeyRing,
    payload: serde_json::Value,
) {
    let mut record = repository.snapshot().unwrap();
    let mut public_metadata = payload.clone();
    public_metadata
        .as_object_mut()
        .unwrap()
        .remove("request_object_private_pem");
    for key in public_metadata["keys"].as_array_mut().unwrap() {
        key.as_object_mut().unwrap().remove("private_pkcs8_der");
    }
    let sealed = ring
        .seal_generation(
            tenant,
            record.revision,
            &public_metadata,
            &serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
    record.public_metadata = public_metadata;
    record.encrypted_private_material = sealed.into_persisted_bytes();
    record.wrapping_key_id = ring.current_id().to_owned();
    repository.replace(Some(record));
}

#[tokio::test]
async fn two_managers_share_database_keyset_without_writing_key_files() {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let ring = SigningKeyWrappingKeyRing::new("current", [3_u8; 32], None).unwrap();
    let tenant = Uuid::now_v7();
    let (first, second) = tokio::join!(
        KeyManager::load_or_create_database(
            settings.clone(),
            None,
            tenant,
            repository.clone(),
            ring.clone()
        ),
        KeyManager::load_or_create_database(settings, None, tenant, repository.clone(), ring),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.snapshot().active_kid, second.snapshot().active_kid);
    assert_eq!(repository.load().await.unwrap().unwrap().revision, 1);
}

#[tokio::test]
async fn database_registration_converges_and_survives_restart_without_files() {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let ring = SigningKeyWrappingKeyRing::new("current", [4_u8; 32], None).unwrap();
    let tenant = Uuid::now_v7();
    let first = KeyManager::load_or_create_database(
        settings.clone(),
        None,
        tenant,
        repository.clone(),
        ring.clone(),
    )
    .await
    .unwrap();
    let purposes: std::collections::BTreeSet<_> = [
        nazo_auth::SigningPurpose::Credential,
        nazo_auth::SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect();
    let (first_kid, second_kid) = tokio::join!(
        first.database_register_local(crate::LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: purposes.clone()
        }),
        KeyManager::load_or_create_database(
            settings.clone(),
            None,
            tenant,
            repository.clone(),
            ring.clone()
        ),
    );
    let first_kid = first_kid.unwrap();
    let second = second_kid.unwrap();
    let records = second.database_list_keys().await.unwrap();
    assert!(
        records
            .iter()
            .any(|record| record.kid == first_kid && record.backend == "local-db")
    );
    let restarted =
        KeyManager::load_or_create_database(settings, None, tenant, repository.clone(), ring)
            .await
            .unwrap();
    assert_eq!(
        restarted
            .database_register_local(crate::LocalKeyRegistration {
                algorithm: jsonwebtoken::Algorithm::ES256,
                purposes
            })
            .await
            .unwrap(),
        first_kid
    );
    assert_eq!(repository.load().await.unwrap().unwrap().revision, 2);
}

#[tokio::test]
async fn database_startup_maintains_an_overdue_keyset_before_it_is_ready() {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant = Uuid::now_v7();
    let ring = SigningKeyWrappingKeyRing::new("current", [10_u8; 32], None).unwrap();
    let manager = KeyManager::load_or_create_database(
        settings.clone(),
        None,
        tenant,
        repository.clone(),
        ring.clone(),
    )
    .await
    .unwrap();
    let revision = repository.load().await.unwrap().unwrap().revision;
    let mut payload = decrypted_payload(&repository, tenant, &ring);
    let active_kid = manager.snapshot().active_kid.clone();
    payload["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|key| key["kid"] == active_kid)
        .unwrap()["created_at"] = serde_json::json!(
        (chrono::Utc::now() - chrono::Duration::days(91))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    replace_payload(&repository, tenant, &ring, payload);

    let restarted =
        KeyManager::load_or_create_database(settings, None, tenant, repository.clone(), ring)
            .await
            .unwrap();
    assert_eq!(
        repository.load().await.unwrap().unwrap().revision,
        revision + 1
    );
    let records = restarted.database_list_keys().await.unwrap();
    let prepublished = records
        .iter()
        .find(|record| record.status == crate::KeyRecordStatus::Prepublished)
        .expect("startup must publish a rotation candidate before readiness");
    assert!(
        restarted
            .snapshot()
            .verification_key(&prepublished.kid)
            .is_some()
    );
}

#[tokio::test]
async fn expired_database_key_remains_encrypted_but_is_not_advertised_or_verifiable() {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::seconds(-1),
        prepublish_window: chrono::Duration::zero(),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant = Uuid::now_v7();
    let ring = SigningKeyWrappingKeyRing::new("current", [11_u8; 32], None).unwrap();
    let manager = KeyManager::load_or_create_database(
        settings.clone(),
        None,
        tenant,
        repository.clone(),
        ring.clone(),
    )
    .await
    .unwrap();
    let retired_kid = manager.snapshot().active_kid.clone();
    manager.refresh().await.unwrap();
    let mut payload = decrypted_payload(&repository, tenant, &ring);
    payload["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|key| key["kid"] == retired_kid)
        .unwrap()["retire_at"] = serde_json::json!(
        (chrono::Utc::now() - chrono::Duration::seconds(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    replace_payload(&repository, tenant, &ring, payload);

    let restarted =
        KeyManager::load_or_create_database(settings, None, tenant, repository.clone(), ring)
            .await
            .unwrap();
    assert!(
        repository.load().await.unwrap().unwrap().public_metadata["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key["kid"] == retired_kid)
    );
    assert!(
        restarted
            .snapshot()
            .verification_key(&retired_kid)
            .is_none()
    );
    assert!(
        restarted.snapshot().jwks()["keys"]
            .as_array()
            .unwrap()
            .iter()
            .all(|key| key["kid"] != retired_kid)
    );
    assert_eq!(
        restarted
            .database_list_keys()
            .await
            .unwrap()
            .into_iter()
            .find(|record| record.kid == retired_kid)
            .unwrap()
            .status,
        crate::KeyRecordStatus::Retired
    );
}

#[tokio::test]
async fn refresh_reseals_an_old_generation_before_previous_wrapping_key_is_removed() {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant = Uuid::now_v7();
    let old = SigningKeyWrappingKeyRing::new("old", [6_u8; 32], None).unwrap();
    KeyManager::load_or_create_database(settings.clone(), None, tenant, repository.clone(), old)
        .await
        .unwrap();
    let rollover =
        SigningKeyWrappingKeyRing::new("new", [7_u8; 32], Some(("old".to_owned(), [6_u8; 32])))
            .unwrap();
    let manager = KeyManager::load_or_create_database(
        settings.clone(),
        None,
        tenant,
        repository.clone(),
        rollover,
    )
    .await
    .unwrap();
    manager.refresh().await.unwrap();
    assert_eq!(
        repository.load().await.unwrap().unwrap().wrapping_key_id,
        "new"
    );
    KeyManager::load_or_create_database(
        settings,
        None,
        tenant,
        repository,
        SigningKeyWrappingKeyRing::new("new", [7_u8; 32], None).unwrap(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn database_update_retries_compare_and_swap_conflicts_before_applying() {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(ConflictRepository::with_conflicts(2));
    let manager = KeyManager::load_or_create_database(
        settings,
        None,
        Uuid::now_v7(),
        repository.clone(),
        SigningKeyWrappingKeyRing::new("current", [12_u8; 32], None).unwrap(),
    )
    .await
    .unwrap();

    let kid = manager
        .database_register_local(crate::LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [nazo_auth::SigningPurpose::Credential]
                .into_iter()
                .collect(),
        })
        .await
        .expect("a bounded number of repository conflicts should converge");
    assert!(kid.starts_with("es256-"));
    assert_eq!(repository.load().await.unwrap().unwrap().revision, 2);
}

#[tokio::test]
async fn database_update_stops_after_the_cas_conflict_budget() {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::minutes(10),
    };
    let repository = Arc::new(ConflictRepository::with_conflicts(8));
    let manager = KeyManager::load_or_create_database(
        settings,
        None,
        Uuid::now_v7(),
        repository.clone(),
        SigningKeyWrappingKeyRing::new("current", [13_u8; 32], None).unwrap(),
    )
    .await
    .unwrap();

    let error = manager
        .database_register_local(crate::LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [nazo_auth::SigningPurpose::Credential]
                .into_iter()
                .collect(),
        })
        .await
        .expect_err("an unbounded conflict stream must fail closed");
    let unavailable = error
        .downcast_ref::<crate::SigningKeyRepositoryUnavailable>()
        .expect("exhausted CAS conflicts must remain a typed persistence failure");
    assert!(unavailable.0.to_string().contains("did not converge"));
    assert_eq!(
        AtomicUsize::load(&repository.conflicts_remaining, Ordering::Acquire),
        0
    );
    assert_eq!(repository.load().await.unwrap().unwrap().revision, 1);
}
