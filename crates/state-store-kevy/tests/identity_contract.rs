use std::{path::PathBuf, sync::Arc, time::Duration};

use jiff::{SignedDuration, Timestamp};
use nazo_identity::{
    AvatarUploadAuthorization, AvatarUploadClaim, OidcFederationState, SessionId,
    SessionRotationOutcome, SessionUpdateOutcome, TenantId, UserId,
    ports::{
        AvatarUploadStatePort, DeliveryConsume, DeliveryPublish, DeliveryStage,
        DeliveryStageResult, DeliveryStorePort, EmailVerificationConsume,
        EmailVerificationStorePort, FederationStatePort, LoginSessionCreate, LoginSessionPort,
        PasskeyCeremonyPort, PasswordHashInput, SessionStorePort,
    },
    session::{SessionRecord, UpstreamSession},
};
use nazo_kevy::{KevyBackend, TenantState};
use serde_json::json;
use tokio::sync::Barrier;
use uuid::Uuid;

struct Fixture {
    backend: Option<KevyBackend>,
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("nazo-kevy-identity-{}", Uuid::new_v4()));
        let backend = KevyBackend::open(&directory, "identity-contract").unwrap();
        Self {
            backend: Some(backend),
            directory,
        }
    }

    fn tenant(&self, id: u128) -> TenantState {
        self.backend
            .as_ref()
            .unwrap()
            .for_tenant(TenantId::new(Uuid::from_u128(id)).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.backend.take();
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn user() -> UserId {
    UserId::new(Uuid::from_u128(11)).unwrap()
}

fn session() -> SessionRecord {
    let mut record = SessionRecord::new(
        user(),
        7,
        Timestamp::now().as_second(),
        vec!["pwd".to_owned()],
        false,
        Some("sid".to_owned()),
    );
    record.record_authentication_at(Timestamp::now());
    record
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_rotation_and_replacement_publish_exactly_one_identity() {
    let fixture = Fixture::new();
    let store = fixture.tenant(1);
    let old = SessionId::new("old");
    let record = session();
    assert_eq!(
        LoginSessionPort::create(&store, "old", &record, 60)
            .await
            .unwrap(),
        LoginSessionCreate::Created
    );
    let snapshot = SessionStorePort::load(&store, &old).await.unwrap().unwrap();
    assert_eq!(snapshot.record(), &record);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for index in 0..16 {
        let store = store.clone();
        let old = old.clone();
        let expected = snapshot.version().clone();
        let record = record.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let id = SessionId::new(format!("new-{index}"));
            barrier.wait().await;
            let result = store
                .rotate(&old, &expected, &id, &record, 60)
                .await
                .unwrap();
            (id, result)
        }));
    }
    let mut winner = None;
    for task in tasks {
        let (id, result) = task.await.unwrap();
        if result == SessionRotationOutcome::Applied {
            assert!(winner.replace(id).is_none());
        } else {
            assert_eq!(result, SessionRotationOutcome::Conflict);
            assert!(SessionStorePort::load(&store, &id).await.unwrap().is_none());
        }
    }
    let winner = winner.unwrap();
    assert!(
        SessionStorePort::load(&store, &old)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .create_replacing(Some(winner.as_str()), "replacement", &record, 60)
            .await
            .unwrap(),
        LoginSessionCreate::Created
    );
    assert!(
        SessionStorePort::load(&store, &winner)
            .await
            .unwrap()
            .is_none()
    );
    let replacement = SessionId::new("replacement");
    assert!(
        SessionStorePort::load(&store, &replacement)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        SessionStorePort::load(&fixture.tenant(2), &replacement)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn session_update_keeps_expiry_and_upstream_cutoffs_never_regress() {
    let fixture = Fixture::new();
    let store = fixture.tenant(1);
    let id = SessionId::new("short");
    let mut record = session();
    LoginSessionPort::create(&store, id.as_str(), &record, 1)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let snapshot = SessionStorePort::load(&store, &id).await.unwrap().unwrap();
    record.add_logged_in_client("new-client".to_owned());
    assert_eq!(
        store
            .compare_and_set(&id, snapshot.version(), &record)
            .await
            .unwrap(),
        SessionUpdateOutcome::Applied
    );
    assert_eq!(
        store
            .compare_and_set(&id, snapshot.version(), &record)
            .await
            .unwrap(),
        SessionUpdateOutcome::Conflict
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(SessionStorePort::load(&store, &id).await.unwrap().is_none());

    let now = Timestamp::now().as_second();
    store
        .revoke_upstream("subject", now - 1, now + 120)
        .await
        .unwrap();
    record.set_upstream(Some(UpstreamSession {
        subject_key: "subject".to_owned(),
        sid_key: Some("upstream-sid".to_owned()),
        started_at: now - 5,
        expires_at: now + 120,
        encrypted_logout: None,
    }));
    LoginSessionPort::create(&store, "revoked", &record, 60)
        .await
        .unwrap();
    assert!(
        SessionStorePort::load(&store, &SessionId::new("revoked"))
            .await
            .unwrap()
            .is_none()
    );
    store
        .revoke_upstream("subject", now - 10, now + 30)
        .await
        .unwrap();
    assert!(
        SessionStorePort::load(&store, &SessionId::new("revoked"))
            .await
            .unwrap()
            .is_none()
    );
    let mut upstream = record.upstream().unwrap().clone();
    upstream.started_at = now;
    record.set_upstream(Some(upstream));
    LoginSessionPort::create(&store, "fresh", &record, 60)
        .await
        .unwrap();
    assert!(
        SessionStorePort::load(&store, &SessionId::new("fresh"))
            .await
            .unwrap()
            .is_some()
    );
    store
        .revoke_upstream("upstream-sid", i64::MAX, now + 120)
        .await
        .unwrap();
    assert!(
        SessionStorePort::load(&store, &SessionId::new("fresh"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn email_attempts_are_bounded_and_stale_owners_cannot_consume_or_clean_new_codes() {
    let fixture = Fixture::new();
    let store = fixture.tenant(1);
    let tenant = TenantId::new(Uuid::from_u128(1)).unwrap();
    let email = "person@example.com";
    assert!(
        store
            .reserve_email_send(tenant, email, "first", 60)
            .await
            .unwrap()
    );
    store
        .store_code(
            tenant,
            email,
            "first",
            PasswordHashInput::new("first-hash").unwrap(),
            60,
        )
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.reserve_code_attempt(tenant, email, 3).await.unwrap()
        }));
    }
    let mut reservations = Vec::new();
    for task in tasks {
        if let Some(record) = task.await.unwrap() {
            reservations.push(record);
        }
    }
    assert_eq!(reservations.len(), 3);
    assert!(
        reservations
            .iter()
            .all(|record| record.opaque_version == reservations[0].opaque_version)
    );
    let old_version = &reservations[0].opaque_version;
    store
        .release_email_send(tenant, email, "first")
        .await
        .unwrap();
    assert!(
        store
            .reserve_email_send(tenant, email, "second", 60)
            .await
            .unwrap()
    );
    store
        .store_code(
            tenant,
            email,
            "second",
            PasswordHashInput::new("second-hash").unwrap(),
            60,
        )
        .await
        .unwrap();
    store.delete_code(tenant, email, "first").await.unwrap();
    store
        .release_email_send(tenant, email, "first")
        .await
        .unwrap();
    assert!(
        !store
            .reserve_email_send(tenant, email, "third", 60)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .consume_code(tenant, email, old_version)
            .await
            .unwrap(),
        EmailVerificationConsume::MissingOrChanged
    );
    let current = store
        .reserve_code_attempt(tenant, email, 3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .consume_code(tenant, email, &current.opaque_version)
            .await
            .unwrap(),
        EmailVerificationConsume::Consumed
    );
    assert_eq!(
        store
            .consume_code(tenant, email, &current.opaque_version)
            .await
            .unwrap(),
        EmailVerificationConsume::MissingOrChanged
    );
    assert!(
        fixture
            .tenant(2)
            .reserve_code_attempt(tenant, email, 3)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federation_and_passkey_ceremonies_have_one_owner_and_one_consumer() {
    let fixture = Fixture::new();
    let store = fixture.tenant(1);
    let state = OidcFederationState {
        browser_binding_hash: Some("owner-browser".to_owned()),
        provider_id: Some("provider".to_owned()),
        nonce: "nonce-\"-\\-雪".to_owned(),
        pkce_verifier: "verifier".to_owned(),
        created_at: Timestamp::now().as_second(),
        discovery: None,
        link_intent: None,
    };
    store.store_oidc("state", &state, 60).await.unwrap();
    assert!(
        store
            .take_oidc("state", "wrong-browser")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .tenant(2)
            .take_oidc("state", "owner-browser")
            .await
            .unwrap()
            .is_none()
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.take_oidc("state", "owner-browser").await.unwrap()
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(value) = task.await.unwrap() {
            winners.push(value);
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(
        serde_json::to_value(&winners[0]).unwrap(),
        serde_json::to_value(&state).unwrap()
    );
    let ceremony: nazo_identity::StoredPasskeyRegistration = serde_json::from_value(json!({
        "tenant_id": TenantId::new(Uuid::from_u128(1)).unwrap(), "user_id": user(), "label": "Key",
        "state": { "challenge": vec![7_u8; 32], "user_id": vec![9_u8; 32], "created_at": 1 }
    }))
    .unwrap();
    store
        .store_registration("ceremony", &ceremony, 60)
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        store.take_registration("ceremony"),
        store.take_registration("ceremony")
    );
    assert_eq!(
        [left.unwrap(), right.unwrap()]
            .into_iter()
            .flatten()
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivery_requires_publication_and_exactly_one_matching_consumer() {
    let fixture = Fixture::new();
    let store = fixture.tenant(1);
    let make_stage = || DeliveryStage {
        attempt_id: Uuid::new_v4(),
        expires_at: Timestamp::now() + SignedDuration::from_secs(60),
        secret_binding: Some("bound".to_owned()),
        value: json!({"delivery_state":"staged", "client_secret":"secret"}),
    };
    let DeliveryStageResult::Created(staged) =
        store.stage(user(), "delivery", make_stage()).await.unwrap()
    else {
        panic!("first stage")
    };
    assert!(matches!(
        store.stage(user(), "delivery", make_stage()).await.unwrap(),
        DeliveryStageResult::Existing
    ));
    assert_eq!(
        store.consume(user(), "delivery", &staged).await.unwrap(),
        DeliveryConsume::MissingOrChanged
    );
    assert_eq!(
        store
            .publish(user(), "delivery", &staged, Uuid::from_u128(77))
            .await
            .unwrap(),
        DeliveryPublish::Published
    );
    assert!(!store.retire(user(), "delivery", &staged).await.unwrap());
    let committed = DeliveryStorePort::load(&store, user(), "delivery")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.value["delivery_state"], "committed");
    assert_eq!(committed.expires_at, staged.expires_at);
    assert!(
        DeliveryStorePort::load(&fixture.tenant(2), user(), "delivery")
            .await
            .unwrap()
            .is_none()
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        let committed = committed.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume(user(), "delivery", &committed).await.unwrap()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap() == DeliveryConsume::Consumed);
    }
    assert_eq!(winners, 1);
    assert!(
        DeliveryStorePort::load(&store, user(), "delivery")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn avatar_reclaim_fences_previous_owner_and_keeps_the_published_candidate() {
    let fixture = Fixture::new();
    let store = fixture.tenant(1);
    let authorization = AvatarUploadAuthorization {
        upload_id: "upload".to_owned(),
        tenant_id: TenantId::new(Uuid::from_u128(1)).unwrap(),
        user_id: user(),
        expected_avatar_url: None,
        expected_avatar_revision: 7,
        staging_object_id: "staged".to_owned(),
        expires_at: Timestamp::now() + SignedDuration::from_secs(60),
    };
    AvatarUploadStatePort::create(&store, &authorization, 60)
        .await
        .unwrap();
    let lease = Timestamp::now() + SignedDuration::from_secs(30);
    let AvatarUploadClaim::Pending {
        ownership_token: first,
        ..
    } = store.claim(user(), "upload", lease).await.unwrap()
    else {
        panic!("first claim")
    };
    assert_eq!(
        store.claim(user(), "upload", lease).await.unwrap(),
        AvatarUploadClaim::Busy
    );
    assert_eq!(
        store
            .claim(UserId::new(Uuid::from_u128(22)).unwrap(), "upload", lease)
            .await
            .unwrap(),
        AvatarUploadClaim::Missing
    );
    assert!(
        store
            .record_candidate(user(), "upload", &first, "etag", "final")
            .await
            .unwrap()
    );
    assert!(
        store
            .record_candidate(user(), "upload", &first, "etag", "final")
            .await
            .unwrap()
    );
    assert!(
        !store
            .record_candidate(user(), "upload", &first, "other-etag", "other-final")
            .await
            .unwrap()
    );
    assert!(store.release(user(), "upload", &first).await.unwrap());
    let AvatarUploadClaim::Publishing {
        ownership_token: second,
        staged_version,
        final_object_id,
        authorization: restored,
    } = store.claim(user(), "upload", lease).await.unwrap()
    else {
        panic!("resume published candidate")
    };
    assert_ne!(first, second);
    assert_eq!(staged_version, "etag");
    assert_eq!(final_object_id, "final");
    assert_eq!(restored, authorization);
    assert!(
        !store
            .complete(user(), "upload", &first, "final")
            .await
            .unwrap()
    );
    assert!(!store.release(user(), "upload", &first).await.unwrap());
    assert!(
        store
            .complete(user(), "upload", &second, "final")
            .await
            .unwrap()
    );
    assert!(
        store
            .complete(user(), "upload", &second, "final")
            .await
            .unwrap()
    );
    assert!(
        !store
            .complete(user(), "upload", &second, "different")
            .await
            .unwrap()
    );
    assert_eq!(
        store.claim(user(), "upload", lease).await.unwrap(),
        AvatarUploadClaim::Completed {
            final_object_id: "final".to_owned()
        }
    );
    assert_eq!(
        fixture
            .tenant(2)
            .claim(user(), "upload", lease)
            .await
            .unwrap(),
        AvatarUploadClaim::Missing
    );
}
