use super::*;
use crate::{
    db::{key, read},
    users::create_user_tx,
};
use jiff::{SignedDuration, Timestamp};
use nazo_identity::{
    TenantContext, UserRole,
    ports::{NewUser, PasswordHashInput},
};
use nazo_openid4vci::CredentialStoreError;
use nazo_openid4vp::*;
use nazo_persistence::{ManagedCredentialDatasetWrite, Openid4vciDatasetStore};
use serde_json::json;
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

struct Fixture {
    db: Option<RocksDb>,
    path: PathBuf,
    actor: Uuid,
    subject: Uuid,
}
impl Fixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("nazo-rocksdb-credentials-{}", Uuid::new_v4()));
        let db = RocksDb::open(&path).unwrap();
        let tx = db.transaction();
        let user = |name: &str, role| {
            create_user_tx(
                &tx,
                NewUser {
                    tenant: TenantContext::default_system(),
                    username: name.into(),
                    email: format!("{name}@example.test"),
                    password_hash: PasswordHashInput::new("test-verifier").unwrap(),
                    email_verified: true,
                },
                role,
            )
            .unwrap()
            .principal
            .user_id
            .as_uuid()
        };
        let actor = user("admin", UserRole::Admin { level: 1 });
        let subject = user("subject", UserRole::User);
        tx.commit().unwrap();
        Self {
            db: Some(db),
            path,
            actor,
            subject,
        }
    }
    fn db(&self) -> &RocksDb {
        self.db.as_ref().unwrap()
    }
    fn write(&self, configuration: &str) -> ManagedCredentialDatasetWrite {
        ManagedCredentialDatasetWrite {
            tenant_id: self.db().tenant_id,
            actor_user_id: self.actor,
            subject_id: self.subject,
            credential_configuration_id: configuration.into(),
            claims: json!({"private":"dataset-value"}),
            valid_from: None,
            valid_until: None,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.db.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test]
async fn datasets_encrypt_bind_owner_and_roll_back_required_audit() {
    let fixture = Fixture::new();
    let store = datasets::DatasetStore::new(fixture.db().clone(), [9; 32]);
    let write = fixture.write("identity");
    let view = store
        .upsert_managed_dataset(write.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.claims, write.claims);
    let tenant = fixture.db().tenant_id;
    assert_eq!(
        store
            .dataset(tenant, fixture.subject, "identity")
            .await
            .unwrap(),
        Some(write.claims)
    );
    assert_eq!(
        store
            .dataset(Uuid::new_v4(), fixture.subject, "identity")
            .await
            .unwrap(),
        None
    );
    let mut row_key = key(0xdc, tenant, fixture.subject.as_bytes());
    row_key.extend_from_slice(b"identity");
    let raw = fixture.db().db.get_pinned(&row_key).unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("dataset-value"));
    drop(raw);
    let invalid_write = fixture.write(&"x".repeat(70_000));
    assert_eq!(
        store.upsert_managed_dataset(invalid_write.clone()).await,
        Err(CredentialStoreError::InvalidTransition)
    );
    assert!(
        store
            .managed_dataset(
                tenant,
                fixture.subject,
                &invalid_write.credential_configuration_id
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .delete_managed_dataset(tenant, fixture.subject, fixture.subject, "identity")
            .await
            .unwrap()
    );
    assert!(
        store
            .delete_managed_dataset(tenant, fixture.actor, fixture.subject, "identity")
            .await
            .unwrap()
    );
    assert!(
        store
            .dataset(tenant, fixture.subject, "identity")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn operator_dataset_ownership_and_ciphertext_aad_cannot_be_rebound() {
    let fixture = Fixture::new();
    let tenant = fixture.db().tenant_id;
    let store = datasets::DatasetStore::new(fixture.db().clone(), [9; 32]);
    let tx = fixture.db().transaction();
    datasets::write_managed_dataset_tx(
        &tx,
        &[9; 32],
        TenantContext::default_system(),
        fixture.subject,
        "identity",
        &json!({"owned":true}),
        Timestamp::now(),
        None,
        "operator_control",
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(
        store
            .upsert_managed_dataset(fixture.write("identity"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .delete_managed_dataset(tenant, fixture.actor, fixture.subject, "identity")
            .await
            .unwrap()
    );
    let mut original = key(0xdc, tenant, fixture.subject.as_bytes());
    original.extend_from_slice(b"identity");
    let mut rebound = key(0xdc, tenant, fixture.actor.as_bytes());
    rebound.extend_from_slice(b"identity");
    let tx = fixture.db().transaction();
    tx.put(&rebound, tx.get_pinned(&original).unwrap().unwrap())
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        store
            .managed_dataset(tenant, fixture.actor, "identity")
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );
}

fn presentation() -> PresentationTransaction {
    let now = Timestamp::now();
    PresentationTransaction {
        id: Uuid::new_v4(),
        client_id_prefix: ClientIdPrefix::RedirectUri,
        request_method: RequestMethod::UrlQuery,
        wallet_authorization_endpoint: "https://wallet.example/authorize".into(),
        request: AuthorizationRequest {
            client_id: "redirect_uri:https://verifier.example/response".into(),
            response_type: "vp_token".into(),
            response_mode: ResponseMode::DirectPost,
            response_uri: "https://verifier.example/response".into(),
            nonce: "nonce".into(),
            state: Uuid::new_v4().to_string(),
            dcql_query: nazo_digital_credentials::DcqlQuery {
                credentials: Vec::new(),
                credential_sets: None,
            },
            client_metadata: None,
            verifier_info: None,
            transaction_data: None,
            wallet_nonce: None,
        },
        request_object: None,
        request_uri: None,
        openid4vc_trust_policy_binding_id: None,
        openid4vc_trust_policy_resource_id: None,
        openid4vc_trust_policy_digest: None,
        response_encryption_private_key: Some([7; 32]),
        created_at: now,
        expires_at: now + SignedDuration::from_mins(10),
    }
}
fn binding() -> PresentationCreateIdempotency<'static> {
    PresentationCreateIdempotency {
        request_jti: "request",
        request_sha256: "digest",
        canonical_request: "{\"normalized\":true}",
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn presentation_create_and_complete_have_one_owner_and_erase_ephemeral_key() {
    let fixture = Fixture::new();
    let store = Arc::new(presentation::PresentationStore::new(
        fixture.db().clone(),
        [9; 32],
    ));
    let transaction = presentation();
    let mut joins = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let transaction = transaction.clone();
        joins.push(tokio::spawn(async move {
            store.create(&transaction, binding()).await.unwrap()
        }));
    }
    let mut created = 0;
    for join in joins {
        match join.await.unwrap() {
            PresentationCreateOutcome::Created => created += 1,
            PresentationCreateOutcome::Existing(existing) => {
                assert!(existing.response_encryption_private_key.is_none())
            }
        }
    }
    assert_eq!(created, 1);
    let mut conflicting = binding();
    conflicting.canonical_request = "{}";
    assert_eq!(
        store.find_by_create_request(conflicting).await,
        Err(PresentationStoreError::IdempotencyConflict)
    );
    assert_eq!(
        store
            .request(transaction.id, Timestamp::now())
            .await
            .unwrap()
            .unwrap()
            .response_encryption_private_key,
        Some([7; 32])
    );
    let now = Timestamp::now();
    let result = PresentationResult {
        transaction_id: transaction.id,
        credentials: Vec::new(),
        completed_at: now,
    };
    let state = blake3::hash(transaction.request.state.as_bytes())
        .to_hex()
        .to_string();
    let (a, b) = tokio::join!(
        store.complete(transaction.id, &state, &result, now),
        store.complete(transaction.id, &state, &result, now)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    assert_eq!(
        store.result(transaction.id, now).await.unwrap(),
        Some(result)
    );
    assert!(store.request(transaction.id, now).await.unwrap().is_none());
    let row: serde_json::Value = read(
        &fixture.db().db,
        &key(0xde, fixture.db().tenant_id, transaction.id.as_bytes()),
    )
    .unwrap()
    .unwrap();
    assert!(row["private_key"].is_null());
    assert!(row["result"].is_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presentation_completion_rechecks_expiry_after_waiting_for_record_lock() {
    let fixture = Fixture::new();
    let store = presentation::PresentationStore::new(fixture.db().clone(), [9; 32]);
    let mut transaction = presentation();
    transaction.expires_at = Timestamp::now() + SignedDuration::from_millis(100);
    store.create(&transaction, binding()).await.unwrap();
    let db = fixture.db().clone();
    let record_key = key(0xde, db.tenant_id, transaction.id.as_bytes());
    let (held, ready) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let tx = db.transaction();
        tx.get_pinned_for_update(record_key, true).unwrap();
        held.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
    });
    ready.recv().unwrap();
    let now = Timestamp::now();
    let result = PresentationResult {
        transaction_id: transaction.id,
        credentials: Vec::new(),
        completed_at: now,
    };
    let state = blake3::hash(transaction.request.state.as_bytes())
        .to_hex()
        .to_string();
    assert!(
        !store
            .complete(transaction.id, &state, &result, now)
            .await
            .unwrap()
    );
    blocker.join().unwrap();
    assert!(store.result(transaction.id, now).await.unwrap().is_none());
}
