#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_digital_credentials::{CredentialFormat, CredentialQuery, DcqlQuery, HolderBinding};
use nazo_identity::ports::{SecretVerifyFuture, SecretVerifyPort};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::{D1Provider, Database};
use nazo_openid4vci::*;
use nazo_openid4vp::{
    AuthorizationRequest, ClientIdPrefix, PresentationCreateIdempotency, PresentationCreateOutcome,
    PresentationResult, PresentationStoreError, PresentationTransaction, RequestMethod,
    ResponseMode,
};
use nazo_persistence::{
    ClientTrustPolicy, ManagedCredentialDatasetWrite, Openid4vcTrustPolicyStore,
};
use serde_json::json;
use std::sync::{Arc, Barrier};
use support::{CLIENT, TENANT, USER};
use uuid::Uuid;

const KEY: [u8; 32] = [37; 32];

struct PasswordVerifier;
impl SecretVerifyPort for PasswordVerifier {
    fn verify_secret(
        &self,
        secret: String,
        hash: nazo_identity::PasswordHash,
    ) -> SecretVerifyFuture<'_> {
        Box::pin(async move { Ok(hash.verify_password(&secret)) })
    }
}

async fn fixture() -> (Database, D1Provider) {
    let (database, provider) = support::fixture().await;
    database
        .execute_sql(include_str!("../migrations/0007_digital_credentials.sql"))
        .unwrap();
    (database, provider)
}
fn issuer(provider: &D1Provider) -> Arc<dyn nazo_persistence::Openid4vciStore> {
    provider.openid4vci_store(KEY, Arc::new(PasswordVerifier))
}
fn now() -> Timestamp {
    Timestamp::from_microsecond(Timestamp::now().as_microsecond()).unwrap()
}
fn assert_sql(database: &Database, predicate: &str) {
    database.execute_sql(&format!("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1)); INSERT INTO assertion SELECT CASE WHEN ({predicate}) THEN 1 ELSE 0 END; DROP TABLE assertion;")).unwrap();
}
fn admin(database: &Database) {
    database.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{{\"Admin\":{{\"level\":1}}}}')) WHERE tenant_id='{TENANT}' AND id='{USER}'")).unwrap();
}
fn dataset_write() -> ManagedCredentialDatasetWrite {
    ManagedCredentialDatasetWrite {
        tenant_id: TENANT,
        actor_user_id: USER,
        subject_id: USER,
        credential_configuration_id: "pid".into(),
        claims: json!({"given_name":"Alice","family_name":"Acceptance"}),
        valid_from: None,
        valid_until: Some(now() + SignedDuration::from_hours(1)),
    }
}

#[test]
fn dataset_authorization_encryption_validity_and_required_audit_are_real() {
    block_on(async {
        let (database, provider) = fixture().await;
        let store = provider.openid4vci_datasets(KEY);
        let write = dataset_write();
        assert!(
            store
                .upsert_managed_dataset(write.clone())
                .await
                .unwrap()
                .is_none()
        );
        assert_sql(
            &database,
            "(SELECT COUNT(*) FROM nazo_vci_dataset_events)=0 AND (SELECT COUNT(*) FROM nazo_audit)=0",
        );
        admin(&database);
        let created = store
            .upsert_managed_dataset(write.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(created.claims, write.claims);
        assert_eq!(created.valid_until, write.valid_until);
        assert_eq!(
            store.managed_dataset(TENANT, USER, "pid").await.unwrap(),
            Some(created.clone())
        );
        assert_eq!(
            store.dataset(TENANT, USER, "pid").await.unwrap(),
            Some(write.claims)
        );
        assert!(
            store
                .datasets_available(TENANT, USER, &["pid".into()])
                .await
                .unwrap()
        );
        assert!(
            !store
                .datasets_available(TENANT, USER, &["pid".into(), "missing".into()])
                .await
                .unwrap()
        );
        assert_sql(
            &database,
            "(SELECT instr(claims_ciphertext,'Alice')=0 FROM nazo_vci_datasets) AND (SELECT COUNT(*) FROM nazo_vci_dataset_events WHERE action=1)=1 AND (SELECT COUNT(*) FROM nazo_audit WHERE event_type='openid4vci_credential_dataset_updated' AND category='credential_lifecycle' AND json_extract(payload,'$.outcome')='success' AND json_extract(payload,'$.schema_version')='nazo.audit.v1')=1",
        );
        assert!(
            provider
                .openid4vci_datasets([38; 32])
                .dataset(TENANT, USER, "pid")
                .await
                .is_err()
        );
        assert!(store.dataset(Uuid::new_v4(), USER, "pid").await.is_err());
        database
            .execute_sql(&format!(
                "UPDATE nazo_vci_datasets SET valid_from={} WHERE tenant_id='{TENANT}'",
                (now() + SignedDuration::from_mins(5)).as_microsecond()
            ))
            .unwrap();
        assert!(store.dataset(TENANT, USER, "pid").await.unwrap().is_none());
        assert!(
            !store
                .datasets_available(TENANT, USER, &["pid".into()])
                .await
                .unwrap()
        );
        assert!(
            store
                .managed_dataset(TENANT, USER, "pid")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .delete_managed_dataset(TENANT, USER, USER, "pid")
                .await
                .unwrap()
        );
        assert!(
            !store
                .delete_managed_dataset(TENANT, USER, USER, "pid")
                .await
                .unwrap()
        );
        assert_sql(
            &database,
            "(SELECT COUNT(*) FROM nazo_vci_dataset_events)=2 AND (SELECT COUNT(*) FROM nazo_audit)=2",
        );
    });
}

#[test]
fn repeated_plaintext_encryption_uses_fresh_nonces_and_keeps_authenticated_readback() {
    block_on(async {
        let (database, provider) = fixture().await;
        admin(&database);
        let store = provider.openid4vci_datasets(KEY);
        let write = dataset_write();
        let first = store
            .upsert_managed_dataset(write.clone())
            .await
            .unwrap()
            .unwrap();
        database
            .execute_sql(
                "CREATE TEMP TABLE first_cipher AS SELECT claims_ciphertext FROM nazo_vci_datasets",
            )
            .unwrap();
        let second = store.upsert_managed_dataset(write).await.unwrap().unwrap();
        assert_eq!(second.claims, first.claims);
        assert_eq!(
            store.dataset(TENANT, USER, "pid").await.unwrap(),
            Some(first.claims)
        );
        // Twelve nonce bytes occupy the first sixteen standard Base64 chars.
        // Re-encrypting the same plaintext under the same key/AAD must not reuse them.
        assert_sql(
            &database,
            "(SELECT substr(n.claims_ciphertext,1,16)<>substr(f.claims_ciphertext,1,16) FROM nazo_vci_datasets n CROSS JOIN first_cipher f)",
        );
    });
}

#[test]
fn dataset_suppressed_effect_source_or_audit_rolls_back_without_a_view() {
    block_on(async {
        for table in ["nazo_vci_datasets", "nazo_vci_dataset_events", "nazo_audit"] {
            let (database, provider) = fixture().await;
            admin(&database);
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                provider
                    .openid4vci_datasets(KEY)
                    .upsert_managed_dataset(dataset_write())
                    .await
                    .is_err(),
                "suppressed {table} must fail closed"
            );
            assert_sql(
                &database,
                "(SELECT COUNT(*) FROM nazo_vci_datasets)=0 AND (SELECT COUNT(*) FROM nazo_vci_dataset_events)=0 AND (SELECT COUNT(*) FROM nazo_audit)=0",
            );
        }
        for table in ["nazo_vci_datasets", "nazo_vci_dataset_events", "nazo_audit"] {
            let (database, provider) = fixture().await;
            admin(&database);
            let store = provider.openid4vci_datasets(KEY);
            let original = store.upsert_managed_dataset(dataset_write()).await.unwrap();
            let operation = if table == "nazo_vci_datasets" {
                "DELETE"
            } else {
                "INSERT"
            };
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE {operation} ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                store
                    .delete_managed_dataset(TENANT, USER, USER, "pid")
                    .await
                    .is_err(),
                "suppressed {table} must roll back deletion"
            );
            assert_eq!(
                store.managed_dataset(TENANT, USER, "pid").await.unwrap(),
                original
            );
            assert_sql(
                &database,
                "(SELECT COUNT(*) FROM nazo_vci_dataset_events)=1 AND (SELECT COUNT(*) FROM nazo_audit)=1",
            );
        }
        let (database, provider) = fixture().await;
        admin(&database);
        database.execute_sql("CREATE TRIGGER corrupt_projection AFTER INSERT ON nazo_vci_datasets BEGIN UPDATE nazo_vci_datasets SET claims_ciphertext='not-the-acknowledged-effect' WHERE tenant_id=NEW.tenant_id AND subject_id=NEW.subject_id AND configuration_id=NEW.configuration_id; END;").unwrap();
        assert!(
            provider
                .openid4vci_datasets(KEY)
                .upsert_managed_dataset(dataset_write())
                .await
                .is_err()
        );
        assert_sql(
            &database,
            "(SELECT COUNT(*) FROM nazo_vci_datasets)=0 AND (SELECT COUNT(*) FROM nazo_vci_dataset_events)=0 AND (SELECT COUNT(*) FROM nazo_audit)=0",
        );
    });
}

#[test]
fn dataset_administrator_cannot_take_operator_ownership_or_misbound_principal() {
    block_on(async {
        let (database, provider) = fixture().await;
        admin(&database);
        let store = provider.openid4vci_datasets(KEY);
        let original = store.upsert_managed_dataset(dataset_write()).await.unwrap();
        database
            .execute_sql("UPDATE nazo_vci_datasets SET source='operator-managed'")
            .unwrap();
        assert!(
            store
                .upsert_managed_dataset(dataset_write())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .delete_managed_dataset(TENANT, USER, USER, "pid")
                .await
                .unwrap()
        );
        assert_eq!(
            store.managed_dataset(TENANT, USER, "pid").await.unwrap(),
            original
        );
        database.execute_sql(&format!("UPDATE nazo_vci_datasets SET source='admin-session'; UPDATE nazo_users SET principal=json_set(principal,'$.user_id','{}')",Uuid::new_v4())).unwrap();
        assert!(
            store
                .upsert_managed_dataset(dataset_write())
                .await
                .unwrap()
                .is_none()
        );
        assert_sql(
            &database,
            "(SELECT COUNT(*) FROM nazo_vci_dataset_events)=1 AND (SELECT COUNT(*) FROM nazo_audit)=1",
        );
    });
}

fn presentation() -> PresentationTransaction {
    let time = now();
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
            dcql_query: DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "pid".into(),
                    format: CredentialFormat::SdJwtVc,
                    multiple: false,
                    meta: Some(json!({"vct_values":["https://issuer.example/pid"]})),
                    claims: None,
                    claim_sets: None,
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: Some(true),
                }],
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
        created_at: time,
        expires_at: time + SignedDuration::from_mins(10),
    }
}
fn binding(jti: &str) -> PresentationCreateIdempotency<'_> {
    PresentationCreateIdempotency {
        request_jti: jti,
        request_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        canonical_request: "{\"normalized\":true}",
    }
}
fn state_hash(transaction: &PresentationTransaction) -> String {
    blake3::hash(transaction.request.state.as_bytes())
        .to_hex()
        .to_string()
}

#[test]
fn presentation_idempotency_and_completion_have_one_owner_under_races() {
    let (database, provider) = block_on(fixture());
    let transaction = presentation();
    let barrier = Arc::new(Barrier::new(8));
    let joins: Vec<_> = (0..8)
        .map(|_| {
            let store = provider.openid4vp_store(TENANT, KEY);
            let barrier = barrier.clone();
            let mut transaction = transaction.clone();
            transaction.id = Uuid::new_v4();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(async move {
                    let outcome = store
                        .create(&transaction, binding("same-request"))
                        .await
                        .unwrap();
                    (transaction.id, outcome)
                })
            })
        })
        .collect();
    let results: Vec<_> = joins.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        results
            .iter()
            .filter(|(_, o)| matches!(o, PresentationCreateOutcome::Created))
            .count(),
        1
    );
    let winner = results
        .iter()
        .find(|(_, o)| matches!(o, PresentationCreateOutcome::Created))
        .unwrap()
        .0;
    for (_, outcome) in &results {
        if let PresentationCreateOutcome::Existing(retained) = outcome {
            assert_eq!(retained.id, winner);
            assert!(retained.response_encryption_private_key.is_none());
        }
    }
    block_on(async {
        let store = provider.openid4vp_store(TENANT, KEY);
        let retained = store.request(winner, now()).await.unwrap().unwrap();
        assert_eq!(retained.response_encryption_private_key, Some([7; 32]));
        assert!(
            provider
                .openid4vp_store(Uuid::new_v4(), KEY)
                .request(winner, now())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider
                .openid4vp_store(TENANT, [38; 32])
                .request(winner, now())
                .await
                .is_err()
        );
        assert_eq!(
            store
                .create(
                    &presentation(),
                    PresentationCreateIdempotency {
                        canonical_request: "different",
                        ..binding("same-request")
                    }
                )
                .await,
            Err(PresentationStoreError::IdempotencyConflict)
        );
        assert!(
            store
                .bind_wallet_nonce(winner, "wallet-nonce", now())
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .request(winner, now())
                .await
                .unwrap()
                .unwrap()
                .request
                .wallet_nonce
                .as_deref(),
            Some("wallet-nonce")
        );
        let time = now();
        let result = PresentationResult {
            transaction_id: winner,
            credentials: Vec::new(),
            completed_at: time,
        };
        assert!(
            !store
                .complete(winner, "wrong-state", &result, time)
                .await
                .unwrap()
        );
    });
    let barrier = Arc::new(Barrier::new(8));
    let time = now();
    let joins: Vec<_> = (0..8)
        .map(|_| {
            let store = provider.openid4vp_store(TENANT, KEY);
            let barrier = barrier.clone();
            let hash = state_hash(&transaction);
            std::thread::spawn(move || {
                barrier.wait();
                block_on(store.complete(
                    winner,
                    &hash,
                    &PresentationResult {
                        transaction_id: winner,
                        credentials: Vec::new(),
                        completed_at: time,
                    },
                    time,
                ))
                .unwrap()
            })
        })
        .collect();
    assert_eq!(
        joins
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|won| *won)
            .count(),
        1
    );
    block_on(async {
        let store = provider.openid4vp_store(TENANT, KEY);
        assert_eq!(
            store
                .result(winner, now())
                .await
                .unwrap()
                .unwrap()
                .completed_at,
            time
        );
        assert!(
            store.request(winner, now()).await.unwrap().is_none(),
            "completed response requests must not resolve to a keyless active transaction"
        );
        let retained = store
            .find_by_create_request(binding("same-request"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.id, winner);
        assert!(retained.response_encryption_private_key.is_none());
        assert!(matches!(
            store.create(&transaction, binding("same-request")).await.unwrap(),
            PresentationCreateOutcome::Existing(existing) if existing.id == winner
        ));
        assert!(
            !store
                .bind_wallet_nonce(winner, "after-completion", now())
                .await
                .unwrap()
        );
    });
    assert_sql(
        &database,
        "(SELECT COUNT(*) FROM nazo_vp_transactions WHERE completed_at IS NOT NULL AND private_key_ciphertext IS NULL AND result_ciphertext IS NOT NULL)=1",
    );
}

#[test]
fn encrypted_presentation_completion_retires_request_but_keeps_result_and_create_identity() {
    block_on(async {
        let (database, provider) = fixture().await;
        let store = provider.openid4vp_store(TENANT, KEY);
        let mut transaction = presentation();
        transaction.request.response_mode = ResponseMode::DirectPostJwt;
        store
            .create(&transaction, binding("encrypted-terminal"))
            .await
            .unwrap();
        assert!(
            store
                .request(transaction.id, now())
                .await
                .unwrap()
                .unwrap()
                .response_encryption_private_key
                .is_some()
        );
        let completed_at = now();
        let result = PresentationResult {
            transaction_id: transaction.id,
            credentials: Vec::new(),
            completed_at,
        };
        assert!(
            store
                .complete(
                    transaction.id,
                    &state_hash(&transaction),
                    &result,
                    completed_at
                )
                .await
                .unwrap()
        );
        // Neither an ordinary replay nor the earlier caller clock may revive
        // the response view after atomic completion erased its response key.
        for clock in [transaction.created_at, now()] {
            assert!(
                store
                    .request(transaction.id, clock)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            store.result(transaction.id, now()).await.unwrap(),
            Some(result)
        );
        let retained = store
            .find_by_create_request(binding("encrypted-terminal"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.id, transaction.id);
        assert_eq!(retained.request, transaction.request);
        assert!(retained.response_encryption_private_key.is_none());
        assert!(matches!(
            store.create(&transaction, binding("encrypted-terminal")).await.unwrap(),
            PresentationCreateOutcome::Existing(existing) if existing.id == transaction.id
        ));
        assert_sql(
            &database,
            "(SELECT COUNT(*) FROM nazo_vp_transactions WHERE completed_at IS NOT NULL AND private_key_ciphertext IS NULL AND result_ciphertext IS NOT NULL)=1",
        );
    });
}

#[test]
fn presentation_rechecks_database_deadline_after_old_caller_time() {
    block_on(async {
        let (database, provider) = fixture().await;
        let store = provider.openid4vp_store(TENANT, KEY);
        let transaction = presentation();
        store.create(&transaction, binding("expire")).await.unwrap();
        database
            .execute_sql(&format!(
                "UPDATE nazo_vp_transactions SET created_at={},expires_at={} WHERE id='{}'",
                (now() - SignedDuration::from_mins(5)).as_microsecond(),
                (now() - SignedDuration::from_secs(1)).as_microsecond(),
                transaction.id
            ))
            .unwrap();
        let stale = transaction.created_at - SignedDuration::from_mins(2);
        assert!(
            !store
                .complete(
                    transaction.id,
                    &state_hash(&transaction),
                    &PresentationResult {
                        transaction_id: transaction.id,
                        credentials: Vec::new(),
                        completed_at: stale
                    },
                    stale
                )
                .await
                .unwrap()
        );
        assert_sql(
            &database,
            "(SELECT completed_at IS NULL AND result_ciphertext IS NULL AND private_key_ciphertext IS NOT NULL FROM nazo_vp_transactions)",
        );
    });
}

fn trust_policy() -> nazo_operator_protocol::Openid4vcTrustPolicy {
    let key = json!({"kty":"EC","crv":"P-256","kid":"trust-fixture","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
    nazo_operator_protocol::Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://issuer.example/attestation".into(),
        client_attestation_jwks: json!({"keys":[key.clone()]}),
        key_attestation_jwks: json!({"keys":[key]}),
        credential_trust_anchor_pem: include_str!(
            "../../crypto/tests/fixtures/certificates/root.pem"
        )
        .into(),
        wallet_authorization_origins: vec!["https://wallet.example".into()],
    }
}
fn provision_trust(database: &Database) -> Uuid {
    let policy = trust_policy();
    nazo_operator_protocol::validate_openid4vc_trust_policy(&policy).unwrap();
    let id = Uuid::new_v4();
    let material = serde_json::to_string(&policy).unwrap().replace('\'', "''");
    database.execute_sql(&format!("INSERT INTO nazo_vc_trust_policies(tenant_id,id,resource_id,resource_digest,material,source,active) VALUES('{TENANT}','{id}','trust-fixture','{}','{material}','operator-managed',1); INSERT INTO nazo_vc_trust_clients(tenant_id,client_id,policy_id,active) VALUES('{TENANT}','{CLIENT}','{id}',1);","a".repeat(64))).unwrap();
    id
}

#[test]
fn trust_binding_revocation_invalidates_request_result_and_completion() {
    block_on(async {
        let (database, provider) = fixture().await;
        assert!(matches!(
            provider.for_client(TENANT, "client").await.unwrap(),
            ClientTrustPolicy::Unbound
        ));
        let policy = provision_trust(&database);
        assert!(matches!(
            provider.for_client(TENANT, "client").await.unwrap(),
            ClientTrustPolicy::Active(_)
        ));
        assert!(
            provider
                .active_for_origin(
                    TENANT,
                    "trust-fixture",
                    "https://wallet.example",
                    &"a".repeat(64)
                )
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            provider
                .active_for_origin(
                    TENANT,
                    "trust-fixture",
                    "https://wallet.example.evil",
                    &"a".repeat(64)
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider
                .active_for_origin(
                    TENANT,
                    "trust-fixture",
                    "https://wallet.example",
                    &"b".repeat(64)
                )
                .await
                .unwrap()
                .is_none()
        );
        let store = provider.openid4vp_store(TENANT, KEY);
        let mut transaction = presentation();
        transaction.openid4vc_trust_policy_binding_id = Some(policy);
        transaction.openid4vc_trust_policy_resource_id = Some("trust-fixture".into());
        transaction.openid4vc_trust_policy_digest = Some("a".repeat(64));
        store.create(&transaction, binding("policy")).await.unwrap();
        database
            .execute_sql("UPDATE nazo_vc_trust_policies SET active=0")
            .unwrap();
        assert!(matches!(
            provider.for_client(TENANT, "client").await.unwrap(),
            ClientTrustPolicy::BoundInactive
        ));
        assert!(
            store
                .request(transaction.id, now())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .bind_wallet_nonce(transaction.id, "late", now())
                .await
                .unwrap()
        );
        let time = now();
        assert!(
            !store
                .complete(
                    transaction.id,
                    &state_hash(&transaction),
                    &PresentationResult {
                        transaction_id: transaction.id,
                        credentials: Vec::new(),
                        completed_at: time
                    },
                    time
                )
                .await
                .unwrap()
        );
        assert!(store.result(transaction.id, now()).await.unwrap().is_none());
        assert!(
            store
                .create(&transaction, binding("new-retired"))
                .await
                .is_err()
        );
    });
}

fn access() -> CredentialAccess {
    CredentialAccess {
        authorization_id: Some(Uuid::new_v4()),
        mtls_x5t_s256: None,
        proof_origin: CredentialProofOrigin::RegisteredClient,
        token_id: Uuid::new_v4(),
        tenant_id: TENANT,
        subject_id: USER,
        client_id: "client".into(),
        configuration_ids: vec!["pid".into()],
        credential_identifiers: Vec::new(),
        dpop_jkt: Some("holder-thumbprint".into()),
        expires_at: now() + SignedDuration::from_hours(1),
    }
}
fn selection() -> Option<CredentialSelection> {
    Some(CredentialSelection {
        configuration_id: "pid".into(),
        credential_identifier: None,
    })
}
fn response(access: &CredentialAccess, status: u16) -> StoredCredentialResponse {
    StoredCredentialResponse {
        selection: selection(),
        issuance_id: Uuid::new_v4(),
        token_id: access.token_id,
        request_digest: "b".repeat(64),
        body: bytes::Bytes::from_static(b"{\"credential\":\"private-credential-body\"}"),
        encoding: CredentialResponseEncoding::Json,
        status,
        dpop_nonce: Some("response-nonce".into()),
        expires_at: now() + SignedDuration::from_mins(10),
    }
}
fn handle(response: &StoredCredentialResponse) -> NotificationHandle {
    NotificationHandle {
        selection: response.selection.clone(),
        notification_id: Uuid::new_v4().to_string(),
        token_id: response.token_id,
        expires_at: response.expires_at,
    }
}
fn offer() -> StoredCredentialOffer {
    StoredCredentialOffer {
        id: Uuid::new_v4(),
        tenant_id: TENANT,
        subject_id: Some(USER),
        credential_configuration_ids: vec!["pid".into()],
        grants: CredentialOfferGrants::new(
            Some(AuthorizationCodeGrant {
                issuer_state: Some("private-issuer-state".into()),
                authorization_server: None,
            }),
            Some(PreAuthorizedCodeGrant {
                pre_authorized_code: "private-pre-authorized-code".into(),
                tx_code: None,
                authorization_server: None,
            }),
        ),
        expires_at: now() + SignedDuration::from_mins(10),
    }
}

#[test]
fn offers_preserve_provenance_verify_real_transaction_code_and_commit_once() {
    let (database, provider) = block_on(fixture());
    let store = issuer(&provider);
    let offer = offer();
    let tx_code = Uuid::new_v4().simple().to_string();
    let tx_hash = nazo_crypto::password::hash_argon2id(tx_code.as_bytes(), 8, 1, 1).unwrap();
    let prepared = block_on(async {
        store
            .insert_offer(
                &offer,
                Some("issuer-state"),
                Some("pre-code"),
                Some(&tx_hash),
            )
            .await
            .unwrap();
        assert_eq!(
            store.offer(TENANT, offer.id, now()).await.unwrap(),
            Some(offer.clone())
        );
        assert!(store.offer(Uuid::new_v4(), offer.id, now()).await.is_err());
        assert!(
            store
                .prepare_pre_authorized_offer(TENANT, "pre-code", Some("wrong"), "client", now())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .prepare_pre_authorized_offer(TENANT, "pre-code", None, "client", now())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider
                .openid4vci_authorization_offers(KEY, Arc::new(PasswordVerifier))
                .resolve_authorization_offer(TENANT, "issuer-state", USER, "client", now())
                .await
                .unwrap()
                .is_some()
        );
        store
            .prepare_pre_authorized_offer(TENANT, "pre-code", Some(&tx_code), "client", now())
            .await
            .unwrap()
            .unwrap()
    });
    assert_sql(
        &database,
        "(SELECT instr(grants_ciphertext,'private-')=0 FROM nazo_vci_offers)",
    );
    let mut base = access();
    base.expires_at = prepared.authorization.expires_at;
    let barrier = Arc::new(Barrier::new(8));
    let joins: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            let prepared = prepared.clone();
            let barrier = barrier.clone();
            let mut access = base.clone();
            access.token_id = Uuid::new_v4();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(store.persist_pre_authorized_access(
                    &prepared.commit_token,
                    &access.token_id.to_string(),
                    &access,
                    Some("client"),
                ))
            })
        })
        .collect();
    let outcomes: Vec<_> = joins.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
    assert!(
        outcomes
            .iter()
            .filter(|o| o.is_err())
            .all(|o| o == &Err(CredentialStoreError::InvalidTransition))
    );
    assert_sql(
        &database,
        "(SELECT COUNT(*) FROM nazo_vci_access)=1 AND (SELECT consumed_at IS NOT NULL AND grants_ciphertext='' AND tx_code_hash IS NULL FROM nazo_vci_offers)",
    );
    block_on(async {
        assert!(
            store
                .offer(TENANT, offer.id, now())
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn prepared_offer_rechecks_client_subject_and_exact_snapshot() {
    block_on(async {
        for fault in ["client", "subject", "snapshot"] {
            let (database, provider) = fixture().await;
            let store = issuer(&provider);
            let offer = offer();
            store
                .insert_offer(&offer, None, Some("pre-code"), None)
                .await
                .unwrap();
            let prepared = store
                .prepare_pre_authorized_offer(TENANT, "pre-code", None, "client", now())
                .await
                .unwrap()
                .unwrap();
            let mut grant = access();
            grant.expires_at = prepared.authorization.expires_at;
            let sql = match fault {
                "client" => "UPDATE nazo_clients SET active=0",
                "subject" => "UPDATE nazo_users SET active=0,epoch=epoch+1",
                _ => "UPDATE nazo_vci_offers SET configuration_ids='[\"other\"]'",
            };
            database.execute_sql(sql).unwrap();
            let error = store
                .persist_pre_authorized_access(
                    &prepared.commit_token,
                    "token",
                    &grant,
                    Some("client"),
                )
                .await
                .unwrap_err();
            assert_eq!(
                error,
                if fault == "client" {
                    CredentialStoreError::ClientInactive
                } else {
                    CredentialStoreError::InvalidTransition
                }
            );
            assert_sql(&database, "(SELECT COUNT(*) FROM nazo_vci_access)=0");
            if fault == "subject" {
                database
                    .execute_sql("UPDATE nazo_users SET active=1")
                    .unwrap();
                assert!(
                    store
                        .offer(TENANT, offer.id, now())
                        .await
                        .unwrap()
                        .is_none()
                );
            } else {
                assert_sql(
                    &database,
                    "(SELECT consumed_at IS NULL FROM nazo_vci_offers)",
                );
            }
        }
    });
}

#[test]
fn offer_consume_failure_rolls_back_grant_and_does_not_spend_offer() {
    block_on(async {
        for behavior in ["ABORT,'fixture refusal'", "IGNORE"] {
            let (database, provider) = fixture().await;
            let store = issuer(&provider);
            let offer = offer();
            store
                .insert_offer(&offer, None, Some("pre-code"), None)
                .await
                .unwrap();
            let prepared = store
                .prepare_pre_authorized_offer(TENANT, "pre-code", None, "client", now())
                .await
                .unwrap()
                .unwrap();
            let mut grant = access();
            grant.expires_at = prepared.authorization.expires_at;
            database.execute_sql(&format!("CREATE TRIGGER refuse BEFORE UPDATE ON nazo_vci_offers BEGIN SELECT RAISE({behavior}); END;")).unwrap();
            assert!(
                store
                    .persist_pre_authorized_access(
                        &prepared.commit_token,
                        "token",
                        &grant,
                        Some("client")
                    )
                    .await
                    .is_err()
            );
            assert_sql(
                &database,
                "(SELECT COUNT(*) FROM nazo_vci_access)=0 AND (SELECT consumed_at IS NULL FROM nazo_vci_offers)",
            );
            database.execute_sql("DROP TRIGGER refuse").unwrap();
            store
                .persist_pre_authorized_access(
                    &prepared.commit_token,
                    "token",
                    &grant,
                    Some("client"),
                )
                .await
                .unwrap();
        }
    });
}

#[test]
fn credential_access_preserves_sender_constraints_and_revocation_across_upsert() {
    block_on(async {
        let (database, provider) = fixture().await;
        let store = issuer(&provider);
        let original = access();
        store.upsert_access("token", &original).await.unwrap();
        assert_eq!(
            store.resolve_access("token", now()).await.unwrap(),
            Some(original.clone())
        );
        let mut changed = original.clone();
        changed.dpop_jkt = Some("other-key".into());
        assert_eq!(
            store.upsert_access("token", &changed).await,
            Err(CredentialStoreError::InvalidTransition)
        );
        let mut changed = original.clone();
        changed.authorization_id = Some(Uuid::new_v4());
        assert_eq!(
            store.upsert_access("token", &changed).await,
            Err(CredentialStoreError::InvalidTransition)
        );
        let mut changed = original.clone();
        changed.tenant_id = Uuid::new_v4();
        assert!(store.upsert_access("token", &changed).await.is_err());
        database
            .execute_sql("UPDATE nazo_users SET epoch=epoch+1")
            .unwrap();
        assert!(
            store
                .resolve_access("token", now())
                .await
                .unwrap()
                .is_none()
        );
        store.upsert_access("token", &original).await.unwrap();
        assert!(
            store
                .resolve_access("token", now())
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn nonce_response_notification_commit_is_atomic_and_exact_response_replay_is_authorized() {
    block_on(async {
        let (database, provider) = fixture().await;
        let store = issuer(&provider);
        let access = access();
        store.upsert_access("token", &access).await.unwrap();
        let nonce = NonceRecord {
            nonce_hash: "nonce".into(),
            expires_at: now() + SignedDuration::from_mins(10),
        };
        store.issue_nonce(&nonce).await.unwrap();
        assert!(store.claim_nonce("nonce", "lease", now()).await.unwrap());
        assert!(!store.claim_nonce("nonce", "other", now()).await.unwrap());
        assert!(!store.release_nonce("nonce", "other", now()).await.unwrap());
        let response = response(&access, 200);
        let handle = handle(&response);
        database.execute_sql("CREATE TRIGGER refuse BEFORE INSERT ON nazo_vci_notifications BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            store
                .finalize_nonce_with_notification_and_response(
                    "nonce",
                    "lease",
                    &handle,
                    &response,
                    now()
                )
                .await
                .is_err()
        );
        assert_sql(
            &database,
            "(SELECT COUNT(*) FROM nazo_vci_responses)=0 AND (SELECT consumed_at IS NULL AND claim_id='lease' FROM nazo_vci_nonces)",
        );
        database.execute_sql("DROP TRIGGER refuse").unwrap();
        assert!(
            !store
                .finalize_nonce_with_notification_and_response(
                    "nonce",
                    "wrong",
                    &handle,
                    &response,
                    now()
                )
                .await
                .unwrap()
        );
        assert!(
            store
                .finalize_nonce_with_notification_and_response(
                    "nonce",
                    "lease",
                    &handle,
                    &response,
                    now()
                )
                .await
                .unwrap()
        );
        assert!(
            !store
                .finalize_nonce_with_notification_and_response(
                    "nonce",
                    "lease",
                    &handle,
                    &response,
                    now()
                )
                .await
                .unwrap()
        );
        assert!(!store.claim_nonce("nonce", "replay", now()).await.unwrap());
        assert_eq!(
            store
                .find_response(
                    response.issuance_id,
                    access.token_id,
                    &response.request_digest,
                    now()
                )
                .await
                .unwrap(),
            Some(response.clone())
        );
        assert!(
            store
                .find_response(
                    response.issuance_id,
                    access.token_id,
                    &"f".repeat(64),
                    now()
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .find_response(
                    response.issuance_id,
                    Uuid::new_v4(),
                    &response.request_digest,
                    now()
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_sql(
            &database,
            "(SELECT instr(body_ciphertext,'private-credential-body')=0 FROM nazo_vci_responses)",
        );
        assert!(
            provider
                .openid4vci_store([38; 32], Arc::new(PasswordVerifier))
                .find_response(
                    response.issuance_id,
                    access.token_id,
                    &response.request_digest,
                    now()
                )
                .await
                .is_err()
        );
        let notification = IssuanceNotification {
            notification_id: handle.notification_id.clone(),
            token_id: access.token_id,
            event: NotificationEvent::CredentialAccepted,
            description: Some("accepted".into()),
            occurred_at: now(),
        };
        assert!(store.record_notification(&notification).await.unwrap());
        let mut retry = notification.clone();
        retry.occurred_at += SignedDuration::from_secs(1);
        assert!(store.record_notification(&retry).await.unwrap());
        retry.event = NotificationEvent::CredentialFailure;
        assert!(!store.record_notification(&retry).await.unwrap());
        assert_sql(
            &database,
            &format!(
                "(SELECT occurred_at={} FROM nazo_vci_notifications)",
                notification.occurred_at.as_microsecond()
            ),
        );
    });
}

#[test]
fn nonce_lease_reclaim_fences_the_old_owner_and_uses_database_time() {
    block_on(async {
        let (database, provider) = fixture().await;
        let store = issuer(&provider);
        let access = access();
        store.upsert_access("token", &access).await.unwrap();
        store
            .issue_nonce(&NonceRecord {
                nonce_hash: "lease".into(),
                expires_at: now() + SignedDuration::from_mins(10),
            })
            .await
            .unwrap();
        assert!(store.claim_nonce("lease", "old", now()).await.unwrap());
        database
            .execute_sql("UPDATE nazo_vci_nonces SET claim_expires_at=1")
            .unwrap();
        assert!(store.claim_nonce("lease", "new", now()).await.unwrap());
        assert!(!store.release_nonce("lease", "old", now()).await.unwrap());
        let response = response(&access, 200);
        let handle = handle(&response);
        assert!(
            !store
                .finalize_nonce_with_notification_and_response(
                    "lease",
                    "old",
                    &handle,
                    &response,
                    now()
                )
                .await
                .unwrap()
        );
        assert!(
            store
                .finalize_nonce_with_notification_and_response(
                    "lease",
                    "new",
                    &handle,
                    &response,
                    now()
                )
                .await
                .unwrap()
        );
        store
            .issue_nonce(&NonceRecord {
                nonce_hash: "expired".into(),
                expires_at: now() + SignedDuration::from_mins(10),
            })
            .await
            .unwrap();
        database
            .execute_sql(
                "UPDATE nazo_vci_nonces SET created_at=1,expires_at=2 WHERE nonce_hash='expired'",
            )
            .unwrap();
        assert!(
            !store
                .claim_nonce("expired", "late", Timestamp::from_microsecond(1).unwrap())
                .await
                .unwrap()
        );
    });
}

#[test]
fn response_and_notification_continuation_reuses_shared_exact_lineage_policy() {
    block_on(async {
        let (_database, provider) = fixture().await;
        let store = issuer(&provider);
        let original = access();
        store.upsert_access("original", &original).await.unwrap();
        let response = response(&original, 200);
        let handle = handle(&response);
        store
            .store_response_with_notification(&handle, &response, now())
            .await
            .unwrap();
        let mut current = original.clone();
        current.token_id = Uuid::new_v4();
        store.upsert_access("current", &current).await.unwrap();
        assert!(
            store
                .find_response(
                    response.issuance_id,
                    current.token_id,
                    &response.request_digest,
                    now()
                )
                .await
                .unwrap()
                .is_some()
        );
        let notification = IssuanceNotification {
            notification_id: handle.notification_id,
            token_id: current.token_id,
            event: NotificationEvent::CredentialAccepted,
            description: None,
            occurred_at: now(),
        };
        assert!(store.record_notification(&notification).await.unwrap());
        for fault in ["lineage", "sender", "selection", "identifier", "origin"] {
            let mut other = original.clone();
            other.token_id = Uuid::new_v4();
            match fault {
                "lineage" => other.authorization_id = Some(Uuid::new_v4()),
                "sender" => other.dpop_jkt = Some("different-key".into()),
                "selection" => other.configuration_ids = vec!["other".into()],
                "identifier" => {
                    other.credential_identifiers =
                        vec![CredentialIdentifier("different-selection".into())]
                }
                _ => other.proof_origin = CredentialProofOrigin::AnonymousPreAuthorized,
            }
            store.upsert_access(fault, &other).await.unwrap();
            assert!(
                store
                    .find_response(
                        response.issuance_id,
                        other.token_id,
                        &response.request_digest,
                        now()
                    )
                    .await
                    .unwrap()
                    .is_none(),
                "{fault} cannot continue the old intent"
            );
            assert!(
                !store
                    .record_notification(&IssuanceNotification {
                        token_id: other.token_id,
                        ..notification.clone()
                    })
                    .await
                    .unwrap()
            );
        }
    });
}

fn deferred(access: &CredentialAccess, ready_in: SignedDuration) -> DeferredCredential {
    let time = now();
    let ready_at = time + ready_in;
    DeferredCredential {
        selection: selection(),
        id: Uuid::new_v4(),
        transaction_hash: Uuid::new_v4().to_string(),
        access: access.clone(),
        configuration_id: "pid".into(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![Some(HolderBinding::Jwk {
            jwk: json!({"kid":"holder"}),
        })],
        payload: DeferredPayload {
            dataset: json!({"secret_dataset":"not-plaintext"}),
            status: None,
            issued_at: time,
            expires_at: time + SignedDuration::from_hours(1),
        },
        ready_at,
        expires_at: time + SignedDuration::from_mins(10),
    }
}

#[test]
fn deferred_claims_pending_busy_release_renewal_and_single_completion() {
    let (database, provider) = block_on(fixture());
    let store = issuer(&provider);
    let original = access();
    let credential = deferred(&original, SignedDuration::from_mins(1));
    block_on(async {
        store.upsert_access("token", &original).await.unwrap();
        store
            .store_deferred_with_response(&credential, &response(&original, 202), now())
            .await
            .unwrap();
        assert!(matches!(
            store
                .claim_ready_deferred(
                    &credential.transaction_hash,
                    original.token_id,
                    "pending",
                    now()
                )
                .await
                .unwrap(),
            DeferredClaimOutcome::Pending { .. }
        ));
    });
    database
        .execute_sql(&format!(
            "UPDATE nazo_vci_deferred SET ready_at={} WHERE id='{}'",
            (now() - SignedDuration::from_secs(1)).as_microsecond(),
            credential.id
        ))
        .unwrap();
    let mut current = original.clone();
    current.token_id = Uuid::new_v4();
    block_on(store.upsert_access("current", &current)).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let joins: Vec<_> = (0..8)
        .map(|i| {
            let store = store.clone();
            let barrier = barrier.clone();
            let hash = credential.transaction_hash.clone();
            let token = current.token_id;
            std::thread::spawn(move || {
                barrier.wait();
                (
                    i,
                    block_on(store.claim_ready_deferred(&hash, token, &i.to_string(), now()))
                        .unwrap(),
                )
            })
        })
        .collect();
    let outcomes: Vec<_> = joins.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, o)| matches!(o, DeferredClaimOutcome::Claimed(_)))
            .count(),
        1
    );
    let (winner, claimed) = outcomes
        .into_iter()
        .find(|(_, o)| matches!(o, DeferredClaimOutcome::Claimed(_)))
        .unwrap();
    if let DeferredClaimOutcome::Claimed(retained) = claimed {
        assert_eq!(retained.payload, credential.payload);
        assert_eq!(retained.access.token_id, original.token_id);
    }
    block_on(async {
        assert!(matches!(
            store
                .claim_ready_deferred(
                    &credential.transaction_hash,
                    current.token_id,
                    "busy",
                    now()
                )
                .await
                .unwrap(),
            DeferredClaimOutcome::Busy { .. }
        ));
        assert!(
            !store
                .release_deferred(
                    &credential.transaction_hash,
                    original.token_id,
                    &winner.to_string(),
                    now()
                )
                .await
                .unwrap()
        );
        assert!(
            store
                .release_deferred(
                    &credential.transaction_hash,
                    current.token_id,
                    &winner.to_string(),
                    now()
                )
                .await
                .unwrap()
        );
        assert!(matches!(
            store
                .claim_ready_deferred(
                    &credential.transaction_hash,
                    current.token_id,
                    "finish",
                    now()
                )
                .await
                .unwrap(),
            DeferredClaimOutcome::Claimed(_)
        ));
        let response = response(&current, 200);
        let handle = handle(&response);
        assert!(
            !store
                .finalize_deferred_with_notification_and_response(
                    &credential.transaction_hash,
                    current.token_id,
                    "wrong",
                    &handle,
                    &response,
                    now()
                )
                .await
                .unwrap()
        );
        assert!(
            store
                .finalize_deferred_with_notification_and_response(
                    &credential.transaction_hash,
                    current.token_id,
                    "finish",
                    &handle,
                    &response,
                    now()
                )
                .await
                .unwrap()
        );
        assert!(matches!(
            store
                .claim_ready_deferred(
                    &credential.transaction_hash,
                    current.token_id,
                    "replay",
                    now()
                )
                .await
                .unwrap(),
            DeferredClaimOutcome::Invalid
        ));
        assert_eq!(
            store
                .find_response(
                    response.issuance_id,
                    current.token_id,
                    &response.request_digest,
                    now()
                )
                .await
                .unwrap(),
            Some(response)
        );
    });
    assert_sql(
        &database,
        "(SELECT instr(payload_ciphertext,'secret_dataset')=0 AND consumed_at IS NOT NULL AND claim_id IS NULL FROM nazo_vci_deferred)",
    );
}

#[test]
fn deferred_storage_failure_keeps_nonce_and_response_uncommitted() {
    block_on(async {
        let (database, provider) = fixture().await;
        let store = issuer(&provider);
        let access = access();
        store.upsert_access("token", &access).await.unwrap();
        store
            .issue_nonce(&NonceRecord {
                nonce_hash: "nonce".into(),
                expires_at: now() + SignedDuration::from_mins(10),
            })
            .await
            .unwrap();
        assert!(store.claim_nonce("nonce", "lease", now()).await.unwrap());
        let deferred = deferred(&access, SignedDuration::from_mins(1));
        let response = response(&access, 202);
        database.execute_sql("CREATE TRIGGER refuse BEFORE INSERT ON nazo_vci_deferred BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            store
                .store_deferred_and_finalize_nonce_with_response(
                    &deferred,
                    "nonce",
                    "lease",
                    &response,
                    now()
                )
                .await
                .is_err()
        );
        assert_sql(
            &database,
            "(SELECT COUNT(*) FROM nazo_vci_responses)=0 AND (SELECT consumed_at IS NULL AND claim_id='lease' FROM nazo_vci_nonces)",
        );
        database.execute_sql("DROP TRIGGER refuse").unwrap();
        store
            .store_deferred_and_finalize_nonce_with_response(
                &deferred,
                "nonce",
                "lease",
                &response,
                now(),
            )
            .await
            .unwrap();
        assert_sql(
            &database,
            "(SELECT COUNT(*) FROM nazo_vci_responses)=1 AND (SELECT consumed_at IS NOT NULL AND claim_id IS NULL FROM nazo_vci_nonces)",
        );
    });
}

#[test]
fn corrupt_or_revoked_deferred_data_never_grants_signing_lease() {
    block_on(async {
        for fault in ["payload", "access", "expiry", "selection"] {
            let (database, provider) = fixture().await;
            let store = issuer(&provider);
            let access = access();
            store.upsert_access("token", &access).await.unwrap();
            let credential = deferred(&access, -SignedDuration::from_secs(1));
            store
                .store_deferred_with_response(&credential, &response(&access, 202), now())
                .await
                .unwrap();
            let sql = match fault {
                "payload" => "UPDATE nazo_vci_deferred SET payload_ciphertext='corrupt'",
                "access" => "UPDATE nazo_vci_access SET revoked_at=1",
                "expiry" => "UPDATE nazo_vci_deferred SET ready_at=1,expires_at=2",
                _ => {
                    "UPDATE nazo_vci_access SET record=json_set(record,'$.configuration_ids',json('[\"other\"]'))"
                }
            };
            database.execute_sql(sql).unwrap();
            let result = store
                .claim_ready_deferred(
                    &credential.transaction_hash,
                    access.token_id,
                    "bad",
                    now() - SignedDuration::from_hours(1),
                )
                .await;
            assert!(
                matches!(result, Err(_) | Ok(DeferredClaimOutcome::Invalid)),
                "{fault} cannot confer a lease"
            );
            assert_sql(
                &database,
                "(SELECT claim_id IS NULL AND consumed_at IS NULL FROM nazo_vci_deferred)",
            );
        }
    });
}

#[test]
fn deferred_revocation_after_claim_prevents_response_notification_and_consumption() {
    block_on(async {
        for fault in ["access_revocation", "subject_epoch"] {
            let (database, provider) = fixture().await;
            let store = issuer(&provider);
            let access = access();
            store.upsert_access("token", &access).await.unwrap();
            let credential = deferred(&access, -SignedDuration::from_secs(1));
            let initial_response = response(&access, 202);
            store
                .store_deferred_with_response(&credential, &initial_response, now())
                .await
                .unwrap();
            assert!(matches!(
                store
                    .claim_ready_deferred(
                        &credential.transaction_hash,
                        access.token_id,
                        "held-claim",
                        now(),
                    )
                    .await
                    .unwrap(),
                DeferredClaimOutcome::Claimed(_)
            ));

            let revoke = if fault == "access_revocation" {
                format!(
                    "UPDATE nazo_vci_access SET revoked_at=1 WHERE tenant_id='{TENANT}' AND token_id='{}'",
                    access.token_id
                )
            } else {
                format!(
                    "UPDATE nazo_users SET epoch=epoch+1 WHERE tenant_id='{TENANT}' AND id='{USER}'"
                )
            };
            database.execute_sql(&revoke).unwrap();
            let completed = response(&access, 200);
            let notification = handle(&completed);
            assert!(
                !store
                    .finalize_deferred_with_notification_and_response(
                        &credential.transaction_hash,
                        access.token_id,
                        "held-claim",
                        &notification,
                        &completed,
                        now(),
                    )
                    .await
                    .unwrap(),
                "{fault} must invalidate an already issued signing lease"
            );
            assert_sql(
                &database,
                &format!(
                    "(SELECT count(*) FROM nazo_vci_responses)=1 \
                     AND EXISTS(SELECT 1 FROM nazo_vci_responses WHERE issuance_id='{}' AND status=202) \
                     AND NOT EXISTS(SELECT 1 FROM nazo_vci_responses WHERE issuance_id='{}') \
                     AND NOT EXISTS(SELECT 1 FROM nazo_vci_notifications) \
                     AND EXISTS(SELECT 1 FROM nazo_vci_deferred WHERE id='{}' AND claim_id='held-claim' AND consumed_at IS NULL) \
                     AND EXISTS(SELECT 1 FROM nazo_vci_access WHERE token_id='{}' AND revoked_at IS NOT NULL)",
                    initial_response.issuance_id,
                    completed.issuance_id,
                    credential.id,
                    access.token_id,
                ),
            );
        }
    });
}
