use super::*;
use crate::db::{put, read};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId, UserId, UserRole};
use std::path::PathBuf;

struct Verify;
impl nazo_identity::ports::SecretVerifyPort for Verify {
    fn verify_secret(
        &self,
        _: String,
        _: nazo_identity::PasswordHash,
    ) -> nazo_identity::ports::SecretVerifyFuture<'_> {
        Box::pin(async { Ok(false) })
    }
}

fn seed_tenant(db: &RocksDb, tenant: Uuid, client: Uuid, user: Uuid) {
    let context = TenantContext {
        tenant_id: TenantId::new(tenant).unwrap(),
        realm_id: RealmId::new(Uuid::new_v4()).unwrap(),
        organization_id: OrganizationId::new(Uuid::new_v4()).unwrap(),
    };
    let tx = db.transaction();
    put(&tx, &key(CLIENT_PUBLIC_ID, tenant, b"client"), &client).unwrap();
    put(
        &tx,
        &key(CLIENT_PRINCIPAL, tenant, client.as_bytes()),
        &ClientPrincipal {
            id: client,
            public_id: "client".into(),
            client_type: "confidential".into(),
            active: true,
            epoch: 0,
            tenant: context,
        },
    )
    .unwrap();
    put(
        &tx,
        &key(USER_PRINCIPAL, tenant, user.as_bytes()),
        &Principal {
            user_id: UserId::new(user).unwrap(),
            tenant: context,
            role: UserRole::User,
            active: true,
            authorization_epoch: 0,
        },
    )
    .unwrap();
    tx.commit().unwrap();
}

struct Fixture {
    store: Option<IssuerStore>,
    path: PathBuf,
    tenant: Uuid,
    client: Uuid,
    user: Uuid,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("nazo-rocksdb-issuer-{}", Uuid::new_v4()));
        let tenant = Uuid::new_v4();
        let client = Uuid::new_v4();
        let user = Uuid::new_v4();
        let db = RocksDb::open(&path).unwrap();
        seed_tenant(&db, tenant, client, user);
        Self {
            store: Some(IssuerStore::new(db, [7; 32], Arc::new(Verify))),
            path,
            tenant,
            client,
            user,
        }
    }
    fn store(&self) -> &IssuerStore {
        self.store.as_ref().unwrap()
    }
    fn db(&self) -> &RocksDb {
        &self.store().store.provider
    }
    fn access(&self) -> CredentialAccess {
        CredentialAccess {
            authorization_id: Some(Uuid::new_v4()),
            mtls_x5t_s256: None,
            proof_origin: CredentialProofOrigin::RegisteredClient,
            token_id: Uuid::new_v4(),
            tenant_id: self.tenant,
            subject_id: self.user,
            client_id: "client".into(),
            configuration_ids: vec!["identity".into()],
            credential_identifiers: Vec::new(),
            dpop_jkt: Some("holder-key".into()),
            expires_at: Timestamp::now() + SignedDuration::from_mins(10),
        }
    }
    fn offer(&self) -> StoredCredentialOffer {
        StoredCredentialOffer {
            id: Uuid::new_v4(),
            tenant_id: self.tenant,
            subject_id: Some(self.user),
            credential_configuration_ids: vec!["identity".into()],
            grants: CredentialOfferGrants::new(
                None,
                Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "secret-offer-code".into(),
                    tx_code: None,
                    authorization_server: None,
                }),
            ),
            expires_at: Timestamp::now() + SignedDuration::from_mins(15),
        }
    }
    fn response(&self, access: &CredentialAccess) -> StoredCredentialResponse {
        StoredCredentialResponse {
            selection: Some(CredentialSelection {
                configuration_id: "identity".into(),
                credential_identifier: None,
            }),
            issuance_id: Uuid::new_v4(),
            token_id: access.token_id,
            request_digest: "request-digest".into(),
            body: bytes::Bytes::from_static(
                b"{  \"credential\": \"private-exact-wire-response\" }",
            ),
            encoding: CredentialResponseEncoding::Json,
            status: 200,
            dpop_nonce: Some("fresh-dpop-nonce".into()),
            expires_at: Timestamp::now() + SignedDuration::from_hours(1),
        }
    }
    fn handle(&self, response: &StoredCredentialResponse) -> NotificationHandle {
        NotificationHandle {
            selection: response.selection.clone(),
            notification_id: Uuid::new_v4().to_string(),
            token_id: response.token_id,
            expires_at: response.expires_at,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_pre_authorized_offer_commits_exactly_one_access_and_no_plaintext() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let offer = fixture.offer();
    store
        .insert_offer(&offer, Some("issuer-state-hash"), Some("code-hash"), None)
        .await
        .unwrap();
    let raw = fixture
        .db()
        .db
        .get_pinned(key(OFFER, fixture.tenant, offer.id.as_bytes()))
        .unwrap()
        .unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("secret-offer-code"));
    assert_eq!(
        store
            .offer(fixture.tenant, offer.id, Timestamp::now())
            .await
            .unwrap(),
        Some(offer.clone())
    );
    let prepared = store
        .prepare_pre_authorized_offer(
            fixture.tenant,
            "code-hash",
            None,
            "client",
            Timestamp::now(),
        )
        .await
        .unwrap()
        .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    for i in 0..8 {
        let store = store.clone();
        let prepared = prepared.clone();
        let access = fixture.access();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            let hash = format!("access-{i}");
            let result = store
                .persist_pre_authorized_access(
                    &prepared.commit_token,
                    &hash,
                    &access,
                    Some("client"),
                )
                .await;
            (hash, result)
        });
    }
    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
        let (hash, result) = result.unwrap();
        let access = store.resolve_access(&hash, Timestamp::now()).await.unwrap();
        if result.is_ok() {
            winners += 1;
            assert!(access.is_some());
        } else {
            assert_eq!(result, Err(CredentialStoreError::InvalidTransition));
            assert!(access.is_none());
        }
    }
    assert_eq!(winners, 1);
    assert!(
        store
            .offer(fixture.tenant, offer.id, Timestamp::now())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .prepare_pre_authorized_offer(
                fixture.tenant,
                "code-hash",
                None,
                "client",
                Timestamp::now()
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn changed_offer_or_inactive_client_does_not_write_access_or_consume_offer() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let offer = fixture.offer();
    store
        .insert_offer(&offer, None, Some("code"), None)
        .await
        .unwrap();
    let prepared = store
        .prepare_pre_authorized_offer(fixture.tenant, "code", None, "client", Timestamp::now())
        .await
        .unwrap()
        .unwrap();
    let access = fixture.access();
    let tx = fixture.db().transaction();
    let offer_key = key(OFFER, fixture.tenant, offer.id.as_bytes());
    let mut changed: OfferRecord = read_tx(&tx, &offer_key, true).unwrap().unwrap();
    changed.snapshot.tx_code_hash = Some("replacement-verifier".into());
    put_expiring(&tx, &offer_key, &changed, changed.snapshot.expires_at).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        store
            .persist_pre_authorized_access(
                &prepared.commit_token,
                "access",
                &access,
                Some("client")
            )
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );
    assert!(
        store
            .resolve_access("access", Timestamp::now())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .offer(fixture.tenant, offer.id, Timestamp::now())
            .await
            .unwrap()
            .is_some()
    );
    let tx = fixture.db().transaction();
    let client_key = key(CLIENT_PRINCIPAL, fixture.tenant, fixture.client.as_bytes());
    let mut client: ClientPrincipal = read_tx(&tx, &client_key, true).unwrap().unwrap();
    client.active = false;
    put(&tx, &client_key, &client).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        store
            .persist_pre_authorized_access(
                &prepared.commit_token,
                "access",
                &access,
                Some("client")
            )
            .await,
        Err(CredentialStoreError::ClientInactive)
    );
    let offer = fixture.offer();
    store
        .insert_offer(&offer, None, Some("anonymous-code"), None)
        .await
        .unwrap();
    let prepared = store
        .prepare_pre_authorized_offer(
            fixture.tenant,
            "anonymous-code",
            None,
            "anonymous",
            Timestamp::now(),
        )
        .await
        .unwrap()
        .unwrap();
    let mut anonymous = fixture.access();
    anonymous.client_id = "anonymous".into();
    anonymous.proof_origin = CredentialProofOrigin::AnonymousPreAuthorized;
    store
        .persist_pre_authorized_access(&prepared.commit_token, "anonymous-access", &anonymous, None)
        .await
        .unwrap();
    assert_eq!(
        store
            .resolve_access("anonymous-access", Timestamp::now())
            .await
            .unwrap(),
        Some(anonymous)
    );
}

#[tokio::test]
async fn nonce_finalize_and_response_are_atomic_and_single_use() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let access = fixture.access();
    store.upsert_access("access", &access).await.unwrap();
    let now = Timestamp::now();
    let nonce = NonceRecord {
        nonce_hash: "nonce".into(),
        expires_at: now + SignedDuration::from_mins(5),
    };
    store.issue_nonce(&nonce).await.unwrap();
    let (first, second) = tokio::join!(
        store.claim_nonce("nonce", "claim-a", now),
        store.claim_nonce("nonce", "claim-b", now)
    );
    assert_ne!(first.unwrap(), second.unwrap());
    let claim = read::<Nonce>(&fixture.db().db, &key(NONCE, Uuid::nil(), b"nonce"))
        .unwrap()
        .unwrap()
        .lease
        .unwrap()
        .claim_id;
    let existing = fixture.response(&access);
    let handle = fixture.handle(&existing);
    store
        .store_response_with_notification(&handle, &existing, now)
        .await
        .unwrap();
    let response = fixture.response(&access);
    assert_eq!(
        store
            .finalize_nonce_with_notification_and_response("nonce", &claim, &handle, &response, now)
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );
    assert!(
        store
            .find_response(
                response.issuance_id,
                access.token_id,
                &response.request_digest,
                now
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !read::<Nonce>(&fixture.db().db, &key(NONCE, Uuid::nil(), b"nonce"))
            .unwrap()
            .unwrap()
            .consumed
    );
    let handle = fixture.handle(&response);
    assert!(
        store
            .finalize_nonce_with_notification_and_response("nonce", &claim, &handle, &response, now)
            .await
            .unwrap()
    );
    assert!(!store.claim_nonce("nonce", "again", now).await.unwrap());
    assert!(
        !store
            .finalize_nonce_with_notification_and_response("nonce", &claim, &handle, &response, now)
            .await
            .unwrap()
    );
    store.issue_nonce(&nonce).await.unwrap();
    assert!(!store.claim_nonce("nonce", "reissued", now).await.unwrap());
}

#[tokio::test]
async fn exact_response_continues_only_same_authorization_and_sender_binding() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let now = Timestamp::now();
    let mut original = fixture.access();
    original.expires_at = now + SignedDuration::from_secs(30);
    store.upsert_access("original", &original).await.unwrap();
    let response = fixture.response(&original);
    let handle = fixture.handle(&response);
    store
        .store_response_with_notification(&handle, &response, now)
        .await
        .unwrap();
    let retained: AccessRecord = read(
        &fixture.db().db,
        &key(ACCESS, Uuid::nil(), original.token_id.as_bytes()),
    )
    .unwrap()
    .unwrap();
    assert!(retained.retain_until >= response.expires_at);
    let mut successor = original.clone();
    successor.token_id = Uuid::new_v4();
    successor.expires_at = now + SignedDuration::from_mins(10);
    store.upsert_access("successor", &successor).await.unwrap();
    let later = now + SignedDuration::from_secs(60);
    assert!(
        store
            .find_response(
                response.issuance_id,
                original.token_id,
                &response.request_digest,
                later
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .find_response(
                response.issuance_id,
                successor.token_id,
                &response.request_digest,
                later
            )
            .await
            .unwrap(),
        Some(response.clone())
    );
    let mut wrong = successor.clone();
    wrong.token_id = Uuid::new_v4();
    wrong.dpop_jkt = Some("other-key".into());
    store.upsert_access("wrong-binding", &wrong).await.unwrap();
    assert!(
        store
            .find_response(
                response.issuance_id,
                wrong.token_id,
                &response.request_digest,
                later
            )
            .await
            .unwrap()
            .is_none()
    );
    let other_tenant = Uuid::new_v4();
    seed_tenant(fixture.db(), other_tenant, fixture.client, fixture.user);
    let mut foreign = successor.clone();
    foreign.tenant_id = other_tenant;
    assert_eq!(
        store.upsert_access("successor", &foreign).await,
        Err(CredentialStoreError::InvalidTransition)
    );
    foreign.token_id = Uuid::new_v4();
    store
        .upsert_access("foreign-tenant", &foreign)
        .await
        .unwrap();
    assert!(
        store
            .find_response(
                response.issuance_id,
                foreign.token_id,
                &response.request_digest,
                later
            )
            .await
            .unwrap()
            .is_none()
    );
    let tx = fixture.db().transaction();
    assert_eq!(
        revoke_for_scope(&tx, other_tenant, fixture.user, "client").unwrap(),
        1
    );
    tx.commit().unwrap();
    assert!(
        store
            .resolve_access("foreign-tenant", now)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .resolve_access("successor", now)
            .await
            .unwrap()
            .is_some()
    );
    let response_key = key(RESPONSE, Uuid::nil(), response.issuance_id.as_bytes());
    let tx = fixture.db().transaction();
    let mut stored: ResponseRecord = read_tx(&tx, &response_key, true).unwrap().unwrap();
    assert!(!stored.body.contains("private-exact-wire-response"));
    stored.body.replace_range(
        0..1,
        if stored.body.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    put_expiring(&tx, &response_key, &stored, stored.expires_at).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        store
            .find_response(
                response.issuance_id,
                successor.token_id,
                &response.request_digest,
                later
            )
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_lease_has_one_owner_and_revocation_blocks_finalization() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let access = fixture.access();
    let now = Timestamp::now();
    store.upsert_access("access", &access).await.unwrap();
    let mut response = fixture.response(&access);
    response.status = 202;
    let deferred = DeferredCredential {
        id: Uuid::new_v4(),
        transaction_hash: "transaction".into(),
        access: access.clone(),
        selection: response.selection.clone(),
        configuration_id: "identity".into(),
        format: nazo_digital_credentials::CredentialFormat::SdJwtVc,
        holder_bindings: vec![None],
        payload: DeferredPayload {
            dataset: serde_json::json!({"secret_claim":"Alice"}),
            status: None,
            issued_at: now,
            expires_at: response.expires_at,
        },
        ready_at: now - SignedDuration::from_secs(1),
        expires_at: response.expires_at,
    };
    store
        .store_deferred_with_response(&deferred, &response, now)
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        store.claim_ready_deferred("transaction", access.token_id, "a", now),
        store.claim_ready_deferred("transaction", access.token_id, "b", now)
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, DeferredClaimOutcome::Claimed(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, DeferredClaimOutcome::Busy { .. }))
            .count(),
        1
    );
    let lease = read::<DeferredRecord>(
        &fixture.db().db,
        &key(DEFERRED, Uuid::nil(), b"transaction"),
    )
    .unwrap()
    .unwrap()
    .lease
    .unwrap();
    assert!(
        !store
            .release_deferred("transaction", Uuid::new_v4(), &lease.claim_id, now)
            .await
            .unwrap()
    );
    let tx = fixture.db().transaction();
    assert_eq!(
        revoke_for_scope(&tx, fixture.tenant, fixture.user, "client").unwrap(),
        1
    );
    tx.commit().unwrap();
    let final_response = fixture.response(&access);
    let handle = fixture.handle(&final_response);
    assert!(
        !store
            .finalize_deferred_with_notification_and_response(
                "transaction",
                access.token_id,
                &lease.claim_id,
                &handle,
                &final_response,
                now
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .find_response(
                final_response.issuance_id,
                access.token_id,
                &final_response.request_digest,
                now
            )
            .await
            .unwrap()
            .is_none()
    );
    store.upsert_access("access", &access).await.unwrap();
    assert!(store.resolve_access("access", now).await.unwrap().is_none());
    assert!(
        fixture
            .db()
            .db
            .get_pinned(key(
                crate::tokens::REVOCATION,
                fixture.tenant,
                blake3::hash(access.token_id.to_string().as_bytes()).as_bytes()
            ))
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn notification_keeps_first_occurrence_and_rejects_conflicting_event() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let access = fixture.access();
    let now = Timestamp::now();
    store.upsert_access("access", &access).await.unwrap();
    let response = fixture.response(&access);
    let handle = fixture.handle(&response);
    store
        .store_response_with_notification(&handle, &response, now)
        .await
        .unwrap();
    let mut notification = IssuanceNotification {
        notification_id: handle.notification_id,
        token_id: access.token_id,
        event: NotificationEvent::CredentialAccepted,
        description: Some("saved".into()),
        occurred_at: now,
    };
    assert!(store.record_notification(&notification).await.unwrap());
    notification.occurred_at += SignedDuration::from_secs(1);
    assert!(store.record_notification(&notification).await.unwrap());
    let saved: NotificationRecord = read(
        &fixture.db().db,
        &key(
            NOTIFICATION,
            Uuid::nil(),
            notification.notification_id.as_bytes(),
        ),
    )
    .unwrap()
    .unwrap();
    assert_eq!(saved.occurred_at, Some(now));
    notification.event = NotificationEvent::CredentialDeleted;
    assert!(!store.record_notification(&notification).await.unwrap());
}

#[tokio::test]
async fn deferred_nonce_and_successor_finalization_commit_one_replayable_result() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let original = fixture.access();
    let now = Timestamp::now();
    store.upsert_access("original", &original).await.unwrap();
    let mut initial = fixture.response(&original);
    initial.status = 202;
    let intent = DeferredCredential {
        id: Uuid::new_v4(),
        transaction_hash: "deferred".into(),
        access: original.clone(),
        selection: initial.selection.clone(),
        configuration_id: "identity".into(),
        format: nazo_digital_credentials::CredentialFormat::SdJwtVc,
        holder_bindings: vec![None],
        payload: DeferredPayload {
            dataset: serde_json::json!({"claim":"source-data"}),
            status: None,
            issued_at: now,
            expires_at: initial.expires_at,
        },
        ready_at: now,
        expires_at: initial.expires_at,
    };
    store
        .issue_nonce(&NonceRecord {
            nonce_hash: "defer-nonce".into(),
            expires_at: original.expires_at,
        })
        .await
        .unwrap();
    assert!(
        store
            .claim_nonce("defer-nonce", "proof-claim", now)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .store_deferred_and_finalize_nonce_with_response(
                &intent,
                "defer-nonce",
                "wrong-claim",
                &initial,
                now
            )
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );
    assert!(
        store
            .find_response(
                initial.issuance_id,
                original.token_id,
                &initial.request_digest,
                now
            )
            .await
            .unwrap()
            .is_none()
    );
    store
        .store_deferred_and_finalize_nonce_with_response(
            &intent,
            "defer-nonce",
            "proof-claim",
            &initial,
            now,
        )
        .await
        .unwrap();
    assert!(
        !store
            .release_nonce("defer-nonce", "proof-claim", now)
            .await
            .unwrap()
    );
    let mut successor = original.clone();
    successor.token_id = Uuid::new_v4();
    store.upsert_access("successor", &successor).await.unwrap();
    let claim = store
        .claim_ready_deferred("deferred", successor.token_id, "deferred-claim", now)
        .await
        .unwrap();
    let DeferredClaimOutcome::Claimed(claimed) = claim else {
        panic!("eligible successor must own the deferred lease")
    };
    assert_eq!(*claimed, intent);
    let final_response = fixture.response(&successor);
    let handle = fixture.handle(&final_response);
    assert!(
        store
            .finalize_deferred_with_notification_and_response(
                "deferred",
                successor.token_id,
                "deferred-claim",
                &handle,
                &final_response,
                now
            )
            .await
            .unwrap()
    );
    assert!(
        !store
            .finalize_deferred_with_notification_and_response(
                "deferred",
                successor.token_id,
                "deferred-claim",
                &handle,
                &final_response,
                now
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .find_response(
                final_response.issuance_id,
                successor.token_id,
                &final_response.request_digest,
                now
            )
            .await
            .unwrap(),
        Some(final_response)
    );
}
