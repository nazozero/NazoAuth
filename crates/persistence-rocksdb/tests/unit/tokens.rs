use super::*;
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId, UserId, UserRole};
use std::path::PathBuf;

const TENANT: Uuid = Uuid::from_u128(0x100);
const CLIENT: Uuid = Uuid::from_u128(0x200);
const USER: Uuid = Uuid::from_u128(0x300);

struct Fixture {
    store: Option<RocksDb>,
    path: PathBuf,
}

impl Fixture {
    fn new(client_type: &str) -> Self {
        let path = std::env::temp_dir().join(format!("nazo-rocksdb-token-{}", Uuid::new_v4()));
        let store = RocksDb::open(&path).unwrap();
        seed(&store, client_type);
        Self {
            store: Some(store),
            path,
        }
    }

    fn db(&self) -> &RocksDb {
        self.store.as_ref().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn seed(store: &RocksDb, client_type: &str) {
    seed_tenant(store, client_type, TENANT);
}

fn seed_tenant(store: &RocksDb, client_type: &str, tenant: Uuid) {
    let context = TenantContext {
        tenant_id: TenantId::new(tenant).unwrap(),
        realm_id: RealmId::new(Uuid::from_u128(0x101)).unwrap(),
        organization_id: OrganizationId::new(Uuid::from_u128(0x102)).unwrap(),
    };
    let tx = store.transaction();
    put(
        &tx,
        &key(CLIENT_PRINCIPAL, tenant, CLIENT.as_bytes()),
        &ClientPrincipal {
            id: CLIENT,
            public_id: "test-client".into(),
            client_type: client_type.into(),
            active: true,
            epoch: 0,
            tenant: context,
        },
    )
    .unwrap();
    put(&tx, &key(CLIENT_PUBLIC_ID, tenant, b"test-client"), &CLIENT).unwrap();
    put(
        &tx,
        &key(USER_PRINCIPAL, tenant, USER.as_bytes()),
        &Principal {
            authorization_epoch: 0,
            user_id: UserId::new(USER).unwrap(),
            tenant: context,
            role: UserRole::User,
            active: true,
        },
    )
    .unwrap();
    put(
        &tx,
        &key(USER_CLAIMS, tenant, USER.as_bytes()),
        &SubjectClaims {
            subject: UserId::new(USER).unwrap(),
            preferred_username: "alice".into(),
            name: Some("Alice".into()),
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            email: "alice@example.test".into(),
            email_verified: true,
            address: None,
            phone_number: None,
            phone_number_verified: false,
            updated_at: Timestamp::now().as_second(),
        },
    )
    .unwrap();
    tx.commit().unwrap();
}

fn base(mode: TokenIssuanceMode) -> CommitTokenIssuance {
    let id = Uuid::now_v7();
    CommitTokenIssuance {
        authorization_id: Some(id),
        principal_state: TokenPrincipalState {
            client_epoch: 0,
            user_epoch: Some(0),
            subject_bound: false,
        },
        subject: USER.to_string(),
        issuance_id: id,
        tenant_id: TENANT,
        client_id: CLIENT,
        user_id: Some(USER),
        mode,
        access_token_jti: Uuid::new_v4().to_string(),
        access_token_expires_at: Timestamp::now().as_second() + 300,
        refresh_token: None,
        native_sso_source: None,
        audit_fields: nazo_auth::TokenIssuedAuditFields {
            client_id: "test-client".into(),
            subject_hash: "subject-digest".into(),
            scope: "openid".into(),
            audience: vec!["api".into()],
        },
    }
}

fn code_mode(identity: &str) -> TokenIssuanceMode {
    TokenIssuanceMode::AuthorizationCode {
        code_identity: identity.into(),
        grant_expires_at: Timestamp::now() + SignedDuration::from_secs(120),
        holder: nazo_auth::AuthorizationCodeHolderEvidence::from_verified_requirements(
            nazo_auth::AuthorizationCodeClientAuthentication::Authenticated,
            Some("original-pkce-s256".into()),
            None,
            None,
            None,
        )
        .unwrap(),
    }
}

fn new_family(raw: &str) -> CommitTokenIssuance {
    let mut input = base(TokenIssuanceMode::Fresh);
    let now = Timestamp::now();
    let family = Uuid::now_v7();
    input.authorization_id = Some(family);
    input.refresh_token = Some(RefreshTokenCommit::IssueNew {
        token: NewRefreshToken {
            raw_token: raw.into(),
            member_id: Uuid::now_v7(),
            tenant_id: TENANT,
            family_id: family,
            rotated_from_id: None,
            lost_response_retry: None,
            client_id: CLIENT,
            user_id: Some(USER),
            audiences: vec!["api".into()],
            issued_at: now,
            expires_at: now + SignedDuration::from_secs(900),
            id_token_sid: Some(Uuid::new_v4().to_string()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
            client_attestation_jkt: None,
        },
        contract: RefreshContract {
            subject: USER.to_string(),
            scopes: vec!["openid".into()],
            audiences: vec!["api".into()],
            authorization_details: serde_json::json!([]),
            authentication_context: nazo_auth::RefreshTokenAuthenticationContext {
                version: nazo_auth::RefreshTokenAuthenticationContext::CURRENT_VERSION,
                issuer: "https://issuer.example.test".into(),
                audience: "test-client".into(),
                auth_time: now.as_second() - 10,
                amr: vec!["pwd".into()],
                oidc_sid: None,
                acr: None,
                userinfo_claim_requests: Default::default(),
                id_token_claim_requests: Default::default(),
            },
        },
    });
    input
}

fn rotation(source: &RefreshToken, raw: &str) -> CommitTokenIssuance {
    let mut input = base(TokenIssuanceMode::Fresh);
    input.authorization_id = Some(source.token_family_id);
    input.refresh_token = Some(RefreshTokenCommit::UseExisting {
        authority: source.authority(),
        rotation: Some(NewRefreshToken {
            raw_token: raw.into(),
            member_id: Uuid::now_v7(),
            tenant_id: source.tenant_id,
            family_id: source.token_family_id,
            rotated_from_id: Some(source.id),
            lost_response_retry: None,
            client_id: source.client_id,
            user_id: source.user_id,
            audiences: source.audience.clone(),
            issued_at: Timestamp::now(),
            expires_at: Timestamp::now() + SignedDuration::from_secs(900),
            id_token_sid: Some(Uuid::new_v4().to_string()),
            dpop_jkt: source.dpop_jkt.clone(),
            mtls_x5t_s256: source.mtls_x5t_s256.clone(),
            client_attestation_jkt: source.client_attestation_jkt.clone(),
        }),
    });
    input
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_code_redemption_has_one_committed_owner_and_audit() {
    let fixture = Fixture::new("confidential");
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(12));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let db = fixture.db().clone();
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            db.commit_token_issuance(base(code_mode("authorization_code:v2:one-use")))
                .await
                .unwrap()
        });
    }
    let mut committed = 0;
    let mut used = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            CommitTokenIssuanceResult::Committed => committed += 1,
            CommitTokenIssuanceResult::AlreadyUsed => used += 1,
            other => panic!("unexpected redemption outcome {other:?}"),
        }
    }
    assert_eq!((committed, used), (1, 11));
    let receipt = fixture
        .db()
        .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:one-use")
        .await
        .unwrap()
        .unwrap();
    assert!(receipt.authorization_code_holder.is_some());
    assert!(
        fixture
            .db()
            .single_use_redemption(Uuid::new_v4(), CLIENT, "authorization_code:v2:one-use")
            .await
            .unwrap()
            .is_none()
    );
    let prefix = key(0x70, Uuid::nil(), &[]);
    let audits = fixture
        .db()
        .db
        .iterator(IteratorMode::From(&prefix, Direction::Forward))
        .map(Result::unwrap)
        .take_while(|(key, _)| key.starts_with(&prefix))
        .count();
    assert_eq!(audits, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_refresh_consumption_compromises_the_whole_family() {
    let fixture = Fixture::new("confidential");
    fixture
        .db()
        .commit_token_issuance(new_family("root"))
        .await
        .unwrap();
    let original = fixture
        .db()
        .refresh_token(TENANT, "root")
        .await
        .unwrap()
        .unwrap();
    let (a, b) = tokio::join!(
        fixture
            .db()
            .commit_token_issuance(rotation(&original, "left")),
        fixture
            .db()
            .commit_token_issuance(rotation(&original, "right")),
    );
    let results = [a.unwrap(), b.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == CommitTokenIssuanceResult::Committed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == CommitTokenIssuanceResult::RotationConflict)
            .count(),
        1
    );
    assert!(
        !fixture
            .db()
            .refresh_family_active(TENANT, original.token_family_id, USER)
            .await
            .unwrap()
    );
    for raw in ["root", "left", "right"] {
        if let Some(token) = fixture.db().refresh_token(TENANT, raw).await.unwrap() {
            assert!(token.revoked_at.is_some());
        }
    }
}

#[tokio::test]
async fn public_rotation_retains_all_live_proofs_and_confidential_rotation_is_bounded() {
    for (client_type, oldest_present) in [("public", true), ("confidential", false)] {
        let fixture = Fixture::new(client_type);
        fixture
            .db()
            .commit_token_issuance(new_family("generation-0"))
            .await
            .unwrap();
        let mut token = fixture
            .db()
            .refresh_token(TENANT, "generation-0")
            .await
            .unwrap()
            .unwrap();
        for generation in 1..=70 {
            let raw = format!("generation-{generation}");
            assert_eq!(
                fixture
                    .db()
                    .commit_token_issuance(rotation(&token, &raw))
                    .await
                    .unwrap(),
                CommitTokenIssuanceResult::Committed
            );
            token = fixture
                .db()
                .refresh_token(TENANT, &raw)
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            fixture
                .db()
                .refresh_token(TENANT, "generation-0")
                .await
                .unwrap()
                .is_some(),
            oldest_present
        );
        assert!(
            fixture
                .db()
                .refresh_family_active(TENANT, token.token_family_id, USER)
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn sender_bound_retry_requires_the_direct_predecessor_and_preserves_claims() {
    let fixture = Fixture::new("confidential");
    let mut input = new_family("bound-original");
    if let Some(RefreshTokenCommit::IssueNew { token, .. }) = &mut input.refresh_token {
        token.dpop_jkt = Some("checked-sender".into());
    }
    fixture.db().commit_token_issuance(input).await.unwrap();
    let original = fixture
        .db()
        .refresh_token(TENANT, "bound-original")
        .await
        .unwrap()
        .unwrap();
    fixture
        .db()
        .commit_token_issuance(rotation(&original, "bound-successor"))
        .await
        .unwrap();
    let snapshot = fixture
        .db()
        .refresh_token_snapshot(TENANT, "bound-original", CLIENT, Timestamp::now(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.presented.id, original.id);
    assert!(snapshot.prepared_subject.is_some());
    let successor = snapshot.successor.unwrap().unwrap();
    let mut retry = rotation(&successor, "retry-successor");
    if let Some(RefreshTokenCommit::UseExisting {
        rotation: Some(token),
        ..
    }) = &mut retry.refresh_token
    {
        token.lost_response_retry = Some(nazo_auth::LostResponseRetry {
            original_id: original.id,
            original_blake3: original.token_blake3,
            retry_started_at: Timestamp::now(),
        });
    }
    assert_eq!(
        fixture.db().commit_token_issuance(retry).await.unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    assert!(
        fixture
            .db()
            .refresh_token_snapshot(TENANT, "bound-original", CLIENT, Timestamp::now(), false)
            .await
            .unwrap()
            .unwrap()
            .successor
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn required_audit_failure_rolls_back_receipt_family_and_indexes() {
    let fixture = Fixture::new("confidential");
    let mut input = new_family("must-not-survive");
    let family = input.refresh_token.as_ref().unwrap().family_id();
    input.mode = code_mode("authorization_code:v2:audit-rollback");
    input.audit_fields.scope = "x".repeat(nazo_persistence::MAX_SECURITY_AUDIT_PAYLOAD_BYTES + 1);
    assert!(fixture.db().commit_token_issuance(input).await.is_err());
    assert!(
        fixture
            .db()
            .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:audit-rollback")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .db()
            .refresh_token(TENANT, "must-not-survive")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        crate::db::read::<Family>(&fixture.db().db, &key(FAMILY, TENANT, family.as_bytes()))
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rotation_and_revocation_leave_no_live_successor() {
    let fixture = Fixture::new("confidential");
    fixture
        .db()
        .commit_token_issuance(new_family("race-original"))
        .await
        .unwrap();
    let original = fixture
        .db()
        .refresh_token(TENANT, "race-original")
        .await
        .unwrap()
        .unwrap();
    let (rotated, revoked) = tokio::join!(
        fixture
            .db()
            .commit_token_issuance(rotation(&original, "race-successor")),
        fixture.db().revoke_token_with_audit(
            TokenRevocation {
                tenant_id: TENANT,
                client_id: CLIENT,
                raw_token: "race-original",
                access_token: None,
            },
            "test-client",
            "ip-digest"
        ),
    );
    assert!(matches!(
        rotated.unwrap(),
        CommitTokenIssuanceResult::Committed | CommitTokenIssuanceResult::RefreshGrantUnavailable
    ));
    assert_eq!(revoked.unwrap(), 1);
    assert!(
        !fixture
            .db()
            .refresh_family_active(TENANT, original.token_family_id, USER)
            .await
            .unwrap()
    );
    if let Some(successor) = fixture
        .db()
        .refresh_token(TENANT, "race-successor")
        .await
        .unwrap()
    {
        assert!(successor.revoked_at.is_some());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn principal_termination_fences_issuance_and_new_refresh_families() {
    let fixture = Fixture::new("confidential");
    let store = fixture.db().clone();
    let (issued, disabled) = tokio::join!(
        fixture
            .db()
            .commit_token_issuance(new_family("terminate-race")),
        store.run(|store| {
            let tx = store.transaction();
            let record_key = key(USER_PRINCIPAL, TENANT, USER.as_bytes());
            let mut principal: Principal = read_tx(&tx, &record_key, true)?.unwrap();
            principal.active = false;
            principal.authorization_epoch += 1;
            put(&tx, &record_key, &principal)?;
            revoke_families(&tx, TENANT, None, Some(USER))?;
            tx.commit().map_err(map_error)
        }),
    );
    disabled.unwrap();
    assert!(matches!(
        issued.unwrap(),
        CommitTokenIssuanceResult::Committed | CommitTokenIssuanceResult::SubjectInactive
    ));
    if let Some(token) = fixture
        .db()
        .refresh_token(TENANT, "terminate-race")
        .await
        .unwrap()
    {
        assert!(token.revoked_at.is_some());
    }
    assert_eq!(
        fixture
            .db()
            .commit_token_issuance(base(TokenIssuanceMode::Fresh))
            .await
            .unwrap(),
        CommitTokenIssuanceResult::SubjectInactive
    );
}

#[tokio::test]
async fn family_capacity_retires_oldest_atomically_and_subject_bindings_do_not_collide() {
    let fixture = Fixture::new("public");
    let mut first = None;
    for index in 0..11 {
        let raw = format!("capacity-{index}");
        fixture
            .db()
            .commit_token_issuance(new_family(&raw))
            .await
            .unwrap();
        if index == 0 {
            first = fixture.db().refresh_token(TENANT, &raw).await.unwrap();
        }
    }
    assert!(
        !fixture
            .db()
            .refresh_family_active(TENANT, first.unwrap().token_family_id, USER)
            .await
            .unwrap()
    );
    let mut private = base(TokenIssuanceMode::Fresh);
    private.subject = "private-subject".into();
    fixture.db().commit_token_issuance(private).await.unwrap();
    let prepared = fixture
        .db()
        .token_principal_state(TENANT, 0, Some(USER), "private-subject")
        .await
        .unwrap();
    assert!(prepared.subject_bound);
    assert!(
        fixture
            .db()
            .token_principal_state(TENANT, 0, Some(Uuid::new_v4()), "private-subject")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn restore_invalidation_is_atomic_idempotent_and_covers_all_tenants() {
    use nazo_persistence::RecoveryInvalidationStore;
    let fixture = Fixture::new("confidential");
    let other_tenant = Uuid::new_v4();
    seed_tenant(fixture.db(), "confidential", other_tenant);
    let mut other = new_family("restore-other-tenant");
    other.tenant_id = other_tenant;
    if let Some(RefreshTokenCommit::IssueNew { token, .. }) = &mut other.refresh_token {
        token.tenant_id = other_tenant;
    }
    fixture.db().commit_token_issuance(other).await.unwrap();
    fixture
        .db()
        .commit_token_issuance(new_family("restore-original"))
        .await
        .unwrap();
    let original = fixture
        .db()
        .refresh_token(TENANT, "restore-original")
        .await
        .unwrap()
        .unwrap();
    let operation = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let hash = "a".repeat(64);
    let now = Timestamp::now();
    let receipt = fixture
        .db()
        .invalidate_after_restore(operation, &hash, epoch, now, now)
        .await
        .unwrap();
    assert_eq!(receipt.revoked_refresh_tokens, 2);
    assert_eq!(
        fixture
            .db()
            .invalidate_after_restore(
                operation,
                &hash,
                epoch,
                now + SignedDuration::from_secs(1),
                now
            )
            .await
            .unwrap(),
        receipt
    );
    assert!(
        !fixture
            .db()
            .refresh_family_active(TENANT, original.token_family_id, USER)
            .await
            .unwrap()
    );
    assert!(
        fixture
            .db()
            .refresh_token(other_tenant, "restore-other-tenant")
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert!(
        fixture
            .db()
            .invalidate_after_restore(Uuid::new_v4(), &hash, epoch, now, now)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_while_waiting_for_required_audit_rolls_back_the_whole_issuance() {
    let fixture = Fixture::new("confidential");
    let mut input = new_family("expires-before-audit");
    input.mode = TokenIssuanceMode::SingleUse {
        grant_key: "deadline-at-audit".into(),
        grant_expires_at: Timestamp::now() + SignedDuration::from_millis(500),
    };
    let audit_key = key(
        crate::audit::EVENTS,
        Uuid::nil(),
        input.issuance_id.as_bytes(),
    );
    let blocker = fixture.db().transaction();
    assert!(
        blocker
            .get_pinned_for_update(&audit_key, true)
            .unwrap()
            .is_none()
    );
    let db = fixture.db().clone();
    let attempt = tokio::spawn(async move { db.commit_token_issuance(input).await });
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    drop(blocker);
    assert_eq!(
        attempt.await.unwrap().unwrap(),
        CommitTokenIssuanceResult::GrantExpired
    );
    assert!(
        fixture
            .db()
            .refresh_token(TENANT, "expires-before-audit")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .db()
            .single_use_redemption(TENANT, CLIENT, "deadline-at-audit")
            .await
            .unwrap()
            .is_none()
    );
    assert!(fixture.db().db.get_pinned(&audit_key).unwrap().is_none());
}

#[tokio::test]
async fn native_sso_survives_source_rotation_and_its_own_capacity_retirement() {
    let fixture = Fixture::new("confidential");
    fixture
        .db()
        .commit_token_issuance(new_family("native-source"))
        .await
        .unwrap();
    let source = fixture
        .db()
        .refresh_token(TENANT, "native-source")
        .await
        .unwrap()
        .unwrap();
    fixture
        .db()
        .commit_token_issuance(rotation(&source, "native-source-rotated"))
        .await
        .unwrap();
    for i in 1..nazo_auth::MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE {
        fixture
            .db()
            .commit_token_issuance(new_family(&format!("native-capacity-{i}")))
            .await
            .unwrap();
    }
    let fence = nazo_auth::NativeSsoSourceFence {
        tenant_id: TENANT,
        user_id: USER,
        source_client_id: "test-client".into(),
        family_id: source.token_family_id,
        device_secret_expires_at: source.expires_at,
    };
    let mut destination = new_family("native-destination");
    destination.native_sso_source = Some(fence.clone());
    assert_eq!(
        fixture
            .db()
            .commit_token_issuance(destination)
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    assert!(
        !fixture
            .db()
            .refresh_family_active(TENANT, source.token_family_id, USER)
            .await
            .unwrap()
    );
    assert!(
        fixture
            .db()
            .refresh_token(TENANT, "native-destination")
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    let mut after_revocation = new_family("native-after-revocation");
    after_revocation.native_sso_source = Some(fence);
    assert_eq!(
        fixture
            .db()
            .commit_token_issuance(after_revocation)
            .await
            .unwrap(),
        CommitTokenIssuanceResult::RefreshGrantUnavailable
    );
    assert!(
        fixture
            .db()
            .refresh_token(TENANT, "native-after-revocation")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_source_family_expiry_is_checked_after_required_audit_wait() {
    let fixture = Fixture::new("confidential");
    let mut source = new_family("native-short-source");
    let source_id = source.refresh_token.as_ref().unwrap().family_id();
    if let Some(RefreshTokenCommit::IssueNew { token, .. }) = &mut source.refresh_token {
        token.expires_at = Timestamp::now() + SignedDuration::from_millis(500);
    }
    fixture.db().commit_token_issuance(source).await.unwrap();
    let mut destination = new_family("native-expired-destination");
    destination.native_sso_source = Some(nazo_auth::NativeSsoSourceFence {
        tenant_id: TENANT,
        user_id: USER,
        source_client_id: "test-client".into(),
        family_id: source_id,
        device_secret_expires_at: Timestamp::now() + SignedDuration::from_secs(600),
    });
    let audit_key = key(
        crate::audit::EVENTS,
        Uuid::nil(),
        destination.issuance_id.as_bytes(),
    );
    let blocker = fixture.db().transaction();
    assert!(
        blocker
            .get_pinned_for_update(&audit_key, true)
            .unwrap()
            .is_none()
    );
    let db = fixture.db().clone();
    let attempt = tokio::spawn(async move { db.commit_token_issuance(destination).await });
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    drop(blocker);
    assert_eq!(
        attempt.await.unwrap().unwrap(),
        CommitTokenIssuanceResult::RefreshGrantUnavailable
    );
    assert!(
        fixture
            .db()
            .refresh_token(TENANT, "native-expired-destination")
            .await
            .unwrap()
            .is_none()
    );
    assert!(fixture.db().db.get_pinned(audit_key).unwrap().is_none());
}

#[test]
fn crash_writer() {
    use std::io::Write;
    let Some(path) = std::env::var_os("NAZO_ROCKSDB_CRASH_PATH") else {
        return;
    };
    let db = RocksDb::open(path).unwrap();
    seed(&db, "confidential");
    let mut input = new_family("crash-original");
    input.mode = code_mode("authorization_code:v2:crash-consumed");
    assert_eq!(
        commit(&db, input).unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    let original = presentation(
        &db.db.snapshot(),
        TENANT,
        blake3::hash(b"crash-original").as_bytes(),
        None,
        false,
    )
    .unwrap()
    .unwrap()
    .presented;
    assert_eq!(
        commit(&db, rotation(&original, "crash-successor")).unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    let tx = db.transaction();
    let family_key = key(FAMILY, TENANT, original.token_family_id.as_bytes());
    let mut family: Family = read_tx(&tx, &family_key, true).unwrap().unwrap();
    family.revoked_at = Some(Timestamp::now());
    put_expiring(&tx, &family_key, &family, family.expires_at).unwrap();
    put(&tx, &key(SUBJECT, TENANT, b"uncommitted-subject"), &USER).unwrap();
    println!("READY_FOR_FORCED_TERMINATION");
    std::io::stdout().flush().unwrap();
    // Keep an uncommitted write batch alive until the parent sends SIGKILL.
    loop {
        std::thread::park();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn forced_process_restart_keeps_acknowledged_consumption_without_partial_writes() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let path = std::env::temp_dir().join(format!("nazo-rocksdb-crash-{}", Uuid::new_v4()));
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tokens::tests::crash_writer",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("NAZO_ROCKSDB_CRASH_PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line.unwrap().contains("READY_FOR_FORCED_TERMINATION") {
                sender.send(()).unwrap();
                break;
            }
        }
    });
    let ready = receiver.recv_timeout(std::time::Duration::from_secs(30));
    let _ = child.kill();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    ready.expect("writer must acknowledge before forced termination");
    assert!(!status.success());
    let reopened = RocksDb::open(&path).unwrap();
    assert!(
        reopened
            .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:crash-consumed")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        reopened
            .commit_token_issuance(base(code_mode("authorization_code:v2:crash-consumed")))
            .await
            .unwrap(),
        CommitTokenIssuanceResult::AlreadyUsed
    );
    let original = reopened
        .refresh_token(TENANT, "crash-original")
        .await
        .unwrap()
        .unwrap();
    let successor = reopened
        .refresh_token(TENANT, "crash-successor")
        .await
        .unwrap()
        .unwrap();
    assert!(original.revoked_at.is_some());
    assert!(successor.revoked_at.is_none());
    assert!(
        crate::db::read::<Uuid>(&reopened.db, &key(SUBJECT, TENANT, b"uncommitted-subject"))
            .unwrap()
            .is_none()
    );
    drop(reopened);
    std::fs::remove_dir_all(path).unwrap();
}
