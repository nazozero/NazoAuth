use crate::support::clients;
use clients::client;

use super::*;
use crate::{MfaTotpKey, MfaTotpKeyRing};
use nazo_auth::{
    AdminClientRepositoryPort, AdminGrantRepositoryPort, DynamicRegistrationClientStore,
    DynamicRegistrationDependencyError,
};
use nazo_identity::{
    OrganizationId, RealmId,
    mfa::{MFA_BACKUP_CODE_COUNT, MFA_TOTP_PERIOD_SECONDS, totp_for_step},
    ports::{
        EncodedSecretHash, MfaRepositoryPort, PasskeyAuthenticationUpdate, PasskeyRepositoryPort,
        PasswordHashInput, RememberedMfaDevicePort, TotpEnrollmentCheck, TotpVerificationOutcome,
    },
};
use nazo_key_management::{
    PersistedSigningKeyset, SigningKeyRepository, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult,
};
use rocksdb::{Direction, IteratorMode};
use std::path::PathBuf;

struct Fixture {
    store: Option<RocksDb>,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("nazo-rocksdb-account-{}", Uuid::new_v4()));
        let store = RocksDb::open(&path).unwrap();
        Self {
            store: Some(store),
            path,
        }
    }
    fn db(&self) -> &RocksDb {
        self.store.as_ref().unwrap()
    }
    fn restart(&mut self) {
        drop(self.store.take());
        self.store = Some(RocksDb::open(&self.path).unwrap());
    }
    fn user(&self, name: &str, role: UserRole) -> PublicAccount {
        let tx = self.db().transaction();
        let account = create_user_tx(
            &tx,
            new_user(
                TenantContext::default_system(),
                name,
                &format!("{name}@example.test"),
            ),
            role,
        )
        .unwrap();
        tx.commit().unwrap();
        account
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
fn new_user(tenant: TenantContext, name: &str, email: &str) -> NewUser {
    NewUser {
        tenant,
        username: name.into(),
        email: email.into(),
        password_hash: PasswordHashInput::new("fixture-password-verifier").unwrap(),
        email_verified: true,
    }
}
fn other_context() -> TenantContext {
    TenantContext {
        tenant_id: TenantId::new(Uuid::new_v4()).unwrap(),
        realm_id: RealmId::new(Uuid::new_v4()).unwrap(),
        organization_id: OrganizationId::new(Uuid::new_v4()).unwrap(),
    }
}
fn hashes() -> Vec<EncodedSecretHash> {
    (0..MFA_BACKUP_CODE_COUNT)
        .map(|i| EncodedSecretHash::new(format!("fixture-backup-{i}")).unwrap())
        .collect()
}
fn ring(id: &str, byte: u8, previous: Option<(&str, u8)>) -> MfaTotpKeyRing {
    MfaTotpKeyRing::new(
        MfaTotpKey::new(id, [byte; 32]).unwrap(),
        previous.map(|(id, b)| MfaTotpKey::new(id, [b; 32]).unwrap()),
    )
    .unwrap()
}
fn audit_count(db: &RocksDb, tenant: TenantId) -> usize {
    let prefix = key(crate::audit::EVENTS, Uuid::nil(), &[]);
    let tenant = tenant.as_uuid().to_string();
    db.db
        .iterator(IteratorMode::From(&prefix, Direction::Forward))
        .take_while(|r| r.as_ref().unwrap().0.starts_with(&prefix))
        .filter(|entry| {
            let value: serde_json::Value = crate::db::decode(&entry.as_ref().unwrap().1).unwrap();
            value["payload"]["tenant_id"].as_str() == Some(tenant.as_str())
        })
        .count()
}

#[tokio::test]
async fn client_authority_and_credentials_commit_with_audit_and_reject_stale_policy() {
    let fixture = Fixture::new();
    let actor = fixture.user("client-admin", UserRole::Admin { level: 2 });
    let tenant = actor.principal.tenant;
    let original = client(tenant, "client");
    let oversized = "x".repeat(nazo_persistence::MAX_SECURITY_AUDIT_PAYLOAD_BYTES);
    assert!(
        fixture
            .db()
            .insert_with_required_audit(
                &original,
                Some("client-secret-v1:salt:digest"),
                Some("rat"),
                actor.id(),
                &oversized
            )
            .await
            .is_err()
    );
    assert!(
        AdminClientRepositoryPort::by_client_id(fixture.db(), original.tenant_id, "client")
            .await
            .unwrap()
            .is_none()
    );
    fixture
        .db()
        .insert_with_required_audit(
            &original,
            Some("client-secret-v1:salt:digest"),
            Some("rat"),
            actor.id(),
            "source",
        )
        .await
        .unwrap();
    let snapshot = fixture
        .db()
        .by_registration_access_token(original.tenant_id, "client", "rat")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.client, original);
    assert!(snapshot.has_client_secret);
    assert_eq!(snapshot.secret_salt.as_deref(), Some("salt"));
    let mut restricted = original.clone();
    restricted.registration.security_policy.session_management = true;
    fixture
        .db()
        .update_with_required_audit(&original, &restricted, actor.id(), "source")
        .await
        .unwrap();
    assert_eq!(
        fixture
            .db()
            .replace_registration(
                &original,
                Some("replacement-secret"),
                "rat",
                Some("new-rat"),
                "source"
            )
            .await
            .err(),
        Some(DynamicRegistrationDependencyError::PolicyChanged)
    );
    assert!(
        fixture
            .db()
            .by_registration_access_token(original.tenant_id, "client", "rat")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .db()
            .client_secret_digest_matches(
                original.tenant_id,
                original.id,
                "client-secret-v1:salt:digest"
            )
            .await
            .unwrap()
    );
    let mut public = restricted.clone();
    public.registration.client_type = "public".into();
    public.registration.token_endpoint_auth_method = "none".into();
    fixture
        .db()
        .update_with_required_audit(&restricted, &public, actor.id(), "source")
        .await
        .unwrap();
    assert!(
        !fixture
            .db()
            .client_secret_digest_matches(
                original.tenant_id,
                original.id,
                "client-secret-v1:salt:digest"
            )
            .await
            .unwrap()
    );
    assert_eq!(
        crate::clients::client_presentation(
            &fixture.db().db.snapshot(),
            original.tenant_id,
            "client"
        )
        .unwrap()
        .unwrap()
        .client_name,
        "client"
    );
    assert!(
        crate::clients::client_userinfo(
            &fixture.db().db.snapshot(),
            original.tenant_id,
            original.id
        )
        .unwrap()
        .unwrap()
        .is_active
    );
}

#[tokio::test]
async fn client_and_grant_pages_follow_persisted_order_without_stale_index_entries() {
    let fixture = Fixture::new();
    let account = fixture.user("grant", UserRole::User);
    let tenant = account.principal.tenant;
    let first = client(tenant, "first");
    let second = client(tenant, "second");
    for c in [&first, &second] {
        let tx = fixture.db().transaction();
        crate::clients::insert_client_tx(&tx, c, None, None, 0).unwrap();
        tx.commit().unwrap();
    }
    let (page, count) = AdminClientRepositoryPort::page(fixture.db(), first.tenant_id, 0, 1)
        .await
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(page[0].id, second.id);
    let scopes = vec!["openid".into()];
    let details = json!([]);
    for (c, seconds) in [(&first, 10), (&second, 20), (&first, 30)] {
        let tx = fixture.db().transaction();
        crate::grants::write_grant_tx(
            &tx,
            first.tenant_id,
            account.id(),
            c.id,
            &scopes,
            &[],
            &details,
            true,
            Timestamp::from_second(seconds).unwrap(),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let page = AdminGrantRepositoryPort::page(fixture.db(), first.tenant_id, 1, 0)
        .await
        .unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.grants[0].client_id, first.client_id);
    assert_eq!(page.grants[0].authorization_count, Some(2));
    assert_eq!(
        page.grants[0].last_authorized_at,
        Some(Timestamp::from_second(30).unwrap())
    );
    let tx = fixture.db().transaction();
    crate::grants::delete_for_client_tx(&tx, first.tenant_id, first.id).unwrap();
    tx.commit().unwrap();
    let page = AdminGrantRepositoryPort::page(fixture.db(), first.tenant_id, 2, 0)
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.grants[0].client_id, second.client_id);
}

#[tokio::test]
async fn concurrent_unique_registration_is_tenant_scoped_and_survives_reopen() {
    let mut fixture = Fixture::new();
    let tenant = TenantContext::default_system();
    let (a, b) = tokio::join!(
        fixture
            .db()
            .create_user(new_user(tenant, "alice", "Alice@example.test")),
        fixture
            .db()
            .create_user(new_user(tenant, "bob", "alice@example.test")),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        a.as_ref().err().or(b.as_ref().err()),
        Some(&RepositoryError::Conflict)
    );
    let account = a.or(b).unwrap();
    let other = other_context();
    fixture
        .db()
        .create_user(new_user(other, "alice", "alice@example.test"))
        .await
        .unwrap();
    assert!(
        fixture
            .db()
            .account_by_id(other.tenant_id, account.principal.user_id)
            .await
            .unwrap()
            .is_none()
    );
    fixture.restart();
    assert_eq!(
        fixture
            .db()
            .account_by_id(tenant.tenant_id, account.principal.user_id)
            .await
            .unwrap()
            .unwrap()
            .id(),
        account.id()
    );
    let page = AdminUserRepositoryPort::page(fixture.db(), tenant.tenant_id, 1, 0)
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.users[0].id(), account.id());
}

#[tokio::test]
async fn administrator_creation_and_mutation_roll_back_on_required_audit_failure() {
    let fixture = Fixture::new();
    let actor = fixture.user("admin", UserRole::Admin { level: 2 });
    let target = fixture.user("target", UserRole::User);
    let context = target.principal.tenant;
    let count = audit_count(fixture.db(), context.tenant_id);
    let oversized = "x".repeat(nazo_persistence::MAX_SECURITY_AUDIT_PAYLOAD_BYTES);
    assert!(
        fixture
            .db()
            .create_user_with_required_audit(
                new_user(context, "new", "new@example.test"),
                actor.principal.user_id,
                oversized.clone()
            )
            .await
            .is_err()
    );
    assert!(
        !fixture
            .db()
            .email_exists(context.tenant_id, "new@example.test")
            .await
            .unwrap()
    );
    assert!(
        fixture
            .db()
            .update_authorized_with_required_audit(
                context,
                actor.principal.user_id,
                target.principal.user_id,
                AdminUserUpdate {
                    role: None,
                    admin_level: None,
                    active: Some(false)
                },
                oversized
            )
            .await
            .is_err()
    );
    let retained = fixture
        .db()
        .account_by_id(context.tenant_id, target.principal.user_id)
        .await
        .unwrap()
        .unwrap();
    assert!(retained.principal.active);
    assert_eq!(retained.principal.authorization_epoch, 0);
    assert_eq!(audit_count(fixture.db(), context.tenant_id), count);
    let changed = fixture
        .db()
        .update_authorized_with_required_audit(
            context,
            actor.principal.user_id,
            target.principal.user_id,
            AdminUserUpdate {
                role: None,
                admin_level: None,
                active: Some(false),
            },
            "source-digest".into(),
        )
        .await
        .unwrap();
    assert!(
        matches!(changed, AdminUserUpdateOutcome::Updated(ref a) if !a.principal.active && a.principal.authorization_epoch == 1)
    );
}

#[tokio::test]
async fn avatar_cas_replay_and_aba_fence_preserve_the_selected_object() {
    let fixture = Fixture::new();
    let user = fixture.user("avatar", UserRole::User);
    let tenant = user.principal.tenant.tenant_id;
    let id = user.principal.user_id;
    let first = fixture
        .db()
        .compare_and_set_avatar(tenant, id, None, 0, Some("a".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.profile.avatar_revision, 1);
    assert!(
        fixture
            .db()
            .compare_and_set_avatar(tenant, id, None, 0, Some("a".into()))
            .await
            .unwrap()
            .is_some()
    );
    fixture
        .db()
        .compare_and_set_avatar(tenant, id, Some("a"), 1, Some("b".into()))
        .await
        .unwrap()
        .unwrap();
    let returned = fixture
        .db()
        .compare_and_set_avatar(tenant, id, Some("b"), 2, Some("a".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(returned.profile.avatar_revision, 3);
    assert!(
        fixture
            .db()
            .compare_and_set_avatar(tenant, id, Some("a"), 1, Some("stale".into()))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .db()
            .account_by_id(tenant, id)
            .await
            .unwrap()
            .unwrap()
            .profile
            .avatar_url
            .as_deref(),
        Some("a")
    );
}

#[tokio::test]
async fn hierarchy_policy_distinguishes_cross_tenant_targets_and_preserves_no_op_accounts() {
    let fixture = Fixture::new();
    let actor = fixture.user("hierarchy-admin", UserRole::Admin { level: 2 });
    let context = actor.principal.tenant;
    let foreign = fixture
        .db()
        .create_user(new_user(other_context(), "foreign", "foreign@example.test"))
        .await
        .unwrap();
    let empty = AdminUserUpdate {
        role: None,
        admin_level: None,
        active: None,
    };
    assert_eq!(
        fixture
            .db()
            .update_authorized_with_required_audit(
                context,
                actor.principal.user_id,
                foreign.principal.user_id,
                empty.clone(),
                "source".into()
            )
            .await
            .unwrap(),
        AdminUserUpdateOutcome::Denied(AdminPolicyError::CrossTenant)
    );
    let target = fixture.user("hierarchy-target", UserRole::User);
    let result = fixture
        .db()
        .update_authorized_with_required_audit(
            context,
            actor.principal.user_id,
            target.principal.user_id,
            empty,
            "source".into(),
        )
        .await
        .unwrap();
    assert_eq!(result, AdminUserUpdateOutcome::Updated(Box::new(target)));
}

#[tokio::test]
async fn signing_key_cas_has_one_winner_and_preserves_the_entire_generation() {
    let mut fixture = Fixture::new();
    let candidate = |revision, marker: &str| PersistedSigningKeyset {
        revision,
        public_metadata: json!({"kid":marker}),
        encrypted_private_material: marker.as_bytes().to_vec(),
        wrapping_key_id: marker.into(),
    };
    assert!(matches!(
        SigningKeyRepository::create_if_absent(fixture.db(), candidate(1, "one"))
            .await
            .unwrap(),
        SigningKeysetCreateResult::Created(_)
    ));
    let (left, right) = tokio::join!(
        SigningKeyRepository::compare_and_swap(fixture.db(), 1, candidate(2, "left")),
        SigningKeyRepository::compare_and_swap(fixture.db(), 1, candidate(2, "right")),
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, SigningKeysetCompareAndSwapResult::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, SigningKeysetCompareAndSwapResult::Conflict(_)))
            .count(),
        1
    );
    fixture.restart();
    let persisted = SigningKeyRepository::load(fixture.db())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.revision, 2);
    assert_eq!(
        persisted.public_metadata["kid"].as_str(),
        Some(persisted.wrapping_key_id.as_str())
    );
    assert_eq!(
        persisted.encrypted_private_material,
        persisted.wrapping_key_id.as_bytes()
    );
    assert!(
        SigningKeyRepository::load(&fixture.db().for_tenant(Uuid::new_v4()))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn totp_audit_replay_backup_generation_and_key_rotation_are_atomic() {
    let fixture = Fixture::new();
    let user = fixture.user("mfa", UserRole::User);
    let tenant = user.principal.tenant.tenant_id;
    let id = user.principal.user_id;
    let claims_key = key(USER_CLAIMS, tenant.as_uuid(), id.as_uuid().as_bytes());
    let tx = fixture.db().transaction();
    let mut claims: SubjectClaims = read_tx(&tx, &claims_key, true).unwrap().unwrap();
    claims.updated_at = 0;
    put(&tx, &claims_key, &claims).unwrap();
    tx.commit().unwrap();
    let old = fixture
        .db()
        .clone()
        .with_totp_key_ring(Some(ring("old", 1, None)));
    old.activate_totp_key().await.unwrap();
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let now = 1_234_567_890;
    let code = totp_for_step(b"12345678901234567890", now / MFA_TOTP_PERIOD_SECONDS).unwrap();
    assert!(old.begin_totp_enrollment(tenant, id, secret).await.unwrap());
    let initial_events = audit_count(&old, tenant);
    assert!(
        old.verify_and_confirm_totp_with_required_audit(
            tenant,
            id,
            &code,
            now,
            hashes(),
            "x".repeat(nazo_persistence::MAX_SECURITY_AUDIT_PAYLOAD_BYTES)
        )
        .await
        .is_err()
    );
    assert_eq!(
        old.check_totp_enrollment(tenant, id, &code, now)
            .await
            .unwrap(),
        TotpEnrollmentCheck::ValidCode
    );
    assert!(
        old.backup_code_candidates(tenant, id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !old.account_by_id(tenant, id)
            .await
            .unwrap()
            .unwrap()
            .account
            .mfa_enabled
    );
    assert_eq!(audit_count(&old, tenant), initial_events);
    let TotpVerificationOutcome::Accepted(generation) = old
        .verify_and_confirm_totp_with_required_audit(
            tenant,
            id,
            &code,
            now,
            hashes(),
            "source".into(),
        )
        .await
        .unwrap()
    else {
        panic!("confirmation must succeed")
    };
    let account = old.account_by_id(tenant, id).await.unwrap().unwrap();
    let claims: SubjectClaims = crate::db::read(&old.db, &claims_key).unwrap().unwrap();
    assert_eq!(claims.updated_at, account.updated_at.as_second());
    assert!(claims.updated_at > 0);
    assert_eq!(
        old.verify_and_consume_totp(tenant, id, &code, now)
            .await
            .unwrap(),
        TotpVerificationOutcome::Replay
    );
    let next = now + MFA_TOTP_PERIOD_SECONDS;
    let code = totp_for_step(b"12345678901234567890", next / MFA_TOTP_PERIOD_SECONDS).unwrap();
    let (a, b) = tokio::join!(
        old.verify_and_consume_totp(tenant, id, &code, next),
        old.verify_and_consume_totp(tenant, id, &code, next)
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, TotpVerificationOutcome::Accepted(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == TotpVerificationOutcome::Replay)
            .count(),
        1
    );
    let codes = old.backup_code_candidates(tenant, id).await.unwrap();
    let (a, b) = tokio::join!(
        old.consume_backup_code_candidate(tenant, id, codes[0].id),
        old.consume_backup_code_candidate(tenant, id, codes[0].id)
    );
    assert_eq!(
        usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
        1
    );
    let deadline = Timestamp::now() + jiff::SignedDuration::from_secs(60);
    assert!(
        old.remember_device(
            tenant,
            id,
            generation,
            "token-digest".into(),
            Some("agent-digest".into()),
            deadline
        )
        .await
        .unwrap()
    );
    assert!(
        old.is_valid(
            tenant,
            id,
            "token-digest",
            Some("agent-digest"),
            Timestamp::now()
        )
        .await
        .unwrap()
    );
    let new = fixture
        .db()
        .clone()
        .with_totp_key_ring(Some(ring("new", 2, Some(("old", 1)))));
    new.activate_totp_key().await.unwrap();
    assert!(old.begin_totp_enrollment(tenant, id, secret).await.is_err());
    assert_eq!(new.rewrap_totp_batch().await.unwrap(), 1);
    let current = fixture
        .db()
        .clone()
        .with_totp_key_ring(Some(ring("new", 2, None)));
    current.activate_totp_key().await.unwrap();
    assert_eq!(
        current
            .verify_and_consume_totp(tenant, id, &code, next)
            .await
            .unwrap(),
        TotpVerificationOutcome::Replay
    );
    assert!(
        current
            .clear_mfa_state_if_current_with_required_audit(tenant, id, generation, "source".into())
            .await
            .unwrap()
    );
    assert!(
        !current
            .is_valid(
                tenant,
                id,
                "token-digest",
                Some("agent-digest"),
                Timestamp::now()
            )
            .await
            .unwrap()
    );
    assert!(
        current
            .begin_totp_enrollment(tenant, id, secret)
            .await
            .unwrap()
    );
    let TotpVerificationOutcome::Accepted(replacement) = current
        .verify_and_confirm_totp(tenant, id, &code, next, hashes())
        .await
        .unwrap()
    else {
        panic!("replacement confirmation must succeed")
    };
    assert_ne!(replacement, generation);
    assert!(
        !current
            .clear_mfa_state_if_current(tenant, id, generation)
            .await
            .unwrap()
    );
    assert_eq!(
        current
            .backup_code_candidates(tenant, id)
            .await
            .unwrap()
            .len(),
        MFA_BACKUP_CODE_COUNT
    );
}

#[tokio::test]
async fn passkey_zero_counter_cas_and_monotonic_uv_fence_stale_assertions() {
    let fixture = Fixture::new();
    let user = fixture.user("passkey", UserRole::User);
    let tenant = user.principal.tenant.tenant_id;
    let id = user.principal.user_id;
    let credential = nazo_passkey::PasskeyCredential {
        id: nazo_passkey::CredentialId(vec![1, 2, 3]),
        public_key_cose: nazo_passkey::CosePublicKey(vec![0xa0]),
        counter: 0,
        transports: vec!["internal".into()],
        aaguid: [0; 16],
        user_handle: Some(id.as_uuid().as_bytes().to_vec()),
        uv_initialized: Some(false),
        backup_eligible: Some(true),
        backup_state: Some(false),
        attestation: Default::default(),
    };
    let public_id = credential.id.to_b64url();
    let saved = PasskeyRepositoryPort::insert(fixture.db(), tenant, id, credential, "key".into())
        .await
        .unwrap();
    assert_eq!(
        fixture.db().list_summaries(tenant, id).await.unwrap()[0].credential_id,
        public_id
    );
    assert_eq!(
        fixture.db().credential_ids(tenant, id).await.unwrap()[0],
        saved.credential.id
    );
    let observed = fixture
        .db()
        .by_credential_id(tenant, id, &public_id)
        .await
        .unwrap()
        .unwrap();
    let update = PasskeyAuthenticationUpdate {
        credential: nazo_passkey::CredentialUpdate {
            expected_counter: 0,
            new_counter: 0,
            expected_backup_eligible: Some(true),
            backup_eligible: true,
            expected_backup_state: Some(false),
            backup_state: true,
        },
        initialize_user_verification: true,
    };
    let (a, b) = tokio::join!(
        fixture.db().update_authentication(&observed, update),
        fixture.db().update_authentication(&observed, update)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        a.as_ref().err().or(b.as_ref().err()),
        Some(&RepositoryError::Conflict)
    );
    let current = fixture
        .db()
        .by_credential_id(tenant, id, &public_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.row.credential.uv_initialized, Some(true));
    assert!(
        fixture
            .db()
            .by_credential_id(other_context().tenant_id, id, &public_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        PasskeyRepositoryPort::delete(fixture.db(), tenant, id, saved.id)
            .await
            .unwrap()
    );
    assert!(
        fixture
            .db()
            .credential_ids(tenant, id)
            .await
            .unwrap()
            .is_empty()
    );
}
