//! Real PostgreSQL regression fixtures for the six administrative identity owners.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Bool, Integer, Jsonb, Text, Timestamptz, Uuid as SqlUuid},
};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use nazo_identity::{
    TenantContext,
    ports::{NewUser, PasswordHashInput},
};
use nazo_persistence::control_plane::*;
use nazo_postgres::{
    ControllerRegistryRepository, RecoveryRootRepository, UserRepository, create_pool, get_conn,
};
use sha2::{Digest as _, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use uuid::Uuid;

struct Fixture {
    pool: nazo_postgres::DbPool,
    registry: ControllerRegistryRepository,
    recovery: RecoveryRootRepository,
    audit: AdminIdentityAudit,
    deployment: String,
}
impl Fixture {
    async fn new() -> Option<Self> {
        let url =
            std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
        let url = match url {
            Ok(url) => url,
            Err(_) => {
                assert!(std::env::var_os("CI").is_none(), "CI requires PostgreSQL");
                return None;
            }
        };
        let pool = create_pool(url, 4).unwrap();
        let tenant = TenantContext::default_system();
        let suffix = Uuid::now_v7();
        let hash =
            nazo_crypto::password::hash_argon2id(b"fixture-only password", 64, 1, 1).unwrap();
        let actor = UserRepository::new(pool.clone())
            .create(NewUser {
                tenant,
                username: suffix.to_string(),
                email: format!("{suffix}@example.test"),
                password_hash: PasswordHashInput::new(hash).unwrap(),
                email_verified: true,
            })
            .await
            .unwrap();
        sql_query("UPDATE users SET role='admin',admin_level=10 WHERE id=$1")
            .bind::<SqlUuid, _>(actor.id())
            .execute(&mut get_conn(&pool).await.unwrap())
            .await
            .unwrap();
        Some(Self {
            registry: ControllerRegistryRepository::new(pool.clone()),
            recovery: RecoveryRootRepository::new(pool.clone()),
            pool,
            audit: AdminIdentityAudit {
                tenant,
                actor_user_id: actor.id(),
                source_ip_hash: "fixture-source".to_owned(),
            },
            deployment: suffix.to_string(),
        })
    }
    fn approval(&self, action: ControllerIdentityAction) -> IdentityApprovalCommand {
        IdentityApprovalCommand {
            deployment_id: self.deployment.clone(),
            action,
            action_sha256: digest(),
            now: Utc::now(),
        }
    }
    fn recovery_approval(&self) -> RecoveryApprovalCommand {
        RecoveryApprovalCommand {
            deployment_id: self.deployment.clone(),
            action_sha256: digest(),
            now: Utc::now(),
        }
    }
    fn creation(&self, token: &str, bind: bool) -> SlotCreationCommand {
        SlotCreationCommand {
            approval_token: token.to_owned(),
            action: if bind {
                ControllerIdentityAction::Bind
            } else {
                ControllerIdentityAction::Add
            },
            action_sha256: digest(),
            slot: NewControllerSlot {
                deployment_id: self.deployment.clone(),
                label: "fixture".to_owned(),
                kid: kid(1),
                public_key: key(1),
            },
            initial_root: bind.then(|| NewRecoveryRoot {
                deployment_id: self.deployment.clone(),
                kid: kid(11),
                public_key: key(11),
            }),
            now: Utc::now(),
        }
    }
    fn rotation(&self, token: &str, controller: &str) -> SlotRotationCommand {
        SlotRotationCommand {
            approval_token: token.to_owned(),
            deployment_id: self.deployment.clone(),
            action_sha256: digest(),
            rotation: RotateControllerKey {
                deployment_id: self.deployment.clone(),
                controller_id: controller.to_owned(),
                label: "rotated".to_owned(),
                kid: kid(2),
                public_key: key(2),
            },
            now: Utc::now(),
        }
    }
    fn revocation(&self, token: &str, controller: &str) -> SlotRevocationCommand {
        SlotRevocationCommand {
            approval_token: token.to_owned(),
            deployment_id: self.deployment.clone(),
            action_sha256: digest(),
            controller_id: controller.to_owned(),
            now: Utc::now(),
        }
    }
    fn root_rotation(&self, token: &str) -> RecoveryRotationCommand {
        RecoveryRotationCommand {
            approval_token: token.to_owned(),
            deployment_id: self.deployment.clone(),
            action_sha256: digest(),
            root: NewRecoveryRoot {
                deployment_id: self.deployment.clone(),
                kid: kid(12),
                public_key: key(12),
            },
            now: Utc::now(),
        }
    }
}
fn key(seed: u8) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn kid(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key(seed)))
}
fn digest() -> String {
    "a".repeat(64)
}

#[derive(QueryableByName)]
struct Snapshot {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
}
async fn snapshot(f: &Fixture) -> serde_json::Value {
    sql_query("SELECT jsonb_build_object('slots',(SELECT md5(COALESCE(jsonb_agg(to_jsonb(s) ORDER BY controller_id),'[]'::jsonb)::text) FROM controller_registry_slots s WHERE deployment_id=$1),'roots',(SELECT md5(COALESCE(jsonb_agg(to_jsonb(r)),'[]'::jsonb)::text) FROM controller_recovery_roots r WHERE deployment_id=$1),'approvals',(SELECT md5(COALESCE(jsonb_agg(to_jsonb(a) ORDER BY approval_id),'[]'::jsonb)::text) FROM controller_identity_approvals a WHERE deployment_id=$1),'canonical',COALESCE((SELECT jsonb_agg(jsonb_build_object('type',event_type,'payload',payload) ORDER BY event_id) FROM public.security_audit_events WHERE payload->>'deployment_id'=$1),'[]'::jsonb)) AS value")
        .bind::<Text,_>(&f.deployment).get_result::<Snapshot>(&mut get_conn(&f.pool).await.unwrap()).await.unwrap().value
}
async fn rollback_with_fault<F>(f: &Fixture, operation: F)
where
    F: std::future::Future<Output = ()>,
{
    let name = format!("identity_required_{}", Uuid::now_v7().simple());
    get_conn(&f.pool).await.unwrap().batch_execute(&format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture canonical append failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON public.security_audit_events FOR EACH ROW WHEN (NEW.payload->>'deployment_id'='{}') EXECUTE FUNCTION {name}();",f.deployment
    )).await.unwrap();
    let before = snapshot(f).await;
    let caught = std::panic::AssertUnwindSafe(async {
        operation.await;
        assert_eq!(
            snapshot(f).await,
            before,
            "business rows, approval consumption and canonical outcome roll back together"
        );
    })
    .catch_unwind()
    .await;
    get_conn(&f.pool)
        .await
        .unwrap()
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON public.security_audit_events; DROP FUNCTION {name}();"
        ))
        .await
        .unwrap();
    if let Err(error) = caught {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn required_control_plane_approvals_accept_submicrosecond_clocks_with_exact_stored_expiry() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    #[derive(QueryableByName)]
    struct ApprovalTimes {
        #[diesel(sql_type = Timestamptz)]
        created_at: DateTime<Utc>,
        #[diesel(sql_type = Timestamptz)]
        expires_at: DateTime<Utc>,
    }
    for nanos in [1, 999, 123_456_789, 999_999_999] {
        let now = DateTime::<Utc>::from_timestamp(1_800_000_000, nanos).unwrap();
        let stored_now =
            DateTime::<Utc>::from_timestamp(1_800_000_000, nanos / 1_000 * 1_000).unwrap();
        let expected_expiry = stored_now + chrono::Duration::seconds(IDENTITY_APPROVAL_TTL_SECONDS);
        for action in [
            ControllerIdentityAction::Bind,
            ControllerIdentityAction::Add,
            ControllerIdentityAction::Rotate,
            ControllerIdentityAction::Revoke,
            ControllerIdentityAction::RecoveryRootRotate,
        ] {
            let approval = if action == ControllerIdentityAction::RecoveryRootRotate {
                let mut command = f.recovery_approval();
                command.now = now;
                f.recovery
                    .issue_rotation_approval_with_required_audit(command, f.audit.clone())
                    .await
                    .unwrap()
            } else {
                let mut command = f.approval(action);
                command.now = now;
                f.registry
                    .issue_identity_approval_with_required_audit(command, f.audit.clone())
                    .await
                    .unwrap()
            };
            let stored = sql_query("SELECT created_at,expires_at FROM controller_identity_approvals WHERE approval_id=$1")
                .bind::<SqlUuid, _>(approval.approval_id)
                .get_result::<ApprovalTimes>(&mut get_conn(&f.pool).await.unwrap())
                .await
                .unwrap();
            assert_eq!(stored.created_at, stored_now);
            assert_eq!(stored.expires_at, expected_expiry);
            assert_eq!(approval.expires_at, stored.expires_at);
            assert_eq!(
                (stored.expires_at - stored.created_at).num_seconds(),
                IDENTITY_APPROVAL_TTL_SECONDS
            );
            let evidence = snapshot(&f).await;
            let event = evidence["canonical"].as_array().unwrap().last().unwrap();
            assert_eq!(
                event["payload"]["expires_at"],
                approval.expires_at.to_rfc3339()
            );
            assert_eq!(
                event["payload"]["approval_id"],
                approval.approval_id.to_string()
            );
        }
    }
    assert_eq!(
        snapshot(&f).await["canonical"].as_array().unwrap().len(),
        20
    );
}

#[tokio::test]
async fn required_control_plane_rewritten_approval_expiry_is_rejected_and_rolled_back() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let name = format!("approval_expiry_{}", Uuid::now_v7().simple());
    get_conn(&f.pool)
        .await
        .unwrap()
        .batch_execute(&format!(
            "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.expires_at := NEW.expires_at + interval '1 microsecond'; RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE INSERT ON controller_identity_approvals FOR EACH ROW WHEN (NEW.deployment_id='{}') EXECUTE FUNCTION {name}();",
            f.deployment
        ))
        .await
        .unwrap();
    let before = snapshot(&f).await;
    let body = std::panic::AssertUnwindSafe(async {
        let now = DateTime::<Utc>::from_timestamp(1_800_000_000, 123_456_789).unwrap();
        let mut command = f.approval(ControllerIdentityAction::Add);
        command.now = now;
        let error = f
            .registry
            .issue_identity_approval_with_required_audit(command, f.audit.clone())
            .await
            .unwrap_err();
        assert!(matches!(error, IdentityApprovalError::Transport(_)));
        assert!(
            error
                .to_string()
                .contains("approval insert changed its authority binding")
        );
        assert_eq!(snapshot(&f).await, before);
        let mut command = f.recovery_approval();
        command.now = now;
        let error = f
            .recovery
            .issue_rotation_approval_with_required_audit(command, f.audit.clone())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RecoveryRotationError::Approval(IdentityApprovalError::Transport(_))
        ));
        assert!(
            error
                .to_string()
                .contains("approval insert changed its authority binding")
        );
        assert_eq!(snapshot(&f).await, before);
    })
    .catch_unwind()
    .await;
    get_conn(&f.pool)
        .await
        .unwrap()
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON controller_identity_approvals; DROP FUNCTION {name}();"
        ))
        .await
        .unwrap();
    if let Err(error) = body {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn required_control_plane_all_six_ledger_failures_roll_back_exact_owners() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    rollback_with_fault(&f, async {
        assert!(
            f.registry
                .issue_identity_approval_with_required_audit(
                    f.approval(ControllerIdentityAction::Bind),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
    })
    .await;
    rollback_with_fault(&f, async {
        assert!(
            f.recovery
                .issue_rotation_approval_with_required_audit(f.recovery_approval(), f.audit.clone())
                .await
                .is_err()
        );
    })
    .await;
    let approval = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Bind),
            f.audit.clone(),
        )
        .await
        .unwrap();
    rollback_with_fault(&f, async {
        assert!(
            f.registry
                .commit_slot_creation_with_required_audit(
                    f.creation(&approval.token, true),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
    })
    .await;
    let slot = f
        .registry
        .commit_slot_creation_with_required_audit(
            f.creation(&approval.token, true),
            f.audit.clone(),
        )
        .await
        .unwrap();
    assert_eq!(slot.kid, kid(1));
    assert_eq!(
        f.recovery
            .current_root(&f.deployment)
            .await
            .unwrap()
            .unwrap()
            .generation,
        1
    );
    let approval = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Rotate),
            f.audit.clone(),
        )
        .await
        .unwrap();
    rollback_with_fault(&f, async {
        assert!(
            f.registry
                .commit_slot_rotation_with_required_audit(
                    f.rotation(&approval.token, &slot.controller_id),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
    })
    .await;
    let slot = f
        .registry
        .commit_slot_rotation_with_required_audit(
            f.rotation(&approval.token, &slot.controller_id),
            f.audit.clone(),
        )
        .await
        .unwrap();
    assert_eq!(slot.kid, kid(2));
    let approval = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Revoke),
            f.audit.clone(),
        )
        .await
        .unwrap();
    rollback_with_fault(&f, async {
        assert!(
            f.registry
                .commit_slot_revocation_with_required_audit(
                    f.revocation(&approval.token, &slot.controller_id),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
    })
    .await;
    let revoked = f
        .registry
        .commit_slot_revocation_with_required_audit(
            f.revocation(&approval.token, &slot.controller_id),
            f.audit.clone(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status, ControllerSlotStatus::Revoked);
    let approval = f
        .recovery
        .issue_rotation_approval_with_required_audit(f.recovery_approval(), f.audit.clone())
        .await
        .unwrap();
    rollback_with_fault(&f, async {
        assert!(
            f.recovery
                .commit_rotation_with_required_audit(
                    f.root_rotation(&approval.token),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
    })
    .await;
    let root = f
        .recovery
        .commit_rotation_with_required_audit(f.root_rotation(&approval.token), f.audit.clone())
        .await
        .unwrap();
    assert_eq!(root.generation, 2);
    assert_eq!(root.recovery_kid, kid(12));
    let after = snapshot(&f).await;
    let events = after["canonical"].as_array().unwrap();
    assert_eq!(events.len(), 8);
    for (event, expected_kid) in [
        ("controller_slot_created", kid(1)),
        ("controller_slot_rotated", kid(2)),
        ("controller_slot_revoked", kid(2)),
    ] {
        let payload = &events.iter().find(|e| e["type"] == event).unwrap()["payload"];
        assert_eq!(payload["controller_id"], slot.controller_id);
        assert_eq!(payload["kid"], expected_kid);
    }
    assert!(
        !serde_json::to_string(events)
            .unwrap()
            .contains(&approval.token)
    );
}

#[tokio::test]
async fn required_control_plane_current_actor_denies_inactive_demoted_and_moved_context() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let approval = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Bind),
            f.audit.clone(),
        )
        .await
        .unwrap();
    let slot = f
        .registry
        .commit_slot_creation_with_required_audit(
            f.creation(&approval.token, true),
            f.audit.clone(),
        )
        .await
        .unwrap();
    let add = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Add),
            f.audit.clone(),
        )
        .await
        .unwrap();
    let rotate = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Rotate),
            f.audit.clone(),
        )
        .await
        .unwrap();
    let revoke = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Revoke),
            f.audit.clone(),
        )
        .await
        .unwrap();
    let root = f
        .recovery
        .issue_rotation_approval_with_required_audit(f.recovery_approval(), f.audit.clone())
        .await
        .unwrap();
    let realm = Uuid::now_v7();
    sql_query("INSERT INTO realms(id,tenant_id,slug,display_name) VALUES($1,$2,$1::text,'Required identity context')")
        .bind::<SqlUuid,_>(realm).bind::<SqlUuid,_>(f.audit.tenant.tenant_id.as_uuid()).execute(&mut get_conn(&f.pool).await.unwrap()).await.unwrap();
    for state in ["inactive", "demoted", "moved"] {
        let sql = match state {
            "inactive" => "UPDATE users SET is_active=false WHERE id=$1 AND $2::uuid IS NOT NULL",
            "demoted" => {
                "UPDATE users SET is_active=true,role='user',admin_level=0 WHERE id=$1 AND $2::uuid IS NOT NULL"
            }
            _ => {
                "UPDATE users SET is_active=true,role='admin',admin_level=10,realm_id=$2 WHERE id=$1"
            }
        };
        sql_query(sql)
            .bind::<SqlUuid, _>(f.audit.actor_user_id)
            .bind::<SqlUuid, _>(realm)
            .execute(&mut get_conn(&f.pool).await.unwrap())
            .await
            .unwrap();
        let before = snapshot(&f).await;
        assert!(
            f.registry
                .issue_identity_approval_with_required_audit(
                    f.approval(ControllerIdentityAction::Add),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
        assert!(
            f.recovery
                .issue_rotation_approval_with_required_audit(f.recovery_approval(), f.audit.clone())
                .await
                .is_err()
        );
        assert!(
            f.registry
                .commit_slot_creation_with_required_audit(
                    f.creation(&add.token, false),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
        assert!(
            f.registry
                .commit_slot_rotation_with_required_audit(
                    f.rotation(&rotate.token, &slot.controller_id),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
        assert!(
            f.registry
                .commit_slot_revocation_with_required_audit(
                    f.revocation(&revoke.token, &slot.controller_id),
                    f.audit.clone()
                )
                .await
                .is_err()
        );
        assert!(
            f.recovery
                .commit_rotation_with_required_audit(f.root_rotation(&root.token), f.audit.clone())
                .await
                .is_err()
        );
        assert_eq!(
            snapshot(&f).await,
            before,
            "all six reject without consuming pending approvals or creating success evidence"
        );
    }
}

struct BareOnly;
struct HiddenAck {
    registry: ControllerRegistryRepository,
    recovery: RecoveryRootRepository,
    commits: Arc<AtomicUsize>,
}
impl ControllerRegistryPort for BareOnly {
    fn issue_identity_approval<'a>(
        &'a self,
        _deployment_id: &'a str,
        _action: ControllerIdentityAction,
        _action_sha256: &'a str,
        _admin_user_id: Uuid,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<IssuedIdentityApproval, IdentityApprovalError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn commit_slot_creation<'a>(
        &'a self,
        _approval_token: &'a str,
        _expected_action: ControllerIdentityAction,
        _expected_action_sha256: &'a str,
        _slot: NewControllerSlot,
        _initial_root: Option<NewRecoveryRoot>,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn commit_slot_rotation<'a>(
        &'a self,
        _approval_token: &'a str,
        _expected_deployment_id: &'a str,
        _expected_action_sha256: &'a str,
        _rotation: RotateControllerKey,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn commit_slot_revocation<'a>(
        &'a self,
        _approval_token: &'a str,
        _expected_deployment_id: &'a str,
        _expected_action_sha256: &'a str,
        _controller_id: &'a str,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn list_slots<'a>(
        &'a self,
        _deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredControllerSlot>, ControllerRegistryError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn admitted_controllers<'a>(
        &'a self,
        _deployment_id: &'a str,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<Vec<AdmittedController>, ControllerRegistryError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn admitted_controller_by_kid<'a>(
        &'a self,
        _deployment_id: &'a str,
        _kid: &'a str,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<Option<AdmittedController>, ControllerRegistryError>> {
        panic!("Required capability must never invoke bare operation")
    }
}
impl ControllerRegistryPort for HiddenAck {
    fn issue_identity_approval<'a>(
        &'a self,
        _deployment_id: &'a str,
        _action: ControllerIdentityAction,
        _action_sha256: &'a str,
        _admin_user_id: Uuid,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<IssuedIdentityApproval, IdentityApprovalError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn commit_slot_creation<'a>(
        &'a self,
        _approval_token: &'a str,
        _expected_action: ControllerIdentityAction,
        _expected_action_sha256: &'a str,
        _slot: NewControllerSlot,
        _initial_root: Option<NewRecoveryRoot>,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn commit_slot_rotation<'a>(
        &'a self,
        _approval_token: &'a str,
        _expected_deployment_id: &'a str,
        _expected_action_sha256: &'a str,
        _rotation: RotateControllerKey,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn commit_slot_revocation<'a>(
        &'a self,
        _approval_token: &'a str,
        _expected_deployment_id: &'a str,
        _expected_action_sha256: &'a str,
        _controller_id: &'a str,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredControllerSlot, CommitWithApprovalError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn list_slots<'a>(
        &'a self,
        _deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredControllerSlot>, ControllerRegistryError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn admitted_controllers<'a>(
        &'a self,
        _deployment_id: &'a str,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<Vec<AdmittedController>, ControllerRegistryError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn admitted_controller_by_kid<'a>(
        &'a self,
        _deployment_id: &'a str,
        _kid: &'a str,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<Option<AdmittedController>, ControllerRegistryError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn issue_identity_approval_with_required_audit(
        &self,
        command: IdentityApprovalCommand,
        audit: AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<'_, Result<IssuedIdentityApproval, IdentityApprovalError>>
    {
        Box::pin(async move {
            let _accepted = self
                .registry
                .issue_identity_approval_with_required_audit(command, audit)
                .await?;
            self.commits.fetch_add(1, Ordering::SeqCst);
            Err(IdentityApprovalError::Transport(anyhow::anyhow!(
                "fixture hides actual committed ACK"
            )))
        })
    }
    fn commit_slot_creation_with_required_audit(
        &self,
        command: SlotCreationCommand,
        audit: AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<'_, Result<StoredControllerSlot, CommitWithApprovalError>>
    {
        Box::pin(async move {
            let _accepted = self
                .registry
                .commit_slot_creation_with_required_audit(command, audit)
                .await?;
            self.commits.fetch_add(1, Ordering::SeqCst);
            Err(CommitWithApprovalError::Transport(anyhow::anyhow!(
                "fixture hides actual committed ACK"
            )))
        })
    }
    fn commit_slot_rotation_with_required_audit(
        &self,
        command: SlotRotationCommand,
        audit: AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<'_, Result<StoredControllerSlot, CommitWithApprovalError>>
    {
        Box::pin(async move {
            let _accepted = self
                .registry
                .commit_slot_rotation_with_required_audit(command, audit)
                .await?;
            self.commits.fetch_add(1, Ordering::SeqCst);
            Err(CommitWithApprovalError::Transport(anyhow::anyhow!(
                "fixture hides actual committed ACK"
            )))
        })
    }
    fn commit_slot_revocation_with_required_audit(
        &self,
        command: SlotRevocationCommand,
        audit: AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<'_, Result<StoredControllerSlot, CommitWithApprovalError>>
    {
        Box::pin(async move {
            let _accepted = self
                .registry
                .commit_slot_revocation_with_required_audit(command, audit)
                .await?;
            self.commits.fetch_add(1, Ordering::SeqCst);
            Err(CommitWithApprovalError::Transport(anyhow::anyhow!(
                "fixture hides actual committed ACK"
            )))
        })
    }
}
impl RecoveryRootPort for BareOnly {
    fn current_root<'a>(
        &'a self,
        _deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredRecoveryRoot>, RecoveryRootError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn issue_rotation_approval<'a>(
        &'a self,
        _deployment_id: &'a str,
        _action_sha256: &'a str,
        _admin_user_id: Uuid,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<IssuedIdentityApproval, RecoveryRotationError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn commit_rotation<'a>(
        &'a self,
        _approval_token: &'a str,
        _expected_deployment_id: &'a str,
        _expected_action_sha256: &'a str,
        _root: NewRecoveryRoot,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredRecoveryRoot, RecoveryRotationError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn issue_recovery_challenge(
        &self,
        _challenge: NewRecoveryChallenge,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<IssuedRecoveryChallenge, RecoveryRootError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn submit_recovery_challenge(
        &self,
        _submission: RecoverySubmission,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<RecoveredSlotCommit, RecoveryRootError>> {
        panic!("Required capability must never invoke bare operation")
    }
}
impl RecoveryRootPort for HiddenAck {
    fn current_root<'a>(
        &'a self,
        _deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredRecoveryRoot>, RecoveryRootError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn issue_rotation_approval<'a>(
        &'a self,
        _deployment_id: &'a str,
        _action_sha256: &'a str,
        _admin_user_id: Uuid,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<IssuedIdentityApproval, RecoveryRotationError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn commit_rotation<'a>(
        &'a self,
        _approval_token: &'a str,
        _expected_deployment_id: &'a str,
        _expected_action_sha256: &'a str,
        _root: NewRecoveryRoot,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<StoredRecoveryRoot, RecoveryRotationError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn issue_recovery_challenge(
        &self,
        _challenge: NewRecoveryChallenge,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<IssuedRecoveryChallenge, RecoveryRootError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn submit_recovery_challenge(
        &self,
        _submission: RecoverySubmission,
        _now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<RecoveredSlotCommit, RecoveryRootError>> {
        panic!("Required capability must never invoke bare operation")
    }
    fn issue_rotation_approval_with_required_audit(
        &self,
        command: RecoveryApprovalCommand,
        audit: AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<'_, Result<IssuedIdentityApproval, RecoveryRotationError>>
    {
        Box::pin(async move {
            let _accepted = self
                .recovery
                .issue_rotation_approval_with_required_audit(command, audit)
                .await?;
            self.commits.fetch_add(1, Ordering::SeqCst);
            Err(RecoveryRotationError::Transport(anyhow::anyhow!(
                "fixture hides actual committed ACK"
            )))
        })
    }
    fn commit_rotation_with_required_audit(
        &self,
        command: RecoveryRotationCommand,
        audit: AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<'_, Result<StoredRecoveryRoot, RecoveryRotationError>>
    {
        Box::pin(async move {
            let _accepted = self
                .recovery
                .commit_rotation_with_required_audit(command, audit)
                .await?;
            self.commits.fetch_add(1, Ordering::SeqCst);
            Err(RecoveryRotationError::Transport(anyhow::anyhow!(
                "fixture hides actual committed ACK"
            )))
        })
    }
}

#[tokio::test]
async fn required_control_plane_hidden_real_commits_withhold_tokens_and_receipts() {
    let Some(f) = Fixture::new().await else {
        return;
    };
    let hidden = HiddenAck {
        registry: f.registry.clone(),
        recovery: f.recovery.clone(),
        commits: Arc::new(AtomicUsize::new(0)),
    };
    assert!(
        hidden
            .issue_identity_approval_with_required_audit(
                f.approval(ControllerIdentityAction::Add),
                f.audit.clone()
            )
            .await
            .is_err()
    );
    assert!(
        hidden
            .issue_rotation_approval_with_required_audit(f.recovery_approval(), f.audit.clone())
            .await
            .is_err()
    );
    let approval = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Bind),
            f.audit.clone(),
        )
        .await
        .unwrap();
    assert!(
        hidden
            .commit_slot_creation_with_required_audit(
                f.creation(&approval.token, true),
                f.audit.clone()
            )
            .await
            .is_err()
    );
    let slot = f
        .registry
        .list_slots(&f.deployment)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let approval = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Rotate),
            f.audit.clone(),
        )
        .await
        .unwrap();
    assert!(
        hidden
            .commit_slot_rotation_with_required_audit(
                f.rotation(&approval.token, &slot.controller_id),
                f.audit.clone()
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.registry.list_slots(&f.deployment).await.unwrap()[0].kid,
        kid(2)
    );
    let approval = f
        .registry
        .issue_identity_approval_with_required_audit(
            f.approval(ControllerIdentityAction::Revoke),
            f.audit.clone(),
        )
        .await
        .unwrap();
    assert!(
        hidden
            .commit_slot_revocation_with_required_audit(
                f.revocation(&approval.token, &slot.controller_id),
                f.audit.clone()
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.registry.list_slots(&f.deployment).await.unwrap()[0].status,
        nazo_postgres::ControllerSlotStatus::Revoked
    );
    let approval = f
        .recovery
        .issue_rotation_approval_with_required_audit(f.recovery_approval(), f.audit.clone())
        .await
        .unwrap();
    assert!(
        hidden
            .commit_rotation_with_required_audit(f.root_rotation(&approval.token), f.audit.clone())
            .await
            .is_err()
    );
    assert_eq!(
        f.recovery
            .current_root(&f.deployment)
            .await
            .unwrap()
            .unwrap()
            .generation,
        2
    );
    assert_eq!(
        AtomicUsize::load(hidden.commits.as_ref(), Ordering::SeqCst),
        6
    );
    assert_eq!(
        snapshot(&f).await["canonical"].as_array().unwrap().len(),
        10
    );
}

#[tokio::test]
async fn required_control_plane_defaults_never_invoke_bare_mutation() {
    let tenant = TenantContext::default_system();
    let audit = AdminIdentityAudit {
        tenant,
        actor_user_id: Uuid::now_v7(),
        source_ip_hash: "fixture-source".to_owned(),
    };
    let bare = BareOnly;
    let deployment = Uuid::now_v7().to_string();
    let controller = Uuid::now_v7().to_string();
    let now = Utc::now();
    assert!(
        bare.issue_identity_approval_with_required_audit(
            IdentityApprovalCommand {
                deployment_id: deployment.clone(),
                action: ControllerIdentityAction::Add,
                action_sha256: digest(),
                now
            },
            audit.clone()
        )
        .await
        .is_err()
    );
    assert!(
        bare.issue_rotation_approval_with_required_audit(
            RecoveryApprovalCommand {
                deployment_id: deployment.clone(),
                action_sha256: digest(),
                now
            },
            audit.clone()
        )
        .await
        .is_err()
    );
    assert!(
        bare.commit_slot_creation_with_required_audit(
            SlotCreationCommand {
                approval_token: "unavailable".to_owned(),
                action: ControllerIdentityAction::Add,
                action_sha256: digest(),
                slot: NewControllerSlot {
                    deployment_id: deployment.clone(),
                    label: "fixture".to_owned(),
                    kid: kid(1),
                    public_key: key(1)
                },
                initial_root: None,
                now
            },
            audit.clone()
        )
        .await
        .is_err()
    );
    assert!(
        bare.commit_slot_rotation_with_required_audit(
            SlotRotationCommand {
                approval_token: "unavailable".to_owned(),
                deployment_id: deployment.clone(),
                action_sha256: digest(),
                rotation: RotateControllerKey {
                    deployment_id: deployment.clone(),
                    controller_id: controller.clone(),
                    label: "fixture".to_owned(),
                    kid: kid(2),
                    public_key: key(2)
                },
                now
            },
            audit.clone()
        )
        .await
        .is_err()
    );
    assert!(
        bare.commit_slot_revocation_with_required_audit(
            SlotRevocationCommand {
                approval_token: "unavailable".to_owned(),
                deployment_id: deployment.clone(),
                action_sha256: digest(),
                controller_id: controller,
                now
            },
            audit.clone()
        )
        .await
        .is_err()
    );
    assert!(
        bare.commit_rotation_with_required_audit(
            RecoveryRotationCommand {
                approval_token: "unavailable".to_owned(),
                deployment_id: deployment.clone(),
                action_sha256: digest(),
                root: NewRecoveryRoot {
                    deployment_id: deployment,
                    kid: kid(12),
                    public_key: key(12)
                },
                now
            },
            audit
        )
        .await
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn required_control_plane_cancelled_accepting_owner_releases_connection_and_deployment_lock()
{
    let Some(f) = Fixture::new().await else {
        return;
    };
    let mut blocker = get_conn(&f.pool).await.unwrap();
    blocker.batch_execute("BEGIN").await.unwrap();
    #[derive(QueryableByName)]
    struct Backend {
        #[diesel(sql_type=Integer)]
        pid: i32,
    }
    let blocker_pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Backend>(&mut blocker)
        .await
        .unwrap()
        .pid;
    sql_query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind::<SqlUuid, _>(f.audit.actor_user_id)
        .execute(&mut blocker)
        .await
        .unwrap();
    // Hold an independent peer before cancelling the owner. Borrowing again
    // afterwards could accidentally make pool recycling release the lock.
    let mut peer = get_conn(&f.pool).await.unwrap();
    peer.batch_execute("SET lock_timeout = '3s'").await.unwrap();
    let repository = f.registry.clone();
    let command = f.approval(ControllerIdentityAction::Add);
    let audit = f.audit.clone();
    let task = tokio::spawn(async move {
        repository
            .issue_identity_approval_with_required_audit(command, audit)
            .await
    });
    #[derive(QueryableByName)]
    struct Waiting {
        #[diesel(sql_type=Bool)]
        value: bool,
    }
    let observed=tokio::time::timeout(std::time::Duration::from_secs(3),async {
        loop {
            let row=sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND pg_blocking_pids(pid) @> ARRAY[$1]::int[]) AS value")
                .bind::<Integer,_>(blocker_pid)
                .get_result::<Waiting>(&mut get_conn(&f.pool).await.unwrap()).await.unwrap();
            if row.value {break;}tokio::task::yield_now().await;
        }
    }).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    blocker.batch_execute("ROLLBACK").await.unwrap();
    drop(blocker);
    assert!(
        observed.is_ok(),
        "real actor lock wait must be observed before cancellation"
    );
    // Socket close and backend rollback are asynchronous. Require PostgreSQL
    // to grant the peer the lock within the same three-second observation
    // bound, rather than racing one nonblocking try against disconnect.
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,$2))")
        .bind::<Text, _>(&f.deployment)
        .bind::<BigInt, _>(nazo_postgres::DEPLOYMENT_IDENTITY_LOCK_SEED)
        .execute(&mut peer)
        .await
        .expect("discarded accepting connection releases its deployment lock");
    assert_eq!(snapshot(&f).await["canonical"].as_array().unwrap().len(), 0);
}
