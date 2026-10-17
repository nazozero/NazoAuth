//! An admin actor in each isolated identity fixture schema.
use diesel::{sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};
use nazo_identity::TenantContext;
use nazo_persistence::control_plane::AdminIdentityAudit;
use uuid::Uuid;

pub fn audit() -> AdminIdentityAudit {
    AdminIdentityAudit {
        tenant: TenantContext::default_system(),
        actor_user_id: Uuid::from_u128(1),
        source_ip_hash: "fixture-source".to_owned(),
    }
}

pub async fn seed_actor(url: &str) {
    let audit = audit();
    let mut connection = AsyncPgConnection::establish(url).await.unwrap();
    sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash, role, admin_level) VALUES ($1,$2,$3,$4,'identity-admin','identity-admin@example.test','unused-test-hash','admin',10)")
        .bind::<SqlUuid, _>(audit.actor_user_id)
        .bind::<SqlUuid, _>(audit.tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(audit.tenant.realm_id.as_uuid())
        .bind::<SqlUuid, _>(audit.tenant.organization_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
}

// Shared fixture setup for lifecycle and process tests, through the real audited commands.
use chrono::{DateTime, Utc};
use nazo_persistence::control_plane::{self as contract, ControllerRegistryPort as _};
use nazo_postgres::ControllerRegistryRepository;

// Each integration binary uses a subset of the shared lifecycle fixture.
#[allow(dead_code)]
pub(crate) trait SlotFixture {
    async fn create_slot(
        &self,
        slot: contract::NewControllerSlot,
        now: DateTime<Utc>,
    ) -> Result<contract::StoredControllerSlot, contract::ControllerRegistryError>;
    async fn rotate_slot(
        &self,
        rotation: contract::RotateControllerKey,
        now: DateTime<Utc>,
    ) -> Result<contract::StoredControllerSlot, contract::ControllerRegistryError>;
    async fn revoke_slot(
        &self,
        deployment_id: &str,
        controller_id: &str,
        now: DateTime<Utc>,
    ) -> Result<contract::StoredControllerSlot, contract::ControllerRegistryError>;
}

async fn approval(
    repository: &ControllerRegistryRepository,
    deployment_id: &str,
    action: contract::ControllerIdentityAction,
    now: DateTime<Utc>,
) -> String {
    repository
        .issue_identity_approval_with_required_audit(
            contract::IdentityApprovalCommand {
                deployment_id: deployment_id.to_owned(),
                action,
                action_sha256: "a".repeat(64),
                now,
            },
            audit(),
        )
        .await
        .expect("fixture actor can approve the exact action")
        .token
}

fn mutation_error(error: contract::CommitWithApprovalError) -> contract::ControllerRegistryError {
    match error {
        contract::CommitWithApprovalError::Mutation(error) => error,
        contract::CommitWithApprovalError::Transport(error) => {
            contract::ControllerRegistryError::Transport(error)
        }
        contract::CommitWithApprovalError::Approval(error) => {
            panic!("fresh fixture approval rejected: {error}")
        }
    }
}

impl SlotFixture for ControllerRegistryRepository {
    async fn create_slot(
        &self,
        slot: contract::NewControllerSlot,
        now: DateTime<Utc>,
    ) -> Result<contract::StoredControllerSlot, contract::ControllerRegistryError> {
        let action = contract::ControllerIdentityAction::Add;
        let approval_token = approval(self, &slot.deployment_id, action, now).await;
        self.commit_slot_creation_with_required_audit(
            contract::SlotCreationCommand {
                approval_token,
                action,
                action_sha256: "a".repeat(64),
                slot,
                initial_root: None,
                now,
            },
            audit(),
        )
        .await
        .map_err(mutation_error)
    }

    async fn rotate_slot(
        &self,
        rotation: contract::RotateControllerKey,
        now: DateTime<Utc>,
    ) -> Result<contract::StoredControllerSlot, contract::ControllerRegistryError> {
        let approval_token = approval(
            self,
            &rotation.deployment_id,
            contract::ControllerIdentityAction::Rotate,
            now,
        )
        .await;
        self.commit_slot_rotation_with_required_audit(
            contract::SlotRotationCommand {
                approval_token,
                action_sha256: "a".repeat(64),
                rotation,
                now,
            },
            audit(),
        )
        .await
        .map_err(mutation_error)
    }

    async fn revoke_slot(
        &self,
        deployment_id: &str,
        controller_id: &str,
        now: DateTime<Utc>,
    ) -> Result<contract::StoredControllerSlot, contract::ControllerRegistryError> {
        let approval_token = approval(
            self,
            deployment_id,
            contract::ControllerIdentityAction::Revoke,
            now,
        )
        .await;
        self.commit_slot_revocation_with_required_audit(
            contract::SlotRevocationCommand {
                approval_token,
                deployment_id: deployment_id.to_owned(),
                controller_id: controller_id.to_owned(),
                action_sha256: "a".repeat(64),
                now,
            },
            audit(),
        )
        .await
        .map_err(mutation_error)
    }
}
