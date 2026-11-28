use super::*;
use nazo_crypto::ed25519::SigningKey;
use nazo_identity::{Principal, TenantContext, UserId, UserRole};
use nazo_operator_protocol::{RecoveryProposal, controller_key_id, recovery_kid};
use std::path::PathBuf;

const DEPLOYMENT_ID: &str = "rocksdb-control-tests";

struct Fixture {
    store: Option<RocksDb>,
    path: PathBuf,
    audit: AdminIdentityAudit,
}

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("nazo-rocksdb-control-{}", Uuid::new_v4()));
        let store = RocksDb::open(&path).unwrap();
        let tenant = TenantContext::default_system();
        let actor_user_id = Uuid::now_v7();
        let tx = store.transaction();
        put(
            &tx,
            &key(
                crate::users::USER_PRINCIPAL,
                tenant.tenant_id.as_uuid(),
                actor_user_id.as_bytes(),
            ),
            &Principal {
                authorization_epoch: 0,
                user_id: UserId::new(actor_user_id).unwrap(),
                tenant,
                role: UserRole::Admin { level: 3 },
                active: true,
            },
        )
        .unwrap();
        tx.commit().unwrap();
        Self {
            store: Some(store),
            path,
            audit: AdminIdentityAudit {
                tenant,
                actor_user_id,
                source_ip_hash: "a".repeat(64),
            },
        }
    }

    fn db(&self) -> &RocksDb {
        self.store.as_ref().unwrap()
    }

    async fn approval(
        &self,
        action: ControllerIdentityAction,
        now: Timestamp,
    ) -> IssuedIdentityApproval {
        self.db()
            .issue_identity_approval_with_required_audit(
                IdentityApprovalCommand {
                    deployment_id: DEPLOYMENT_ID.into(),
                    action,
                    action_sha256: "b".repeat(64),
                    now,
                },
                self.audit.clone(),
            )
            .await
            .unwrap()
    }

    async fn create_command(
        &self,
        seed: u8,
        now: Timestamp,
        initial_root: bool,
    ) -> SlotCreationCommand {
        let action = if initial_root {
            ControllerIdentityAction::Bind
        } else {
            ControllerIdentityAction::Add
        };
        let approval = self.approval(action, now).await;
        let key = SigningKey::from_bytes(&[seed; 32]).verifying_key();
        let root = SigningKey::from_bytes(&[100; 32])
            .verifying_key()
            .to_bytes();
        SlotCreationCommand {
            approval_token: approval.token,
            action,
            action_sha256: approval.action_sha256,
            slot: NewControllerSlot {
                deployment_id: DEPLOYMENT_ID.into(),
                label: format!("controller-{seed}"),
                kid: controller_key_id(&key),
                public_key: key.to_bytes(),
            },
            initial_root: initial_root.then(|| NewRecoveryRoot {
                deployment_id: DEPLOYMENT_ID.into(),
                kid: recovery_kid(&root),
                public_key: root,
            }),
            now,
        }
    }

    fn reopen(&mut self) {
        drop(self.store.take());
        self.store = Some(RocksDb::open(&self.path).unwrap());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_is_consumed_once_and_failed_mutation_preserves_it() {
    let fixture = Fixture::new();
    let now = Timestamp::now();
    let first = fixture.create_command(1, now, true).await;
    let (left, right) = tokio::join!(
        fixture
            .db()
            .commit_slot_creation_with_required_audit(first.clone(), fixture.audit.clone()),
        fixture
            .db()
            .commit_slot_creation_with_required_audit(first, fixture.audit.clone())
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(matches!(
        left.err().or(right.err()).unwrap(),
        CommitWithApprovalError::Approval(IdentityApprovalError::Replayed)
    ));
    for seed in [2, 3] {
        fixture
            .db()
            .commit_slot_creation_with_required_audit(
                fixture.create_command(seed, now, false).await,
                fixture.audit.clone(),
            )
            .await
            .unwrap();
    }
    let fourth = fixture.create_command(4, now, false).await;
    assert!(matches!(
        fixture
            .db()
            .commit_slot_creation_with_required_audit(fourth.clone(), fixture.audit.clone())
            .await,
        Err(CommitWithApprovalError::Mutation(
            ControllerRegistryError::SlotLimit(_)
        ))
    ));
    let slots = fixture.db().list_slots(DEPLOYMENT_ID).await.unwrap();
    assert_eq!(slots.len(), 3);
    let approval = fixture
        .approval(ControllerIdentityAction::Revoke, now)
        .await;
    fixture
        .db()
        .commit_slot_revocation_with_required_audit(
            SlotRevocationCommand {
                approval_token: approval.token,
                deployment_id: DEPLOYMENT_ID.into(),
                action_sha256: approval.action_sha256,
                controller_id: slots[0].controller_id.clone(),
                now,
            },
            fixture.audit.clone(),
        )
        .await
        .unwrap();
    fixture
        .db()
        .commit_slot_creation_with_required_audit(fourth, fixture.audit.clone())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .db()
            .admitted_controllers(DEPLOYMENT_ID, now)
            .await
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        fixture
            .db()
            .current_root(DEPLOYMENT_ID)
            .await
            .unwrap()
            .unwrap()
            .generation,
        1
    );
}

fn proposal() -> RecoveryProposal {
    let controller = SigningKey::from_bytes(&[20; 32]).verifying_key();
    let root = SigningKey::from_bytes(&[101; 32])
        .verifying_key()
        .to_bytes();
    RecoveryProposal {
        deployment_id: DEPLOYMENT_ID.into(),
        controller_label: "recovered".into(),
        controller_kid: controller_key_id(&controller),
        controller_public_key: controller.to_bytes(),
        recovery_kid: recovery_kid(&root),
        recovery_public_key: root,
    }
}

fn candidate(proposal: &RecoveryProposal, nonce: [u8; 32]) -> NewRecoveryChallenge {
    NewRecoveryChallenge {
        deployment_id: proposal.deployment_id.clone(),
        controller_label: proposal.controller_label.clone(),
        controller_kid: proposal.controller_kid.clone(),
        controller_public_key: proposal.controller_public_key,
        recovery_kid: proposal.recovery_kid.clone(),
        recovery_public_key: proposal.recovery_public_key,
        allocation_nonce: nonce,
        allocation_signature: proposal.sign_allocation(&nonce, &[100; 32]),
    }
}

#[tokio::test]
async fn recovery_attempt_limit_and_exact_receipt_survive_reopen() {
    let mut fixture = Fixture::new();
    let now = Timestamp::now();
    fixture
        .db()
        .commit_slot_creation_with_required_audit(
            fixture.create_command(1, now, true).await,
            fixture.audit.clone(),
        )
        .await
        .unwrap();
    let proposal = proposal();
    let allocation = candidate(&proposal, rand::random());
    assert!(matches!(
        fixture
            .db()
            .issue_recovery_challenge(allocation.clone(), now)
            .await,
        Err(RecoveryRootError::ControllersStillAdmitted(_))
    ));
    let now = now + SignedDuration::from_secs(CONTROLLER_KEY_TTL_SECONDS + 1);
    let challenge = fixture
        .db()
        .issue_recovery_challenge(allocation.clone(), now)
        .await
        .unwrap();
    assert_eq!(
        challenge,
        fixture
            .db()
            .issue_recovery_challenge(allocation.clone(), now)
            .await
            .unwrap()
    );
    let invalid = RecoverySubmission {
        deployment_id: DEPLOYMENT_ID.into(),
        challenge_id: challenge.challenge_id,
        nonce: challenge.nonce,
        signature: [0; 64],
    };
    for _ in 0..MAX_RECOVERY_CHALLENGE_ATTEMPTS {
        assert!(matches!(
            fixture
                .db()
                .submit_recovery_challenge(invalid.clone(), now)
                .await,
            Err(RecoveryRootError::InvalidSignature)
        ));
    }
    fixture.reopen();
    assert!(matches!(
        fixture.db().submit_recovery_challenge(invalid, now).await,
        Err(RecoveryRootError::ChallengeExhausted)
    ));
    assert!(matches!(
        fixture.db().issue_recovery_challenge(allocation, now).await,
        Err(RecoveryRootError::AllocationProofReplayed)
    ));
    let challenge = fixture
        .db()
        .issue_recovery_challenge(candidate(&proposal, rand::random()), now)
        .await
        .unwrap();
    let submission = RecoverySubmission {
        deployment_id: DEPLOYMENT_ID.into(),
        challenge_id: challenge.challenge_id,
        nonce: challenge.nonce,
        signature: proposal.sign_challenge(
            &challenge.challenge_id.to_string(),
            &challenge.nonce,
            &[100; 32],
        ),
    };
    let accepted = fixture
        .db()
        .submit_recovery_challenge(submission.clone(), now)
        .await
        .unwrap();
    fixture.reopen();
    assert_eq!(
        accepted,
        fixture
            .db()
            .submit_recovery_challenge(submission.clone(), now)
            .await
            .unwrap()
    );
    assert_eq!(accepted.recovery_generation, 2);
    let mut changed = submission;
    changed.nonce[0] ^= 1;
    assert!(matches!(
        fixture.db().submit_recovery_challenge(changed, now).await,
        Err(RecoveryRootError::ChallengeReplayed)
    ));
    assert_eq!(
        fixture
            .db()
            .admitted_controllers(DEPLOYMENT_ID, now)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        fixture
            .db()
            .current_root(DEPLOYMENT_ID)
            .await
            .unwrap()
            .unwrap()
            .recovery_public_key,
        proposal.recovery_public_key
    );
}

#[tokio::test]
async fn actor_authority_is_rechecked_before_approval_consumption() {
    let fixture = Fixture::new();
    let now = Timestamp::now();
    let command = fixture.create_command(1, now, true).await;
    let tx = fixture.db().transaction();
    let authority_key = key(
        crate::users::USER_PRINCIPAL,
        fixture.audit.tenant.tenant_id.as_uuid(),
        fixture.audit.actor_user_id.as_bytes(),
    );
    let mut actor: Principal = read_tx(&tx, &authority_key, true).unwrap().unwrap();
    actor.active = false;
    put(&tx, &authority_key, &actor).unwrap();
    tx.commit().unwrap();
    assert!(
        fixture
            .db()
            .commit_slot_creation_with_required_audit(command.clone(), fixture.audit.clone())
            .await
            .is_err()
    );
    assert!(
        fixture
            .db()
            .list_slots(DEPLOYMENT_ID)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .db()
            .current_root(DEPLOYMENT_ID)
            .await
            .unwrap()
            .is_none()
    );
    let approval: Approval = read(
        &fixture.db().db,
        &key(
            APPROVAL,
            Uuid::nil(),
            blake3::hash(command.approval_token.as_bytes()).as_bytes(),
        ),
    )
    .unwrap()
    .unwrap();
    assert!(!approval.consumed);
}
