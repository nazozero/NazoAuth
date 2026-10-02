//! Database-backed invariant pins for the Recovery Root plane (04A D10/D11/D12).
//! Every test runs in an isolated schema; without `NAZO_TEST_DATABASE_URL`
//! (or `DATABASE_URL`) they skip so the suite stays hermetic.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, TimeZone, Utc};
use diesel::{
    QueryableByName, connection::InstrumentationEvent, sql_query,
    sql_types::{Bool, SmallInt, Uuid as DieselUuid},
};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _, SimpleAsyncConnection as _,
};
use ed25519_dalek::{Signer as _, SigningKey};
use nazo_operator_protocol::{
    RECOVERY_KDF_ID, RecoveryProposal, RecoveryRootRotation, derive_recovery_seed,
    format_recovery_secret, parse_recovery_secret, recovery_kid, validate_controller_id,
};
use nazo_postgres::{
    CONTROLLER_KEY_TTL_SECONDS, ControllerRegistryError, ControllerRegistryRepository,
    ControllerSlotStatus, IdentityApprovalError, IssuedIdentityApproval,
    MAX_RECOVERY_CHALLENGE_ATTEMPTS, NewControllerSlot, NewRecoveryChallenge, NewRecoveryRoot,
    RECOVERY_CHALLENGE_TTL_SECONDS, RecoveredSlotCommit, RecoveryRootError, RecoveryRootRepository,
    RecoveryRotationError, RecoverySubmission, create_pool,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

mod support;

use support::{
    query_counter::QueryCounter, run_isolated_application_migrations, schema_database_url,
};

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI recovery tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

async fn isolated(case: &str) -> Option<(String, RecoveryRootRepository)> {
    isolated_with_pool_size(case, 8).await
}

async fn isolated_with_pool_size(
    case: &str,
    max_connections: usize,
) -> Option<(String, RecoveryRootRepository)> {
    let database_url = database_url()?;
    let schema = format!("controller_recovery_{}_{}", case, Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE SCHEMA \"{schema}\";"))
        .await
        .expect("isolated schema should create");
    let isolated_url = schema_database_url(&database_url, &schema);
    run_isolated_application_migrations(&isolated_url).await;
    Some((
        isolated_url.clone(),
        RecoveryRootRepository::new(
            create_pool(isolated_url, max_connections).expect("pool should create"),
        ),
    ))
}

#[derive(QueryableByName)]
struct AttemptState {
    #[diesel(sql_type = SmallInt)]
    attempts: i16,
    #[diesel(sql_type = Bool)]
    consumed: bool,
}

async fn attempt_state(url: &str, challenge_id: Uuid) -> AttemptState {
    let mut connection = AsyncPgConnection::establish(url)
        .await
        .expect("fixture connection");
    sql_query(
        "SELECT attempts, consumed_at IS NOT NULL AS consumed
         FROM controller_recovery_challenges WHERE challenge_id = $1",
    )
    .bind::<DieselUuid, _>(challenge_id)
    .get_result(&mut connection)
    .await
    .expect("fixture challenge state")
}

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

fn kid_of(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

/// Stand-in for the control side: one generation's offline recovery material.
/// The secret is produced through the mandated display form and parsed back,
/// so the fixture exercises the exact transcription contract (04A §2).
struct RecoveryMaterial {
    display_secret: String,
    seed: [u8; 32],
    public_key: [u8; 32],
}

fn recovery_material(deployment: &str, generation: u8) -> RecoveryMaterial {
    let display_secret = format_recovery_secret(&[generation; 32]);
    let secret = parse_recovery_secret(&display_secret).expect("display form must parse");
    let seed = derive_recovery_seed(&secret, deployment);
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    RecoveryMaterial {
        display_secret,
        seed,
        public_key,
    }
}

impl RecoveryMaterial {
    fn rotation(&self, deployment: &str) -> RecoveryRootRotation {
        RecoveryRootRotation {
            deployment_id: deployment.to_owned(),
            kid: kid_of(&self.public_key),
            public_key: self.public_key,
        }
    }

    fn root_input(&self, deployment: &str) -> NewRecoveryRoot {
        NewRecoveryRoot {
            deployment_id: deployment.to_owned(),
            kid: kid_of(&self.public_key),
            public_key: self.public_key,
        }
    }

    fn sign(&self, proposal: &RecoveryProposal, challenge_id: Uuid, nonce: &[u8; 32]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed)
            .sign(&proposal.challenge_message(&challenge_id.to_string(), nonce))
            .to_bytes()
    }

    fn sign_allocation(
        &self,
        proposal: &RecoveryProposal,
        allocation_nonce: &[u8; 32],
    ) -> [u8; 64] {
        proposal.sign_allocation(allocation_nonce, &self.seed)
    }
}

fn controller_key_for_slot(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// The proposed replacement state of one recovery: a fresh controller key and
/// the next generation's Recovery Public Key.
fn challenge_input(
    deployment: &str,
    controller_seed: u8,
    next: &RecoveryMaterial,
    current: &RecoveryMaterial,
) -> NewRecoveryChallenge {
    let allocation_nonce = [controller_seed.wrapping_add(100); 32];
    let mut challenge = NewRecoveryChallenge {
        deployment_id: deployment.to_owned(),
        controller_label: "recovered-primary".to_owned(),
        controller_kid: kid_of(&controller_key_for_slot(controller_seed)),
        controller_public_key: controller_key_for_slot(controller_seed),
        recovery_kid: recovery_kid(&next.public_key),
        recovery_public_key: next.public_key,
        allocation_nonce,
        allocation_signature: [0; 64],
    };
    challenge.allocation_signature =
        current.sign_allocation(&proposal_from(&challenge), &allocation_nonce);
    challenge
}

fn proposal_from(challenge: &NewRecoveryChallenge) -> RecoveryProposal {
    RecoveryProposal {
        deployment_id: challenge.deployment_id.clone(),
        controller_label: challenge.controller_label.clone(),
        controller_kid: challenge.controller_kid.clone(),
        controller_public_key: challenge.controller_public_key,
        recovery_kid: challenge.recovery_kid.clone(),
        recovery_public_key: challenge.recovery_public_key,
    }
}

fn submission(
    deployment: &str,
    challenge_id: Uuid,
    nonce: &[u8; 32],
    signature: &[u8; 64],
) -> RecoverySubmission {
    RecoverySubmission {
        deployment_id: deployment.to_owned(),
        challenge_id,
        nonce: *nonce,
        signature: *signature,
    }
}

/// Enroll a root through the D12 approval path — the only way roots exist.
async fn enroll_root(
    repository: &RecoveryRootRepository,
    deployment: &str,
    material: &RecoveryMaterial,
    now: DateTime<Utc>,
) -> IssuedIdentityApproval {
    let rotation = material.rotation(deployment);
    let issued = repository
        .issue_rotation_approval(deployment, &rotation.action_sha256(), Uuid::now_v7(), now)
        .await
        .expect("approval issuance should succeed");
    repository
        .commit_rotation(
            &issued.token,
            deployment,
            &rotation.action_sha256(),
            material.root_input(deployment),
            now,
        )
        .await
        .expect("root enrollment should succeed in fixtures");
    issued
}

async fn registry_repository(url: &str) -> ControllerRegistryRepository {
    ControllerRegistryRepository::new(create_pool(url.to_owned(), 8).expect("pool should create"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_needs_unconsumed_fresh_approval_and_bumps_exactly_one_generation() {
    let Some((_url, repository)) = isolated("rotate").await else {
        return;
    };
    let deployment = "deployment-recovery-rotate";
    let first = recovery_material(deployment, 1);
    let second = recovery_material(deployment, 2);

    assert!(
        repository
            .current_root(deployment)
            .await
            .expect("read should succeed")
            .is_none()
    );

    // Enrollment through the approved path lands at generation 1 with the
    // pinned KDF id stored alongside the key (D10).
    enroll_root(&repository, deployment, &first, at(0)).await;
    let root = repository
        .current_root(deployment)
        .await
        .expect("read should succeed")
        .expect("root should exist after enrollment");
    assert_eq!(root.generation, 1);
    assert_eq!(root.kdf, RECOVERY_KDF_ID);
    assert_eq!(root.recovery_kid, kid_of(&first.public_key));
    // Neither the stored row nor its summary view carries any secret marker.
    let summary_rendered = format!("{:?}", root.summary());
    let rendered = format!("{root:?} {summary_rendered}");
    assert!(!rendered.contains("NAZO-RECOVERY-"));
    assert!(!rendered.contains(&first.display_secret));

    // An unknown token cannot commit.
    let unknown = repository
        .commit_rotation(
            "unused",
            deployment,
            &"a".repeat(64),
            second.root_input(deployment),
            at(1),
        )
        .await
        .expect_err("unknown token must fail");
    assert!(matches!(
        unknown,
        RecoveryRotationError::Approval(IdentityApprovalError::UnknownToken)
    ));

    // A valid old-root allocation may be in flight when an administrator
    // proactively rotates the root. The rotation must close it atomically so
    // it cannot squat on the new generation's one-pending slot.
    let pending_before_rotation = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 50, &recovery_material(deployment, 3), &first),
            at(1),
        )
        .await
        .expect("old root can authorize one pending challenge");

    // Approved rotation bumps exactly one generation and replaces material.
    let rotation = second.rotation(deployment);
    let issued = repository
        .issue_rotation_approval(deployment, &rotation.action_sha256(), Uuid::now_v7(), at(2))
        .await
        .expect("issuance should succeed");
    let rotated = repository
        .commit_rotation(
            &issued.token,
            deployment,
            &rotation.action_sha256(),
            second.root_input(deployment),
            at(3),
        )
        .await
        .expect("approved rotation should commit");
    assert_eq!(rotated.generation, 2);
    assert_eq!(rotated.recovery_kid, kid_of(&second.public_key));
    let old_pending = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                pending_before_rotation.challenge_id,
                &pending_before_rotation.nonce,
                &[0; 64],
            ),
            at(4),
        )
        .await
        .expect_err("rotation must terminalize the old generation's pending challenge");
    assert!(matches!(old_pending, RecoveryRootError::ChallengeReplayed));
    repository
        .issue_recovery_challenge(
            challenge_input(deployment, 51, &recovery_material(deployment, 4), &second),
            at(4),
        )
        .await
        .expect("the new root must not be blocked by old pending state");

    // Replay of the consumed token fails and changes nothing.
    let replay = repository
        .commit_rotation(
            &issued.token,
            deployment,
            &rotation.action_sha256(),
            second.root_input(deployment),
            at(4),
        )
        .await
        .expect_err("replay must fail");
    assert!(matches!(
        replay,
        RecoveryRotationError::Approval(IdentityApprovalError::Replayed)
    ));
    assert_eq!(
        repository
            .current_root(deployment)
            .await
            .expect("read should succeed")
            .expect("root remains")
            .generation,
        2
    );

    // A generation bump must always replace key material; otherwise proofs
    // from before a nominal rotation would still verify afterwards.
    let same_rotation = second.rotation(deployment);
    let same_approval = repository
        .issue_rotation_approval(
            deployment,
            &same_rotation.action_sha256(),
            Uuid::now_v7(),
            at(5),
        )
        .await
        .expect("approval issuance is independent of current root material");
    let same_key = repository
        .commit_rotation(
            &same_approval.token,
            deployment,
            &same_rotation.action_sha256(),
            second.root_input(deployment),
            at(6),
        )
        .await
        .expect_err("rotation to identical recovery material must fail");
    assert!(matches!(
        same_key,
        RecoveryRotationError::Mutation(RecoveryRootError::InvalidIdentity(_))
    ));

    // An unconsumed but expired approval cannot commit either.
    let stale_rotation = first.rotation(deployment);
    let stale = repository
        .issue_rotation_approval(
            deployment,
            &stale_rotation.action_sha256(),
            Uuid::now_v7(),
            at(7),
        )
        .await
        .expect("issuance should succeed");
    let expired = repository
        .commit_rotation(
            &stale.token,
            deployment,
            &stale_rotation.action_sha256(),
            first.root_input(deployment),
            at(7) + Duration::seconds(RECOVERY_CHALLENGE_TTL_SECONDS + 60),
        )
        .await
        .expect_err("expired approval must fail");
    assert!(matches!(
        expired,
        RecoveryRotationError::Approval(IdentityApprovalError::Expired)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotated_away_recovery_keys_can_never_be_installed_again() {
    let Some((_url, repository)) = isolated("root_history").await else {
        return;
    };
    let deployment = "deployment-recovery-history";
    let first = recovery_material(deployment, 1);
    let second = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &first, at(0)).await;

    let second_rotation = second.rotation(deployment);
    let second_approval = repository
        .issue_rotation_approval(
            deployment,
            &second_rotation.action_sha256(),
            Uuid::now_v7(),
            at(1),
        )
        .await
        .expect("approval should issue");
    let rotated = repository
        .commit_rotation(
            &second_approval.token,
            deployment,
            &second_rotation.action_sha256(),
            second.root_input(deployment),
            at(2),
        )
        .await
        .expect("fresh key should rotate");
    assert_eq!(rotated.generation, 2);

    let reuse_rotation = first.rotation(deployment);
    let reuse_approval = repository
        .issue_rotation_approval(
            deployment,
            &reuse_rotation.action_sha256(),
            Uuid::now_v7(),
            at(3),
        )
        .await
        .expect("approval should issue");
    let reuse = repository
        .commit_rotation(
            &reuse_approval.token,
            deployment,
            &reuse_rotation.action_sha256(),
            first.root_input(deployment),
            at(4),
        )
        .await
        .expect_err("historical key reuse must fail");
    assert!(matches!(
        reuse,
        RecoveryRotationError::Mutation(RecoveryRootError::InvalidIdentity(_))
    ));

    let root = repository
        .current_root(deployment)
        .await
        .expect("root read should work")
        .expect("root should remain installed");
    assert_eq!(root.generation, 2);
    assert_eq!(root.recovery_public_key, second.public_key);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_rotations_cannot_install_one_recovery_key_twice() {
    let Some((_url, repository)) = isolated("root_history_concurrent").await else {
        return;
    };
    let deployment = "deployment-recovery-history-race";
    let first = recovery_material(deployment, 1);
    let second = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &first, at(0)).await;
    let rotation = second.rotation(deployment);
    let action_sha256 = rotation.action_sha256();
    let first_approval = repository
        .issue_rotation_approval(deployment, &action_sha256, Uuid::now_v7(), at(1))
        .await
        .unwrap();
    let second_approval = repository
        .issue_rotation_approval(deployment, &action_sha256, Uuid::now_v7(), at(1))
        .await
        .unwrap();

    let first_commit = repository.commit_rotation(
        &first_approval.token,
        deployment,
        &action_sha256,
        second.root_input(deployment),
        at(2),
    );
    let second_commit = repository.commit_rotation(
        &second_approval.token,
        deployment,
        &action_sha256,
        second.root_input(deployment),
        at(2),
    );
    let (first_result, second_result) = tokio::join!(first_commit, second_commit);
    let failure = match (first_result, second_result) {
        (Ok(_), Err(error)) | (Err(error), Ok(_)) => error,
        (Ok(_), Ok(_)) => panic!("the same recovery key committed twice"),
        (Err(first), Err(second)) => {
            panic!("both serialized rotations failed: {first}; {second}")
        }
    };
    assert!(matches!(
        failure,
        RecoveryRotationError::Mutation(RecoveryRootError::InvalidIdentity(_))
    ));

    let root = repository.current_root(deployment).await.unwrap().unwrap();
    assert_eq!(root.generation, 2);
    assert_eq!(root.recovery_public_key, second.public_key);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn challenges_are_refused_while_any_controller_is_admitted_and_single_pending() {
    let Some((url, repository)) = isolated_with_pool_size("gate_p1", 1).await else {
        return;
    };
    let deployment = "deployment-recovery-gate";
    let current = recovery_material(deployment, 1);
    enroll_root(&repository, deployment, &current, at(0)).await;
    let registry = repository.registry();
    let key = controller_key_for_slot(9);
    registry
        .create_slot(
            NewControllerSlot {
                deployment_id: deployment.to_owned(),
                label: "primary".to_owned(),
                kid: kid_of(&key),
                public_key: key,
            },
            at(0),
        )
        .await
        .expect("slot should enroll");

    // An unauthenticated caller cannot allocate state or use the endpoint as
    // an admitted-controller oracle: proof verification happens first.
    let mut forged_allocation =
        challenge_input(deployment, 10, &recovery_material(deployment, 2), &current);
    forged_allocation.allocation_signature[0] ^= 1;
    let forged = repository
        .issue_recovery_challenge(forged_allocation, at(1))
        .await
        .expect_err("invalid allocation proof must fail before state or gate disclosure");
    assert!(matches!(forged, RecoveryRootError::InvalidAllocationProof));

    // With one admitting key left the ordinary fresh-2FA identity paths are
    // available, so the break-glass challenge is refused outright.
    let refused = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 10, &recovery_material(deployment, 2), &current),
            at(2),
        )
        .await
        .expect_err("challenge must be refused while controllers admit");
    match refused {
        RecoveryRootError::ControllersStillAdmitted(admitted) => {
            assert_eq!(admitted.len(), 1);
            assert!(!format!("{admitted:?}").contains("public_key"));
        }
        other => panic!("unexpected error: {other}"),
    }

    // Revoke the last slot: no admitting key remains, issuance succeeds.
    for slot in registry
        .list_slots(deployment)
        .await
        .expect("listing works")
    {
        registry
            .revoke_slot(deployment, &slot.controller_id, at(3))
            .await
            .expect("revocation should succeed");
    }
    let issued = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 10, &recovery_material(deployment, 2), &current),
            at(4),
        )
        .await
        .expect("challenge should issue without admitting keys");
    assert_eq!(
        (issued.expires_at - at(4)).num_seconds(),
        RECOVERY_CHALLENGE_TTL_SECONDS
    );
    let idempotent = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 10, &recovery_material(deployment, 2), &current),
            at(5),
        )
        .await
        .expect("the same live allocation proof must return the same challenge");
    assert_eq!(idempotent, issued);

    // At most ONE outstanding challenge per deployment.
    let pending = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 11, &recovery_material(deployment, 3), &current),
            at(6),
        )
        .await
        .expect_err("second pending challenge must be refused");
    assert!(matches!(pending, RecoveryRootError::ChallengePending));

    // Burn the outstanding challenge through its attempt cap; afterwards a
    // new challenge may be issued again because the dead one stops blocking.
    for attempt in 0..MAX_RECOVERY_CHALLENGE_ATTEMPTS {
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            repository.submit_recovery_challenge(
                submission(
                    deployment,
                    issued.challenge_id,
                    &issued.nonce,
                    &[0xffu8; 64],
                ),
                at(7 + i64::from(attempt)),
            ),
        )
        .await
        .expect("a rejected submission must not wait for a second pool connection")
        .expect_err("wrong signature must fail");
        assert!(matches!(outcome, RecoveryRootError::InvalidSignature));
    }
    let state = attempt_state(&url, issued.challenge_id).await;
    assert_eq!(i32::from(state.attempts), MAX_RECOVERY_CHALLENGE_ATTEMPTS);
    assert!(
        state.consumed,
        "the fifth rejected answer must close the challenge"
    );
    let dead = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                issued.challenge_id,
                &issued.nonce,
                &[0xffu8; 64],
            ),
            at(20),
        )
        .await
        .expect_err("exhausted challenge must refuse");
    assert!(matches!(dead, RecoveryRootError::ChallengeExhausted));

    let replayed_allocation = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 10, &recovery_material(deployment, 2), &current),
            at(21),
        )
        .await
        .expect_err("a consumed allocation proof must not create another challenge");
    assert!(matches!(
        replayed_allocation,
        RecoveryRootError::AllocationProofReplayed
    ));

    repository
        .issue_recovery_challenge(
            challenge_input(deployment, 12, &recovery_material(deployment, 4), &current),
            at(22),
        )
        .await
        .expect("a new challenge may issue once the old one is dead");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_recovery_revokes_everything_installs_one_slot_and_rotates_the_root() {
    let Some((url, repository)) = isolated_with_pool_size("commit_p1", 1).await else {
        return;
    };
    let registry = registry_repository(&url).await;
    let deployment = "deployment-recovery-commit";
    let old_material = recovery_material(deployment, 1);
    let next_material = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &old_material, at(0)).await;

    // Two lost keys exist, then get revoked out of the admitting set.
    for seed in [1u8, 2] {
        let key = controller_key_for_slot(seed);
        let slot = registry
            .create_slot(
                NewControllerSlot {
                    deployment_id: deployment.to_owned(),
                    label: format!("lost-{seed}"),
                    kid: kid_of(&key),
                    public_key: key,
                },
                at(0),
            )
            .await
            .expect("fixture slot should enroll");
        registry
            .revoke_slot(deployment, &slot.controller_id, at(5))
            .await
            .expect("fixture revocation should succeed");
    }

    // The break-glass flow: challenge bound to the EXACT proposed material.
    let challenge = challenge_input(deployment, 9, &next_material, &old_material);
    let proposal = proposal_from(&challenge);
    proposal
        .validate()
        .expect("fixture proposal is well formed");
    let issued = repository
        .issue_recovery_challenge(challenge, at(10))
        .await
        .expect("challenge should issue");
    let signature = old_material.sign(&proposal, issued.challenge_id, &issued.nonce);

    // Wrong nonce fails without consuming anything but the attempt counter.
    let mut wrong_nonce = issued.nonce;
    wrong_nonce[0] ^= 1;
    let nonce_failure = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        repository.submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &wrong_nonce, &signature),
            at(11),
        ),
    )
    .await
    .expect("nonce rejection must finish with the only pool connection")
    .expect_err("wrong nonce must fail");
    assert!(matches!(nonce_failure, RecoveryRootError::NonceMismatch));
    let state = attempt_state(&url, issued.challenge_id).await;
    assert_eq!(
        state.attempts, 1,
        "the counter survives the rejected transaction"
    );
    assert!(!state.consumed);

    // The correct answer atomically commits the whole recovery.
    let commit: RecoveredSlotCommit = repository
        .submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &issued.nonce, &signature),
            at(12),
        )
        .await
        .expect("signed answer must commit");
    assert_eq!(commit.recovery_generation, 2);
    let retry = repository
        .submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &issued.nonce, &signature),
            at(13),
        )
        .await
        .expect("an exact receipt retry also works with pool size one");
    assert_eq!(retry, commit);
    assert_eq!(attempt_state(&url, issued.challenge_id).await.attempts, 1);
    validate_controller_id(&commit.slot.controller_id)
        .expect("the recovered slot gets a freshly assigned UUIDv7 controller_id");
    assert_eq!(commit.slot.status, ControllerSlotStatus::Active);
    assert_eq!(commit.slot.label, "recovered-primary");
    assert_eq!(commit.slot.kid, kid_of(&controller_key_for_slot(9)));
    assert_eq!(commit.slot.issued_at, at(12));
    assert_eq!(
        (commit.slot.expires_at - commit.slot.issued_at).num_seconds(),
        CONTROLLER_KEY_TTL_SECONDS,
        "the recovered slot obeys the fixed 30-day expiry"
    );
    assert_eq!(
        commit.slot.slot_index, 0,
        "lowest free index after mass revocation"
    );

    // Exactly one admitting key exists; everything else stays revoked history.
    let admitted = repository
        .registry()
        .admitted_controllers(deployment, at(13))
        .await
        .expect("admission listing works");
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted[0].kid, commit.slot.kid);
    let slots = registry
        .list_slots(deployment)
        .await
        .expect("listing works");
    assert_eq!(slots.len(), 3);
    assert_eq!(
        slots
            .iter()
            .filter(|slot| slot.status == ControllerSlotStatus::Revoked)
            .count(),
        2
    );

    // The root was replaced in the same transaction.
    let root = repository
        .current_root(deployment)
        .await
        .expect("read works")
        .expect("root remains");
    assert_eq!(root.generation, 2);
    assert_eq!(root.recovery_kid, kid_of(&next_material.public_key));

    // The OLD secret is dead: on a fresh challenge it cannot verify anymore.
    registry
        .revoke_slot(deployment, &commit.slot.controller_id, at(20))
        .await
        .expect("fixture revocation frees the gate");
    let later = recovery_material(deployment, 3);
    let stale_allocation = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 21, &later, &old_material),
            at(21),
        )
        .await
        .expect_err("a proof made by the rotated-away root must fail allocation");
    assert!(matches!(
        stale_allocation,
        RecoveryRootError::InvalidAllocationProof
    ));
    let issued_second = repository
        .issue_recovery_challenge(
            challenge_input(deployment, 21, &later, &next_material),
            at(21),
        )
        .await
        .expect("new challenge should issue");
    let stale_signature = old_material.sign(
        &proposal_from(&challenge_input(deployment, 21, &later, &next_material)),
        issued_second.challenge_id,
        &issued_second.nonce,
    );
    let stale_outcome = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                issued_second.challenge_id,
                &issued_second.nonce,
                &stale_signature,
            ),
            at(22),
        )
        .await
        .expect_err("old-generation secret must fail");
    assert!(matches!(stale_outcome, RecoveryRootError::InvalidSignature));

    // A recovery-derived public key never admits ordinary operations: the
    // admission lookup only answers for controller slots.
    for kid in [kid_of(&old_material.public_key), root.recovery_kid.clone()] {
        assert!(
            registry
                .admitted_controller_by_kid(deployment, &kid, at(23))
                .await
                .expect("lookup works")
                .is_none(),
            "recovery material must never appear in the admitting set"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_cannot_reinstall_a_historical_root_or_leave_a_slot() {
    let Some((_url, repository)) = isolated("recover_root_history").await else {
        return;
    };
    let deployment = "deployment-recovery-history-commit";
    let first = recovery_material(deployment, 1);
    let second = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &first, at(0)).await;

    let to_second = challenge_input(deployment, 10, &second, &first);
    let to_second_proposal = proposal_from(&to_second);
    let issued = repository
        .issue_recovery_challenge(to_second, at(1))
        .await
        .expect("first recovery challenge should issue");
    let signature = first.sign(&to_second_proposal, issued.challenge_id, &issued.nonce);
    let recovered = repository
        .submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &issued.nonce, &signature),
            at(2),
        )
        .await
        .expect("fresh recovery root should commit");
    repository
        .registry()
        .revoke_slot(deployment, &recovered.slot.controller_id, at(3))
        .await
        .expect("fixture revocation should close ordinary admission");

    let back_to_first = challenge_input(deployment, 11, &first, &second);
    let back_to_first_proposal = proposal_from(&back_to_first);
    let issued = repository
        .issue_recovery_challenge(back_to_first, at(4))
        .await
        .expect("current root may allocate the exact proposal");
    let signature = second.sign(&back_to_first_proposal, issued.challenge_id, &issued.nonce);
    let rejected = repository
        .submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &issued.nonce, &signature),
            at(5),
        )
        .await
        .expect_err("historical root must not be reinstalled");
    assert!(matches!(rejected, RecoveryRootError::InvalidIdentity(_)));

    let root = repository.current_root(deployment).await.unwrap().unwrap();
    assert_eq!(root.generation, 2);
    assert_eq!(root.recovery_public_key, second.public_key);
    assert!(
        repository
            .registry()
            .admitted_controllers(deployment, at(6))
            .await
            .unwrap()
            .is_empty(),
        "failed recovery must roll back the proposed controller slot"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_expiry_and_wrong_signers_fail_closed_without_partial_state() {
    let Some((_url, repository)) = isolated("failclosed").await else {
        return;
    };
    let deployment = "deployment-recovery-fail";
    let material = recovery_material(deployment, 1);
    let next = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &material, at(0)).await;

    // Expired challenge: dead by the fixed server-side window even though it
    // was never consumed.
    let expired_challenge = challenge_input(deployment, 30, &next, &material);
    let expired_proposal = proposal_from(&expired_challenge);
    let expired_issued = repository
        .issue_recovery_challenge(expired_challenge, at(0))
        .await
        .expect("challenge issues");
    let expired_signature = material.sign(
        &expired_proposal,
        expired_issued.challenge_id,
        &expired_issued.nonce,
    );
    let outcome = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                expired_issued.challenge_id,
                &expired_issued.nonce,
                &expired_signature,
            ),
            expired_issued.expires_at,
        )
        .await
        .expect_err("expired challenge must refuse");
    assert!(matches!(outcome, RecoveryRootError::ChallengeExpired));

    // Unknown challenge ids fail closed.
    let ghost = Uuid::now_v7();
    let unknown = repository
        .submit_recovery_challenge(submission(deployment, ghost, &[0u8; 32], &[0u8; 64]), at(1))
        .await
        .expect_err("unknown challenge must fail");
    assert!(matches!(unknown, RecoveryRootError::ChallengeUnknown));

    // Live challenge: wrong signer cannot pass, the right one commits once,
    // and an identical replay afterwards is rejected as consumed.  The first
    // (lapsed) challenge stays pending until its TTL passes, so reissuing
    // starts after expiry — a live pending challenge blocks issuance.
    let live_challenge = challenge_input(deployment, 31, &next, &material);
    let live_proposal = proposal_from(&live_challenge);
    let live_issued = repository
        .issue_recovery_challenge(live_challenge, at(601))
        .await
        .expect("challenge issues after the lapsed one expired");
    let impostor = SigningKey::from_bytes(&[0x77u8; 32]);
    let forged = impostor
        .sign(
            &live_proposal
                .challenge_message(&live_issued.challenge_id.to_string(), &live_issued.nonce),
        )
        .to_bytes();
    let forged_outcome = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                live_issued.challenge_id,
                &live_issued.nonce,
                &forged,
            ),
            at(602),
        )
        .await
        .expect_err("a non-recovery signer must fail");
    assert!(matches!(
        forged_outcome,
        RecoveryRootError::InvalidSignature
    ));

    let genuine = material.sign(&live_proposal, live_issued.challenge_id, &live_issued.nonce);
    let commit = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                live_issued.challenge_id,
                &live_issued.nonce,
                &genuine,
            ),
            at(603),
        )
        .await
        .expect("the right answer commits");
    assert_eq!(commit.slot.kid, kid_of(&controller_key_for_slot(31)));

    let replayed = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                live_issued.challenge_id,
                &live_issued.nonce,
                &genuine,
            ),
            at(604),
        )
        .await
        .expect("an exact retry must return the committed receipt");
    assert_eq!(replayed, commit);

    let altered_replay = repository
        .submit_recovery_challenge(
            submission(
                deployment,
                live_issued.challenge_id,
                &live_issued.nonce,
                &forged,
            ),
            at(605),
        )
        .await
        .expect_err("a different signed answer must not read the receipt");
    assert!(matches!(
        altered_replay,
        RecoveryRootError::ChallengeReplayed
    ));

    // Cross-deployment submissions cannot read another deployment's challenge.
    let cross = repository
        .submit_recovery_challenge(
            submission(
                "deployment-other",
                live_issued.challenge_id,
                &live_issued.nonce,
                &genuine,
            ),
            at(14),
        )
        .await
        .expect_err("cross-deployment submission must fail");
    assert!(matches!(cross, RecoveryRootError::ChallengeUnknown));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovered_slots_count_toward_the_three_slot_bound() {
    let Some((_url, repository)) = isolated("bound").await else {
        return;
    };
    let deployment = "deployment-recovery-bound";
    let material = recovery_material(deployment, 1);
    let next = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &material, at(0)).await;

    let challenge = challenge_input(deployment, 40, &next, &material);
    let proposal = proposal_from(&challenge);
    let issued = repository
        .issue_recovery_challenge(challenge, at(0))
        .await
        .expect("no admitting keys, no active slots: gate open");
    let signature = material.sign(&proposal, issued.challenge_id, &issued.nonce);
    repository
        .submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &issued.nonce, &signature),
            at(1),
        )
        .await
        .expect("recovery commits");

    let registry = repository.registry();
    // Two more ordinary slots fill the set to three...
    for seed in [41u8, 42] {
        let key = controller_key_for_slot(seed);
        registry
            .create_slot(
                NewControllerSlot {
                    deployment_id: deployment.to_owned(),
                    label: format!("extra-{seed}"),
                    kid: kid_of(&key),
                    public_key: key,
                },
                at(2),
            )
            .await
            .unwrap_or_else(|error| panic!("slot {seed} should enroll: {error}"));
    }
    // ...and the fourth add is refused exactly like any normal over-add.
    let fourth_key = controller_key_for_slot(43);
    let refused = registry
        .create_slot(
            NewControllerSlot {
                deployment_id: deployment.to_owned(),
                label: "fourth".to_owned(),
                kid: kid_of(&fourth_key),
                public_key: fourth_key,
            },
            at(3),
        )
        .await
        .expect_err("fourth active slot must be refused");
    assert!(matches!(refused, ControllerRegistryError::SlotLimit(_)));
}

/// P0-5 negative test: a recovery submission must WAIT for the shared
/// per-deployment identity lock. Before the lock unification a concurrent
/// bind could commit its active slot between the challenge's re-check and
/// the batch revoke, because recovery held a different advisory key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_submission_waits_for_the_deployment_identity_lock() {
    use nazo_postgres::DEPLOYMENT_IDENTITY_LOCK_SEED;
    use std::time::Duration as StdDuration;

    let Some((url, repository)) = isolated("lock_interleave").await else {
        return;
    };
    let deployment = "deployment-recovery-lock";
    let material = recovery_material(deployment, 1);
    let next = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &material, at(0)).await;

    // No admitting controllers exist, so break-glass issuance succeeds.
    let challenge = challenge_input(deployment, 40, &next, &material);
    let proposal = proposal_from(&challenge);
    let issued = repository
        .issue_recovery_challenge(challenge, at(1))
        .await
        .expect("challenge issues without admitted controllers");
    let signature = material.sign(&proposal, issued.challenge_id, &issued.nonce);

    // An explicit transaction occupies the SHARED deployment identity lock —
    // exactly what any concurrent bind/rotate commit holds while it runs.
    let mut holder = AsyncPgConnection::establish(&url)
        .await
        .expect("holder connection");
    holder
        .batch_execute("BEGIN")
        .await
        .expect("holder transaction");
    holder
        .batch_execute(&format!(
            "SELECT pg_advisory_xact_lock(hashtextextended('{deployment}', \
             {DEPLOYMENT_IDENTITY_LOCK_SEED}));"
        ))
        .await
        .expect("holder takes the identity lock");

    // While the lock is held the submission cannot complete.
    let pending = repository.submit_recovery_challenge(
        submission(deployment, issued.challenge_id, &issued.nonce, &signature),
        at(2),
    );
    tokio::pin!(pending);
    let raced = tokio::time::timeout(StdDuration::from_millis(400), pending.as_mut()).await;
    assert!(
        raced.is_err(),
        "submission must block on the shared deployment identity lock"
    );

    // Releasing the holder lets the same submission finish its commit.
    holder
        .batch_execute("COMMIT")
        .await
        .expect("holder releases the lock");
    let commit = pending
        .await
        .expect("submission completes once the lock releases");
    assert_eq!(commit.slot.kid, kid_of(&controller_key_for_slot(40)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_failure_rolls_back_root_approval_and_pending_challenge() {
    let Some((url, repository)) = isolated("hist_fail").await else {
        return;
    };
    let deployment = "deployment-history-failure";
    let first = recovery_material(deployment, 1);
    let second = recovery_material(deployment, 2);
    let third = recovery_material(deployment, 3);
    enroll_root(&repository, deployment, &first, at(0)).await;
    let before = repository.current_root(deployment).await.unwrap().unwrap();
    let pending = repository
        .issue_recovery_challenge(challenge_input(deployment, 60, &third, &first), at(1))
        .await
        .unwrap();
    let rotation = second.rotation(deployment);
    let approval = repository
        .issue_rotation_approval(
            deployment,
            &rotation.action_sha256(),
            Uuid::now_v7(),
            at(2),
        )
        .await
        .unwrap();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    connection
        .batch_execute(
            "ALTER TABLE controller_recovery_root_key_history
             ADD CONSTRAINT injected_history_failure CHECK (false) NOT VALID",
        )
        .await
        .unwrap();
    let error = repository
        .commit_rotation(
            &approval.token,
            deployment,
            &rotation.action_sha256(),
            second.root_input(deployment),
            at(3),
        )
        .await
        .expect_err("failed history insertion must abort the complete rotation");
    assert!(matches!(
        error,
        RecoveryRotationError::Mutation(RecoveryRootError::Transport(_))
    ));
    assert_eq!(repository.current_root(deployment).await.unwrap().unwrap(), before);
    let pending_state = attempt_state(&url, pending.challenge_id).await;
    assert_eq!(pending_state.attempts, 0);
    assert!(!pending_state.consumed);
    connection
        .batch_execute(
            "ALTER TABLE controller_recovery_root_key_history DROP CONSTRAINT injected_history_failure",
        )
        .await
        .unwrap();
    let replaced = repository
        .commit_rotation(
            &approval.token,
            deployment,
            &rotation.action_sha256(),
            second.root_input(deployment),
            at(4),
        )
        .await
        .expect("failed history insertion must also roll back approval consumption");
    assert_eq!(replaced.generation, 2);
    assert_eq!(replaced.created_at, before.created_at);
    assert_eq!(replaced.kdf, before.kdf);
    assert_eq!(replaced.updated_at, at(4));
    assert_eq!(replaced, repository.current_root(deployment).await.unwrap().unwrap());
    assert!(attempt_state(&url, pending.challenge_id).await.consumed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generation_exhaustion_rolls_back_the_root_and_approval() {
    let Some((url, repository)) = isolated("gen_max").await else {
        return;
    };
    let deployment = "deployment-generation-exhaustion";
    let first = recovery_material(deployment, 1);
    let second = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &first, at(0)).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    sql_query("UPDATE controller_recovery_roots SET generation = $2 WHERE deployment_id = $1")
        .bind::<diesel::sql_types::Varchar, _>(deployment)
        .bind::<diesel::sql_types::Integer, _>(i32::MAX)
        .execute(&mut connection)
        .await
        .unwrap();
    let before = repository.current_root(deployment).await.unwrap().unwrap();
    let rotation = second.rotation(deployment);
    let approval = repository
        .issue_rotation_approval(
            deployment,
            &rotation.action_sha256(),
            Uuid::now_v7(),
            at(1),
        )
        .await
        .unwrap();
    let error = repository
        .commit_rotation(
            &approval.token,
            deployment,
            &rotation.action_sha256(),
            second.root_input(deployment),
            at(2),
        )
        .await
        .expect_err("generation overflow must fail closed");
    assert!(matches!(
        error,
        RecoveryRotationError::Mutation(RecoveryRootError::Transport(_))
    ));
    assert_eq!(repository.current_root(deployment).await.unwrap().unwrap(), before);
    sql_query("UPDATE controller_recovery_roots SET generation = $2 WHERE deployment_id = $1")
        .bind::<diesel::sql_types::Varchar, _>(deployment)
        .bind::<diesel::sql_types::Integer, _>(i32::MAX - 1)
        .execute(&mut connection)
        .await
        .unwrap();
    let replaced = repository
        .commit_rotation(
            &approval.token,
            deployment,
            &rotation.action_sha256(),
            second.root_input(deployment),
            at(3),
        )
        .await
        .expect("overflow must leave both approval and fresh key available for retry");
    assert_eq!(replaced.generation, i32::MAX);
    assert_eq!(replaced.recovery_public_key, second.public_key);
    assert_eq!(replaced.created_at, before.created_at);
    assert_eq!(replaced.kdf, before.kdf);
    assert_eq!(replaced, repository.current_root(deployment).await.unwrap().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_enrollment_and_replacement_return_rows_in_six_data_queries() {
    let Some((url, _fixture)) = isolated("root_rows").await else {
        return;
    };
    let pool = create_pool(url, 1).unwrap();
    let counter = QueryCounter::new();
    let mut connection = pool.get().await.unwrap();
    connection.set_instrumentation(counter.clone());
    drop(connection);
    let repository = RecoveryRootRepository::new(pool);
    let deployment = "deployment-root-returning";
    let mut first_created_at = None;
    for generation in [1u8, 2] {
        let material = recovery_material(deployment, generation);
        let rotation = material.rotation(deployment);
        let now = at(i64::from(generation));
        let approval = repository
            .issue_rotation_approval(
                deployment,
                &rotation.action_sha256(),
                Uuid::now_v7(),
                now,
            )
            .await
            .unwrap();
        let before = counter.snapshot();
        let root = repository
            .commit_rotation(
                &approval.token,
                deployment,
                &rotation.action_sha256(),
                material.root_input(deployment),
                now,
            )
            .await
            .unwrap();
        let evidence = counter.since(before);
        assert_eq!(evidence.data_queries, 6);
        assert_eq!(evidence.begins, 1);
        assert_eq!(evidence.commits, 1);
        assert_eq!(evidence.rollbacks, 0);
        assert_eq!(evidence.failed_queries, 0);
        assert_eq!(root.generation, i32::from(generation));
        assert_eq!(root.kdf, RECOVERY_KDF_ID);
        assert_eq!(root.updated_at, now);
        assert_eq!(root.created_at, *first_created_at.get_or_insert(now));
        assert_eq!(root, repository.current_root(deployment).await.unwrap().unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_rollback_does_not_reuse_a_connection_for_the_counter() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

    #[derive(QueryableByName)]
    struct BackendPid {
        #[diesel(sql_type = diesel::sql_types::Integer)]
        pid: i32,
    }
    #[derive(QueryableByName)]
    struct Termination {
        #[diesel(sql_type = Bool)]
        terminated: bool,
    }

    let Some((url, _fixture)) = isolated("rollback_loss").await else {
        return;
    };
    let pool = create_pool(url.clone(), 1).unwrap();
    let repository = RecoveryRootRepository::new(pool.clone());
    let deployment = "deployment-rollback-loss";
    let first = recovery_material(deployment, 1);
    let second = recovery_material(deployment, 2);
    enroll_root(&repository, deployment, &first, at(0)).await;
    let before = repository.current_root(deployment).await.unwrap().unwrap();
    let issued = repository
        .issue_recovery_challenge(challenge_input(deployment, 70, &second, &first), at(1))
        .await
        .unwrap();
    let mut connection = pool.get().await.unwrap();
    let pid = sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<BackendPid>(&mut connection)
        .await
        .unwrap();
    let mut killer = AsyncPgConnection::establish(&url).await.unwrap();
    let rollback_interrupted = Arc::new(AtomicBool::new(false));
    let attempted_counter = Arc::new(AtomicBool::new(false));
    let interrupted = rollback_interrupted.clone();
    let attempted = attempted_counter.clone();
    connection.set_instrumentation(move |event: InstrumentationEvent<'_>| {
        if let InstrumentationEvent::StartQuery { query, .. } = &event {
            if query.to_string().contains("SET attempts = attempts + 1") {
                attempted.store(true, Ordering::SeqCst);
            }
        }
        if matches!(&event, InstrumentationEvent::RollbackTransaction { .. })
            && !interrupted.swap(true, Ordering::SeqCst)
        {
            // Interrupt this fixture's own backend before its ROLLBACK.
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    sql_query("SELECT pg_terminate_backend($1) AS terminated")
                        .bind::<diesel::sql_types::Integer, _>(pid.pid)
                        .get_result::<Termination>(&mut killer)
                        .await
                        .expect("the fixture must be able to terminate its own backend")
                })
            });
            assert!(result.terminated);
        }
    });
    drop(connection);
    let mut wrong_nonce = issued.nonce;
    wrong_nonce[0] ^= 1;
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        repository.submit_recovery_challenge(
            submission(deployment, issued.challenge_id, &wrong_nonce, &[0u8; 64]),
            at(2),
        ),
    )
    .await
    .expect("a failed rollback must return without another pool checkout")
    .expect_err("rollback transport failure must fail closed");
    assert!(matches!(error, RecoveryRootError::Transport(_)));
    assert!(rollback_interrupted.load(Ordering::SeqCst));
    assert!(!attempted_counter.load(Ordering::SeqCst));
    let state = attempt_state(&url, issued.challenge_id).await;
    assert_eq!(state.attempts, 0);
    assert!(!state.consumed);
    assert_eq!(repository.current_root(deployment).await.unwrap().unwrap(), before);
}
