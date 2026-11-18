//! E04 admission stages 1/2/4: strict presentation parsing and Controller
//! Registry admission.
//!
//! Stage 1 parses the presented compact JWS far enough to classify malformed
//! input *before* any authority is consulted: size bounds, three segments,
//! base64url payload, closed envelope schema (`deny_unknown_fields`
//! everywhere), and the frozen policy validators.  It deliberately does not
//! touch signatures — key material is not known yet.
//!
//! Stage 2 resolves the controller kid/public key **by deployment_id** from
//! the D01/D02 Controller Registry persistence port. NazoAuth is the only
//! authority that answers whether this controller key is currently admitted.
//! Stage 4 requires an active current key. Expired keys require a signed
//! successor proposal through the privileged local operator channel; expiry
//! alone is not revocation of that host administrator's controller identity.

use anyhow::Context as _;
use jiff::Timestamp;
use nazo_crypto::ed25519::VerifyingKey;
use nazo_operator_protocol::PresentedControlOperation;
use nazo_persistence::{AdmittedController, ControllerRegistryPort};

/// Stage 1: bounded presentation with immutable payload/canonical bytes.
/// Signature authority is established only by consuming `verify` after admission.
pub(super) fn present(compact: &str) -> anyhow::Result<PresentedControlOperation<'_>> {
    PresentedControlOperation::parse(compact).context("control operation presentation is invalid")
}

/// A controller key the registry admits right now (stage 2 + 4 output).
pub(super) struct AdmittedControllerIdentity {
    pub(super) controller_id: String,
    pub(super) kid: String,
    pub(super) verifying_key: VerifyingKey,
}

/// Typed admission failures.  Transport failures are infrastructure faults;
/// they never classify an operation outcome.
#[derive(Debug)]
pub(super) enum AdmissionError {
    Unauthorized,
    Transport(anyhow::Error),
}

/// Stage 2+4: resolve and admit the presenting controller key by deployment.
pub(super) async fn admit_controller(
    repository: &dyn ControllerRegistryPort,
    deployment_id: &str,
    kid: &str,
    now: Timestamp,
    allow_renewal: bool,
) -> Result<AdmittedControllerIdentity, AdmissionError> {
    let admitted = repository
        .admitted_controller_by_kid(deployment_id, kid, now)
        .await
        .map_err(|error| {
            AdmissionError::Transport(
                anyhow::Error::new(error).context("controller registry admission lookup failed"),
            )
        })?;
    if let Some(admitted) = admitted {
        return decode_admitted_identity(admitted).map_err(AdmissionError::Transport);
    }
    // Only the signed successor proposal on the local operator channel can
    // recover an expired key. Revoked and superseded keys never qualify.
    if allow_renewal {
        let slots = repository
            .list_slots(deployment_id)
            .await
            .map_err(|error| AdmissionError::Transport(anyhow::Error::new(error)))?;
        if let Some(slot) = slots.into_iter().find(|slot| {
            slot.kid == kid
                && slot.status == nazo_persistence::control_plane::ControllerSlotStatus::Active
        }) {
            return decode_admitted_identity(AdmittedController {
                controller_id: slot.controller_id,
                kid: slot.kid,
                public_key: slot.public_key,
                expires_at: slot.expires_at,
            })
            .map_err(AdmissionError::Transport);
        }
    }
    Err(AdmissionError::Unauthorized)
}

fn decode_admitted_identity(
    admitted: AdmittedController,
) -> anyhow::Result<AdmittedControllerIdentity> {
    let bytes: [u8; 32] =
        admitted.public_key.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("controller registry holds an invalid public key length")
        })?;
    let verifying_key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("controller registry holds an invalid public key"))?;
    Ok(AdmittedControllerIdentity {
        controller_id: admitted.controller_id,
        kid: admitted.kid,
        verifying_key,
    })
}
