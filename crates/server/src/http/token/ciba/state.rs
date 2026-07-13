//! CIBA request persistence model and deterministic state transitions.

pub(super) use nazo_auth::{CibaRequestState, CibaStatus};
pub(super) use nazo_valkey::AtomicResult as CibaAtomicResult;
use nazo_valkey::{CibaStore, ValkeyConnection};
use std::fmt;
use uuid::Uuid;

pub(super) const CIBA_TRANSITION_MAX_ATTEMPTS: usize = 4;
const CIBA_EXPIRED_STATE_RETENTION_SECONDS: i64 = 120;
const CIBA_SLOW_DOWN_INCREMENT_SECONDS: u64 = 5;

#[derive(Clone, Debug)]
pub(super) struct StoredCibaRequest {
    inner: nazo_valkey::StoredCibaRequest,
    pub(super) state: CibaRequestState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CibaPollTransition {
    AuthorizationPending(CibaRequestState),
    SlowDown(CibaRequestState),
    Approved,
    Denied,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CibaDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CibaDecisionEvaluation {
    Commit(CibaRequestState),
    UserMismatch,
    AlreadyHandled,
    Expired,
}

#[derive(Debug)]
pub(super) enum CibaStateError {
    Atomic(nazo_valkey::Error),
    Malformed(String),
    Serialization(serde_json::Error),
}

#[derive(Debug)]
pub(super) enum CibaCreateFailure {
    DeadlineElapsed,
    Storage(CibaStateError),
    CollisionLimit,
}

impl fmt::Display for CibaCreateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineElapsed => formatter.write_str("CIBA creation deadline elapsed"),
            Self::Storage(error) => write!(formatter, "CIBA creation storage failed: {error}"),
            Self::CollisionLimit => formatter.write_str("CIBA auth_req_id collision limit reached"),
        }
    }
}

impl std::error::Error for CibaCreateFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::DeadlineElapsed | Self::CollisionLimit => None,
        }
    }
}

impl fmt::Display for CibaStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Atomic(error) => write!(formatter, "CIBA state command failed: {error}"),
            Self::Malformed(reason) => write!(formatter, "CIBA state is malformed: {reason}"),
            Self::Serialization(error) => {
                write!(formatter, "CIBA state serialization failed: {error}")
            }
        }
    }
}

impl std::error::Error for CibaStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Atomic(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::Malformed(_) => None,
        }
    }
}

impl From<nazo_valkey::Error> for CibaStateError {
    fn from(error: nazo_valkey::Error) -> Self {
        Self::Atomic(error)
    }
}

impl From<serde_json::Error> for CibaStateError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

pub(super) fn ciba_retention_deadline(expires_at: i64) -> i64 {
    expires_at.saturating_add(CIBA_EXPIRED_STATE_RETENTION_SECONDS)
}

#[cfg(test)]
pub(super) fn ciba_request_key(auth_req_id: &str) -> String {
    format!("oauth:ciba:{}", crate::support::blake3_hex(auth_req_id))
}

pub(super) fn evaluate_ciba_poll(state: &CibaRequestState, now: i64) -> CibaPollTransition {
    if now >= state.expires_at {
        return CibaPollTransition::Expired;
    }
    match state.status {
        CibaStatus::Approved => CibaPollTransition::Approved,
        CibaStatus::Denied => CibaPollTransition::Denied,
        CibaStatus::Pending => {
            let too_early = state.last_poll_at.is_some_and(|last_poll_at| {
                let interval = i64::try_from(state.interval_seconds).unwrap_or(i64::MAX);
                now.saturating_sub(last_poll_at) < interval
            });
            let mut next = state.clone();
            next.last_poll_at = Some(now);
            if too_early {
                next.interval_seconds = next
                    .interval_seconds
                    .saturating_add(CIBA_SLOW_DOWN_INCREMENT_SECONDS);
                CibaPollTransition::SlowDown(next)
            } else {
                CibaPollTransition::AuthorizationPending(next)
            }
        }
    }
}

pub(super) fn evaluate_ciba_decision(
    state: &CibaRequestState,
    expected_user_id: Option<Uuid>,
    decision: CibaDecision,
    now: i64,
) -> CibaDecisionEvaluation {
    if expected_user_id.is_some_and(|user_id| user_id != state.user_id) {
        return CibaDecisionEvaluation::UserMismatch;
    }
    if state.status != CibaStatus::Pending {
        return CibaDecisionEvaluation::AlreadyHandled;
    }
    if now >= state.expires_at {
        return CibaDecisionEvaluation::Expired;
    }
    let mut next = state.clone();
    next.status = match decision {
        CibaDecision::Approve => CibaStatus::Approved,
        CibaDecision::Deny => CibaStatus::Denied,
    };
    CibaDecisionEvaluation::Commit(next)
}

pub(super) async fn load_ciba_request_state(
    valkey: &ValkeyConnection,
    auth_req_id: &str,
) -> Result<Option<StoredCibaRequest>, CibaStateError> {
    let stored = CibaStore::new(valkey)
        .load(auth_req_id)
        .await
        .map_err(|error| {
            if error.kind() == nazo_valkey::ErrorKind::Protocol {
                CibaStateError::Malformed(error.to_string())
            } else {
                CibaStateError::Atomic(error)
            }
        })?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let state = stored.value().clone();
    if state.expires_at <= 0 {
        return Err(CibaStateError::Malformed(
            "expires_at must be a positive Unix timestamp".to_owned(),
        ));
    }
    if state.retention_expires_at < state.expires_at {
        return Err(CibaStateError::Malformed(
            "retention deadline precedes protocol expiry".to_owned(),
        ));
    }

    Ok(Some(StoredCibaRequest {
        inner: stored,
        state,
    }))
}

pub(super) async fn create_ciba_request_state(
    valkey: &ValkeyConnection,
    auth_req_id: &str,
    state: &CibaRequestState,
) -> Result<CibaAtomicResult, CibaStateError> {
    Ok(CibaStore::new(valkey).create(auth_req_id, state).await?)
}

pub(super) async fn create_unique_ciba_request<F>(
    valkey: &ValkeyConnection,
    state: &CibaRequestState,
    mut generate_id: F,
) -> Result<String, CibaCreateFailure>
where
    F: FnMut() -> String,
{
    for _ in 0..CIBA_TRANSITION_MAX_ATTEMPTS {
        let auth_req_id = generate_id();
        match create_ciba_request_state(valkey, &auth_req_id, state).await {
            Ok(CibaAtomicResult::Applied) => return Ok(auth_req_id),
            Ok(CibaAtomicResult::Conflict) => continue,
            Ok(CibaAtomicResult::DeadlineElapsed) => {
                return Err(CibaCreateFailure::DeadlineElapsed);
            }
            Err(error) => return Err(CibaCreateFailure::Storage(error)),
        }
    }
    Err(CibaCreateFailure::CollisionLimit)
}

pub(super) async fn replace_ciba_request_state(
    valkey: &ValkeyConnection,
    auth_req_id: &str,
    expected: &StoredCibaRequest,
    state: &CibaRequestState,
) -> Result<CibaAtomicResult, CibaStateError> {
    Ok(CibaStore::new(valkey)
        .replace(auth_req_id, &expected.inner, state)
        .await?)
}

pub(super) async fn delete_ciba_request_state(
    valkey: &ValkeyConnection,
    auth_req_id: &str,
    expected: &StoredCibaRequest,
) -> Result<CibaAtomicResult, CibaStateError> {
    Ok(CibaStore::new(valkey)
        .delete(auth_req_id, &expected.inner)
        .await?)
}
