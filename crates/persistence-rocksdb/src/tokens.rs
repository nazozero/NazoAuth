//! Token authority, single-use fences and refresh-family transitions.
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken, PreparedTokenSubject,
    RefreshContract, RefreshToken, RefreshTokenCommit, RefreshTokenSnapshot, SingleUseRedemption,
    TokenFuture, TokenIssuanceMode, TokenPortError, TokenPrincipalState, TokenRepositoryPort,
    TokenRevocation, UserinfoSnapshot,
};
use nazo_identity::{Principal, SubjectClaims, ports::RepositoryError};
use nazo_persistence::SecurityAuditEvent;
use nazo_resource_server::{
    AccessTokenRevocationLookup, MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS,
    ProtectedResourceDependencyError, ResourceServerPortFuture, RevocationLookupKey,
};
use rocksdb::{Direction, IteratorMode, SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    RocksDb,
    audit::append_in_tx,
    clients::{CLIENT_PRINCIPAL, CLIENT_PUBLIC_ID, ClientPrincipal},
    db::{decode, delete_expiring, key, map_error, put, put_expiring, read_snapshot, read_tx},
    users::{USER_CLAIMS, USER_PRINCIPAL},
};

pub(crate) const FAMILY: u8 = 0x50;
const CONTRACT: u8 = 0x51;
const CURRENT: u8 = 0x52;
pub(crate) const SPENT: u8 = 0x53;
const SCOPE: u8 = 0x54;
const BY_CLIENT: u8 = 0x55;
const BY_USER: u8 = 0x56;
pub(crate) const RECEIPT: u8 = 0x57;
pub(crate) const REVOCATION: u8 = 0x59;
const SUBJECT: u8 = 0x5a;
pub(crate) const SPENT_ORDER: u8 = 0x5b;
const RETRY_SECONDS: i64 = 60;

type Tx<'a> = Transaction<'a, TransactionDB>;
type Snapshot<'a> = SnapshotWithThreadMode<'a, TransactionDB>;

#[derive(Deserialize, Serialize)]
struct Family {
    client_id: Uuid,
    user_id: Option<Uuid>,
    contract_key: [u8; 32],
    member_id: Uuid,
    digest: [u8; 32],
    audience: Vec<String>,
    issued_at: Timestamp,
    expires_at: Timestamp,
    id_token_sid: Option<String>,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
    client_attestation_jkt: Option<String>,
    revoked_at: Option<Timestamp>,
    reuse_detected_at: Option<Timestamp>,
}

impl Family {
    fn active(&self, now: Timestamp) -> bool {
        self.revoked_at.is_none() && self.reuse_detected_at.is_none() && self.expires_at > now
    }

    fn current(self, tenant_id: Uuid, family_id: Uuid, contract: RefreshContract) -> RefreshToken {
        RefreshToken {
            id_token_sid: self.id_token_sid,
            id: self.member_id,
            token_blake3: self.digest,
            tenant_id,
            token_family_id: family_id,
            client_id: self.client_id,
            user_id: self.user_id,
            contract_key: self.contract_key,
            contract,
            audience: self.audience,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at.or(self.reuse_detected_at),
            dpop_jkt: self.dpop_jkt,
            mtls_x5t_s256: self.mtls_x5t_s256,
            client_attestation_jkt: self.client_attestation_jkt,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct Spent {
    family_id: Uuid,
    member_id: Uuid,
    successor_member_id: Uuid,
    spent_at: Timestamp,
    expires_at: Timestamp,
}

#[derive(Deserialize, Serialize)]
struct Receipt {
    access_token_jti: String,
    access_token_expires_at: Timestamp,
    refresh_token_family_id: Option<Uuid>,
    holder: Option<serde_json::Value>,
    retain_until: Timestamp,
}

#[derive(Deserialize, Serialize)]
struct Revocation {
    client_id: Uuid,
    expires_at: Timestamp,
}

fn invalid(message: &'static str) -> RepositoryError {
    RepositoryError::Consistency(message.to_owned())
}

fn token_error(error: RepositoryError) -> TokenPortError {
    match error {
        RepositoryError::Unavailable => TokenPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => TokenPortError::Conflict,
        RepositoryError::Consistency(_) => TokenPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => TokenPortError::Unexpected,
    }
}

fn joined(first: &Uuid, tail: &[u8]) -> Vec<u8> {
    let mut id = Vec::with_capacity(16 + tail.len());
    id.extend_from_slice(first.as_bytes());
    id.extend_from_slice(tail);
    id
}

fn scope_key(tenant: Uuid, client: Uuid, user: Option<Uuid>) -> Vec<u8> {
    key(
        SCOPE,
        tenant,
        &joined(&client, user.unwrap_or(Uuid::nil()).as_bytes()),
    )
}

fn spent_order_key(tenant: Uuid, spent: &Spent) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(40);
    suffix.extend_from_slice(spent.family_id.as_bytes());
    suffix.extend_from_slice(&((spent.spent_at.as_microsecond() as u64) ^ (1 << 63)).to_be_bytes());
    suffix.extend_from_slice(spent.member_id.as_bytes());
    key(SPENT_ORDER, tenant, &suffix)
}

fn retention(expiry: Timestamp) -> Result<Timestamp, RepositoryError> {
    expiry
        .checked_add(SignedDuration::from_secs(
            MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS,
        ))
        .map_err(|_| invalid("token retention deadline is not representable"))
}

fn validate_input(input: &CommitTokenIssuance) -> Result<Timestamp, RepositoryError> {
    if input.issuance_id.is_nil()
        || input.tenant_id.is_nil()
        || input.client_id.is_nil()
        || input.access_token_jti.trim().is_empty()
        || input.subject.is_empty()
        || input.subject.chars().count() > 255
        || input.principal_state.client_epoch < 0
        || input
            .principal_state
            .user_epoch
            .is_some_and(|epoch| epoch < 0)
        || input.principal_state.user_epoch.is_some() != input.user_id.is_some()
    {
        return Err(invalid("token issuance commit input is malformed"));
    }
    match &input.mode {
        TokenIssuanceMode::SingleUse { grant_key, .. }
            if grant_key.trim().is_empty() || grant_key.starts_with("authorization_code:") =>
        {
            return Err(invalid("single-use grant identity is malformed"));
        }
        TokenIssuanceMode::AuthorizationCode { code_identity, .. }
            if !code_identity.starts_with("authorization_code:v2:") =>
        {
            return Err(invalid("authorization code identity is malformed"));
        }
        _ => {}
    }
    let authorization_id = input
        .refresh_token
        .as_ref()
        .map(RefreshTokenCommit::family_id)
        .unwrap_or(input.issuance_id);
    if input
        .authorization_id
        .is_some_and(|id| id != authorization_id)
    {
        return Err(invalid(
            "authorization reference does not match issuance source",
        ));
    }
    if let Some(refresh) = input.refresh_token.as_ref() {
        let (tenant, client, user) = match refresh {
            RefreshTokenCommit::IssueNew { token, .. } => {
                (token.tenant_id, token.client_id, token.user_id)
            }
            RefreshTokenCommit::UseExisting { authority, .. } => {
                if input.mode != TokenIssuanceMode::Fresh {
                    return Err(invalid("refresh cannot redeem a single-use grant"));
                }
                (authority.tenant_id, authority.client_id, authority.user_id)
            }
        };
        if (tenant, client, user) != (input.tenant_id, input.client_id, input.user_id)
            || refresh.contract().subject != input.subject
        {
            return Err(invalid("refresh owner does not match issuance"));
        }
        validate_refresh(refresh)?;
    }
    if let Some(source) = &input.native_sso_source
        && (source.tenant_id != input.tenant_id
            || Some(source.user_id) != input.user_id
            || source.family_id.is_nil()
            || source.source_client_id.is_empty()
            || input.mode != TokenIssuanceMode::Fresh
            || !matches!(
                input.refresh_token,
                Some(RefreshTokenCommit::IssueNew { .. })
            ))
    {
        return Err(invalid("Native SSO source does not match issuance"));
    }
    Timestamp::new(input.access_token_expires_at, 0)
        .map_err(|_| invalid("access-token expiry is not representable"))
}

fn validate_refresh(refresh: &RefreshTokenCommit) -> Result<(), RepositoryError> {
    let contract = refresh.contract();
    let audiences_valid =
        |values: &[String]| !values.is_empty() && values.iter().all(|v| !v.trim().is_empty());
    if !contract.authentication_context.is_well_formed()
        || contract.subject.trim().is_empty()
        || !audiences_valid(&contract.audiences)
    {
        return Err(invalid("refresh authentication contract is malformed"));
    }
    match refresh {
        RefreshTokenCommit::IssueNew { token, contract } => {
            if contract.authentication_context.version
                != nazo_auth::RefreshTokenAuthenticationContext::CURRENT_VERSION
                || token.rotated_from_id.is_some()
                || token.lost_response_retry.is_some()
                || token.audiences != contract.audiences
            {
                return Err(invalid("new refresh family does not preserve its grant"));
            }
        }
        RefreshTokenCommit::UseExisting {
            authority,
            rotation,
        } => {
            if authority.family_id.is_nil()
                || authority.member_id.is_nil()
                || authority
                    .id_token_sid
                    .as_deref()
                    .is_some_and(|s| s.trim().is_empty())
                || !audiences_valid(&authority.current_audiences)
                || !nazo_auth::is_subset(&authority.current_audiences, &contract.audiences)
            {
                return Err(invalid("refresh source authority is malformed"));
            }
            if let Some(token) = rotation
                && (token.family_id != authority.family_id
                    || token.tenant_id != authority.tenant_id
                    || token.client_id != authority.client_id
                    || token.user_id != authority.user_id
                    || token.rotated_from_id != Some(authority.member_id)
                    || !nazo_auth::is_subset(&token.audiences, &authority.current_audiences)
                    || token.dpop_jkt != authority.dpop_jkt
                    || token.mtls_x5t_s256 != authority.mtls_x5t_s256
                    || token.client_attestation_jkt != authority.client_attestation_jkt)
            {
                return Err(invalid("refresh replacement does not preserve its source"));
            }
        }
    }
    if let Some(token) = refresh.token()
        && (token.family_id.is_nil()
            || token.member_id.is_nil()
            || token.raw_token.is_empty()
            || token
                .id_token_sid
                .as_deref()
                .is_some_and(|s| s.trim().is_empty())
            || !audiences_valid(&token.audiences)
            || contract.authentication_context.auth_time > token.issued_at.as_second()
            || token.expires_at <= token.issued_at)
    {
        return Err(invalid("refresh replacement is malformed"));
    }
    Ok(())
}

fn issuance_event(input: &CommitTokenIssuance) -> SecurityAuditEvent {
    let refresh = input.refresh_token.as_ref();
    SecurityAuditEvent {
        event_id: input.issuance_id,
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: serde_json::json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
            "tenant_id": input.tenant_id, "issuance_id": input.issuance_id,
            "event_category": "token_lifecycle", "user_id": input.user_id,
            "client_id": input.audit_fields.client_id, "subject_hash": input.audit_fields.subject_hash,
            "scope": input.audit_fields.scope, "audience": input.audit_fields.audience,
            "access_token_jti": input.access_token_jti,
            "refresh_token_family_id": refresh.map(RefreshTokenCommit::family_id),
            "rotated_from_id": refresh.and_then(RefreshTokenCommit::token).and_then(|token| token.rotated_from_id),
        }),
        occurred_at: Timestamp::now(),
    }
}

fn reuse_event(input: &CommitTokenIssuance, token: &NewRefreshToken) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "refresh_reuse_detected".to_owned(),
        event_category: "token_replay".to_owned(),
        payload: serde_json::json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
            "tenant_id": input.tenant_id, "issuance_id": input.issuance_id,
            "event_category": "token_replay", "client_id": input.audit_fields.client_id,
            "token_family_id": token.family_id, "rotated_from_id": token.rotated_from_id,
            "source_token_id": token.lost_response_retry.map(|retry| retry.original_id),
        }),
        occurred_at: Timestamp::now(),
    }
}

fn compromise(
    tx: &Tx<'_>,
    tenant: Uuid,
    id: Uuid,
    family: &mut Family,
) -> Result<(), RepositoryError> {
    let now = Timestamp::now();
    family.revoked_at.get_or_insert(now);
    family.reuse_detected_at.get_or_insert(now);
    put_expiring(
        tx,
        &key(FAMILY, tenant, id.as_bytes()),
        family,
        family.expires_at,
    )
}

fn native_source(
    tx: &Tx<'_>,
    source: &nazo_auth::NativeSsoSourceFence,
) -> Result<Option<Timestamp>, RepositoryError> {
    let Some(client_id) = tx
        .get_pinned(key(
            CLIENT_PUBLIC_ID,
            source.tenant_id,
            source.source_client_id.as_bytes(),
        ))
        .map_err(map_error)?
        .map(|raw| decode::<Uuid>(&raw))
        .transpose()?
    else {
        return Ok(None);
    };
    let client: Option<ClientPrincipal> = read_tx(
        tx,
        &key(CLIENT_PRINCIPAL, source.tenant_id, client_id.as_bytes()),
        false,
    )?;
    if !client.is_some_and(|client| client.active) {
        return Ok(None);
    }
    let family: Option<Family> = read_tx(
        tx,
        &key(FAMILY, source.tenant_id, source.family_id.as_bytes()),
        false,
    )?;
    let Some(family) = family else {
        return Ok(None);
    };
    let now = Timestamp::now();
    Ok((family.client_id == client_id
        && family.user_id == Some(source.user_id)
        && family.active(now)
        && source.device_secret_expires_at > now)
        .then_some(family.expires_at.min(source.device_secret_expires_at)))
}

fn persist_refresh(
    tx: &Tx<'_>,
    input: &CommitTokenIssuance,
    client_type: &str,
) -> Result<(CommitTokenIssuanceResult, Option<Timestamp>), RepositoryError> {
    let Some(refresh) = &input.refresh_token else {
        return Ok((CommitTokenIssuanceResult::Committed, None));
    };
    let tenant = input.tenant_id;
    // Capacity mutations and rotations use the same scope before family order.
    // Unrelated principals/families never share this lock.
    let scope = scope_key(tenant, input.client_id, input.user_id);
    let scope_expiry = if refresh.token().is_some() {
        tx.get_pinned_for_update(&scope, true)
            .map_err(map_error)?
            .map(|raw| crate::db::expiration(&raw))
            .transpose()?
    } else {
        None
    };
    let native_deadline = if let Some(source) = &input.native_sso_source {
        let Some(deadline) = native_source(tx, source)? else {
            return Ok((CommitTokenIssuanceResult::RefreshGrantUnavailable, None));
        };
        Some(deadline)
    } else {
        None
    };
    let family_id = refresh.family_id();
    let family_key = key(FAMILY, tenant, family_id.as_bytes());
    let family: Option<Family> = read_tx(tx, &family_key, refresh.token().is_some())?;
    let now = Timestamp::now();
    match refresh {
        RefreshTokenCommit::IssueNew { token, contract } => {
            if let Some(mut family) = family {
                compromise(tx, tenant, family_id, &mut family)?;
                return Ok((CommitTokenIssuanceResult::RotationConflict, native_deadline));
            }
            let mut scope_ids: Vec<Uuid> = read_tx(tx, &scope, true)?.unwrap_or_default();
            if token.user_id.is_some() {
                let mut active = Vec::with_capacity(scope_ids.len());
                let mut scope_deadline = token.expires_at;
                for id in scope_ids.drain(..) {
                    let candidate: Option<Family> = tx
                        .get_pinned(key(FAMILY, tenant, id.as_bytes()))
                        .map_err(map_error)?
                        .map(|raw| decode(&raw))
                        .transpose()?;
                    if let Some(candidate) = candidate
                        && candidate.active(now)
                    {
                        scope_deadline = scope_deadline.max(candidate.expires_at);
                        active.push((candidate.issued_at, id));
                    }
                }
                active.sort_unstable();
                while active.len() >= nazo_auth::MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE as usize {
                    let (_, victim_id) = active.remove(0);
                    let victim_key = key(FAMILY, tenant, victim_id.as_bytes());
                    if let Some(mut victim) = read_tx::<Family>(tx, &victim_key, true)?
                        && victim.active(Timestamp::now())
                    {
                        victim.revoked_at = Some(Timestamp::now());
                        put_expiring(tx, &victim_key, &victim, victim.expires_at)?;
                        append_in_tx(
                            tx,
                            &SecurityAuditEvent {
                                event_id: Uuid::now_v7(),
                                event_type: "refresh_family_capacity_retired".into(),
                                event_category: "token_lifecycle".into(),
                                payload: serde_json::json!({
                                    "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                                    "tenant_id": tenant, "issuance_id": input.issuance_id,
                                    "event_category": "token_lifecycle", "token_family_id": victim_id,
                                    "client_id": input.client_id, "user_id": input.user_id,
                                    "reason": "active_family_cap",
                                    "max_active_families": nazo_auth::MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE,
                                }),
                                occurred_at: Timestamp::now(),
                            },
                        )?;
                    }
                }
                scope_ids.extend(active.into_iter().map(|(_, id)| id));
                scope_ids.push(family_id);
                put_expiring(tx, &scope, &scope_ids, scope_deadline)?;
            }
            let contract_bytes = crate::db::encode(contract)?;
            let digest = *blake3::hash(token.raw_token.as_bytes()).as_bytes();
            if tx
                .get_pinned_for_update(key(CURRENT, tenant, &digest), true)
                .map_err(map_error)?
                .is_some()
                || tx
                    .get_pinned(key(SPENT, tenant, &digest))
                    .map_err(map_error)?
                    .is_some()
            {
                return Err(RepositoryError::Conflict);
            }
            let family = Family {
                client_id: token.client_id,
                user_id: token.user_id,
                contract_key: *blake3::hash(&contract_bytes[8..]).as_bytes(),
                member_id: token.member_id,
                digest,
                audience: token.audiences.clone(),
                issued_at: token.issued_at,
                expires_at: token.expires_at,
                id_token_sid: token.id_token_sid.clone(),
                dpop_jkt: token.dpop_jkt.clone(),
                mtls_x5t_s256: token.mtls_x5t_s256.clone(),
                client_attestation_jkt: token.client_attestation_jkt.clone(),
                revoked_at: None,
                reuse_detected_at: None,
            };
            tx.put(key(CONTRACT, tenant, family_id.as_bytes()), contract_bytes)
                .map_err(map_error)?;
            put_expiring(tx, &family_key, &family, family.expires_at)?;
            put(tx, &key(CURRENT, tenant, &digest), &family_id)?;
            put(
                tx,
                &key(
                    BY_CLIENT,
                    tenant,
                    &joined(&token.client_id, family_id.as_bytes()),
                ),
                &(),
            )?;
            if let Some(user) = token.user_id {
                put(
                    tx,
                    &key(BY_USER, tenant, &joined(&user, family_id.as_bytes())),
                    &(),
                )?;
            }
        }
        RefreshTokenCommit::UseExisting {
            authority,
            rotation,
        } => {
            let Some(mut family) = family else {
                return Ok((
                    CommitTokenIssuanceResult::RefreshGrantUnavailable,
                    native_deadline,
                ));
            };
            if !family.active(now) {
                return Ok((
                    CommitTokenIssuanceResult::RefreshGrantUnavailable,
                    native_deadline,
                ));
            }
            let contract: RefreshContract = tx
                .get_pinned(key(CONTRACT, tenant, family_id.as_bytes()))
                .map_err(map_error)?
                .map(|raw| decode(&raw))
                .transpose()?
                .ok_or_else(|| invalid("refresh family has no contract"))?;
            let matches = family.member_id == authority.member_id
                && family.digest == authority.token_blake3
                && family.client_id == authority.client_id
                && family.user_id == authority.user_id
                && family.contract_key == authority.contract_key
                && contract == authority.contract
                && family.audience == authority.current_audiences
                && family.expires_at == authority.expires_at
                && family.id_token_sid == authority.id_token_sid
                && family.dpop_jkt == authority.dpop_jkt
                && family.mtls_x5t_s256 == authority.mtls_x5t_s256
                && family.client_attestation_jkt == authority.client_attestation_jkt;
            if !matches {
                if rotation.is_some() {
                    compromise(tx, tenant, family_id, &mut family)?;
                    return Ok((CommitTokenIssuanceResult::RotationConflict, native_deadline));
                }
                return Ok((
                    CommitTokenIssuanceResult::RefreshGrantUnavailable,
                    native_deadline,
                ));
            }
            let Some(token) = rotation else {
                return Ok((CommitTokenIssuanceResult::Committed, native_deadline));
            };
            if let Some(retry) = token.lost_response_retry {
                let edge: Option<Spent> = tx
                    .get_pinned(key(SPENT, tenant, &retry.original_blake3))
                    .map_err(map_error)?
                    .map(|raw| decode(&raw))
                    .transpose()?;
                if !edge.is_some_and(|edge| {
                    let elapsed = retry.retry_started_at.duration_since(edge.spent_at);
                    edge.family_id == family_id
                        && edge.member_id == retry.original_id
                        && edge.successor_member_id == authority.member_id
                        && elapsed >= SignedDuration::ZERO
                        && elapsed <= SignedDuration::from_secs(RETRY_SECONDS)
                }) {
                    compromise(tx, tenant, family_id, &mut family)?;
                    return Ok((CommitTokenIssuanceResult::RotationConflict, native_deadline));
                }
            }
            let digest = *blake3::hash(token.raw_token.as_bytes()).as_bytes();
            if tx
                .get_pinned_for_update(key(CURRENT, tenant, &digest), true)
                .map_err(map_error)?
                .is_some()
                || tx
                    .get_pinned(key(SPENT, tenant, &digest))
                    .map_err(map_error)?
                    .is_some()
            {
                return Err(RepositoryError::Conflict);
            }
            let spent = Spent {
                family_id,
                member_id: family.member_id,
                successor_member_id: token.member_id,
                spent_at: now,
                expires_at: family.expires_at,
            };
            put_expiring(
                tx,
                &key(SPENT, tenant, &family.digest),
                &spent,
                spent.expires_at,
            )?;
            put_expiring(
                tx,
                &spent_order_key(tenant, &spent),
                &family.digest,
                spent.expires_at,
            )?;
            tx.delete(key(CURRENT, tenant, &family.digest))
                .map_err(map_error)?;
            put(tx, &key(CURRENT, tenant, &digest), &family_id)?;
            if let Some(limit) = nazo_auth::refresh_spent_proof_limit(
                client_type,
                family.dpop_jkt.as_deref(),
                family.mtls_x5t_s256.as_deref(),
            ) {
                trim_spent(tx, tenant, family_id, limit as usize)?;
            }
            family.member_id = token.member_id;
            family.digest = digest;
            family.audience.clone_from(&token.audiences);
            family.issued_at = token.issued_at;
            family.expires_at = token.expires_at;
            family.id_token_sid.clone_from(&token.id_token_sid);
            put_expiring(tx, &family_key, &family, family.expires_at)?;
            if family.user_id.is_some()
                && scope_expiry.is_none_or(|expiry| expiry < family.expires_at.as_microsecond())
            {
                let ids: Vec<Uuid> = read_tx(tx, &scope, true)?
                    .ok_or_else(|| invalid("refresh family has no scope index"))?;
                put_expiring(tx, &scope, &ids, family.expires_at)?;
            }
        }
    }
    Ok((CommitTokenIssuanceResult::Committed, native_deadline))
}

fn trim_spent(
    tx: &Tx<'_>,
    tenant: Uuid,
    family: Uuid,
    limit: usize,
) -> Result<(), RepositoryError> {
    let prefix = key(SPENT_ORDER, tenant, family.as_bytes());
    let mut end = prefix.clone();
    end.extend_from_slice(&[u8::MAX; 24]);
    let mut excess = Vec::new();
    let mut count = 0;
    for item in tx.iterator(IteratorMode::From(&end, Direction::Reverse)) {
        let (order_key, raw) = item.map_err(map_error)?;
        if !order_key.starts_with(&prefix) {
            break;
        }
        count += 1;
        if count > limit {
            excess.push((order_key, decode::<[u8; 32]>(&raw)?));
        }
    }
    for (order_key, digest) in excess {
        let spent_key = key(SPENT, tenant, &digest);
        if let Some(spent) = read_tx::<Spent>(tx, &spent_key, true)? {
            delete_expiring(tx, &spent_key, spent.expires_at)?;
            delete_expiring(tx, &order_key, spent.expires_at)?;
        }
    }
    Ok(())
}

fn commit(
    store: &RocksDb,
    input: CommitTokenIssuance,
) -> Result<CommitTokenIssuanceResult, RepositoryError> {
    let expiry = validate_input(&input)?;
    let tx = store.transaction();
    let client: Option<ClientPrincipal> = read_tx(
        &tx,
        &key(
            CLIENT_PRINCIPAL,
            input.tenant_id,
            input.client_id.as_bytes(),
        ),
        false,
    )?;
    let Some(client) = client.filter(|c| c.active && c.epoch == input.principal_state.client_epoch)
    else {
        return Ok(CommitTokenIssuanceResult::ClientInactive);
    };
    if let Some(user) = input.user_id {
        let principal: Option<Principal> = read_tx(
            &tx,
            &key(USER_PRINCIPAL, input.tenant_id, user.as_bytes()),
            false,
        )?;
        if !principal.is_some_and(|p| {
            p.active && Some(p.authorization_epoch) == input.principal_state.user_epoch
        }) {
            return Ok(CommitTokenIssuanceResult::SubjectInactive);
        }
    }
    let single_use = match &input.mode {
        TokenIssuanceMode::Fresh => None,
        TokenIssuanceMode::SingleUse {
            grant_key,
            grant_expires_at,
        }
        | TokenIssuanceMode::AuthorizationCode {
            code_identity: grant_key,
            grant_expires_at,
            ..
        } => {
            let receipt_key = key(
                RECEIPT,
                input.tenant_id,
                &joined(
                    &input.client_id,
                    blake3::hash(grant_key.as_bytes()).as_bytes(),
                ),
            );
            if tx
                .get_pinned_for_update(&receipt_key, true)
                .map_err(map_error)?
                .is_some()
            {
                return Ok(CommitTokenIssuanceResult::AlreadyUsed);
            }
            if *grant_expires_at <= Timestamp::now() {
                return Ok(CommitTokenIssuanceResult::GrantExpired);
            }
            Some((receipt_key, retention(expiry)?.max(*grant_expires_at)))
        }
    };
    let (refresh_result, native_deadline) = persist_refresh(&tx, &input, &client.client_type)?;
    match refresh_result {
        CommitTokenIssuanceResult::Committed => {}
        CommitTokenIssuanceResult::RotationConflict => {
            append_in_tx(
                &tx,
                &reuse_event(
                    &input,
                    input
                        .refresh_token
                        .as_ref()
                        .and_then(RefreshTokenCommit::token)
                        .ok_or_else(|| invalid("refresh compromise has no replacement"))?,
                ),
            )?;
            tx.commit().map_err(map_error)?;
            return Ok(CommitTokenIssuanceResult::RotationConflict);
        }
        result => return Ok(result),
    }
    if let Some(user) = input.user_id
        && input.subject != user.to_string()
    {
        let binding_key = key(SUBJECT, input.tenant_id, input.subject.as_bytes());
        // First binding takes the exclusive key directly; established owners
        // share the read lock, avoiding an absent-key lock-upgrade race.
        match read_tx::<Uuid>(&tx, &binding_key, !input.principal_state.subject_bound)? {
            Some(owner) if owner != user => return Err(invalid("subject ownership collision")),
            Some(_) => {}
            None if input.principal_state.subject_bound => {
                return Err(invalid("prepared subject binding is missing"));
            }
            None => put(&tx, &binding_key, &user)?,
        }
    }
    if let Some((receipt_key, retain_until)) = single_use {
        let holder = match &input.mode {
            TokenIssuanceMode::AuthorizationCode { holder, .. } => Some(
                serde_json::to_value(holder)
                    .map_err(|_| invalid("code holder cannot be encoded"))?,
            ),
            _ => None,
        };
        put_expiring(
            &tx,
            &receipt_key,
            &Receipt {
                access_token_jti: input.access_token_jti.clone(),
                access_token_expires_at: expiry,
                refresh_token_family_id: input
                    .refresh_token
                    .as_ref()
                    .map(RefreshTokenCommit::family_id),
                holder,
                retain_until,
            },
            retain_until,
        )?;
    }
    append_in_tx(&tx, &issuance_event(&input))?;
    let now = Timestamp::now();
    match &input.mode {
        TokenIssuanceMode::SingleUse {
            grant_expires_at, ..
        }
        | TokenIssuanceMode::AuthorizationCode {
            grant_expires_at, ..
        } if *grant_expires_at <= now => return Ok(CommitTokenIssuanceResult::GrantExpired),
        _ => {}
    }
    if native_deadline.is_some_and(|deadline| deadline <= now)
        || input
            .refresh_token
            .as_ref()
            .is_some_and(|refresh| match refresh {
                RefreshTokenCommit::IssueNew { token, .. } => token.expires_at <= now,
                RefreshTokenCommit::UseExisting {
                    authority,
                    rotation,
                } => {
                    authority.expires_at <= now
                        || rotation
                            .as_ref()
                            .is_some_and(|token| token.expires_at <= now)
                }
            })
    {
        return Ok(CommitTokenIssuanceResult::RefreshGrantUnavailable);
    }
    tx.commit().map_err(map_error)?;
    Ok(CommitTokenIssuanceResult::Committed)
}

fn prepared_subject(
    snapshot: &Snapshot<'_>,
    tenant: Uuid,
    user: Uuid,
    subject: &str,
) -> Result<Option<PreparedTokenSubject>, RepositoryError> {
    let principal: Option<Principal> =
        read_snapshot(snapshot, &key(USER_PRINCIPAL, tenant, user.as_bytes()))?;
    let Some(principal) = principal.filter(|p| p.active && p.authorization_epoch >= 0) else {
        return Ok(None);
    };
    let bound: Option<Uuid> = if subject == user.to_string() {
        None
    } else {
        read_snapshot(snapshot, &key(SUBJECT, tenant, subject.as_bytes()))?
    };
    if bound.is_some_and(|owner| owner != user) {
        return Err(invalid("subject ownership collision"));
    }
    let claims: SubjectClaims =
        read_snapshot(snapshot, &key(USER_CLAIMS, tenant, user.as_bytes()))?
            .ok_or_else(|| invalid("active subject has no claims"))?;
    Ok(Some(PreparedTokenSubject {
        tenant_id: tenant,
        claims,
        user_epoch: principal.authorization_epoch,
        token_subject: subject.to_owned(),
        subject_bound: bound.is_some(),
    }))
}

fn presentation(
    snapshot: &Snapshot<'_>,
    tenant: Uuid,
    digest: &[u8; 32],
    retry: Option<(Uuid, Timestamp)>,
    prepare: bool,
) -> Result<Option<RefreshTokenSnapshot>, RepositoryError> {
    let current: Option<Uuid> = read_snapshot(snapshot, &key(CURRENT, tenant, digest))?;
    let spent: Option<Spent> = if current.is_none() {
        read_snapshot(snapshot, &key(SPENT, tenant, digest))?
    } else {
        None
    };
    let Some(id) = current.or_else(|| spent.as_ref().map(|s| s.family_id)) else {
        return Ok(None);
    };
    let Some(family) = read_snapshot::<Family>(snapshot, &key(FAMILY, tenant, id.as_bytes()))?
    else {
        return Ok(None);
    };
    let contract: RefreshContract = read_snapshot(snapshot, &key(CONTRACT, tenant, id.as_bytes()))?
        .ok_or_else(|| invalid("refresh family has no contract"))?;
    let mut successor = None;
    let presented = if let Some(spent) = spent {
        if retry.is_some_and(|(client, now)| {
            let elapsed = now.duration_since(spent.spent_at);
            family.client_id == client
                && (family.dpop_jkt.is_some() || family.mtls_x5t_s256.is_some())
                && family.member_id == spent.successor_member_id
                && family.active(now)
                && elapsed >= SignedDuration::ZERO
                && elapsed <= SignedDuration::from_secs(RETRY_SECONDS)
        }) {
            // Only the eligible retry needs a second owned projection.
            let current_family: Family =
                read_snapshot(snapshot, &key(FAMILY, tenant, id.as_bytes()))?
                    .ok_or_else(|| invalid("refresh family disappeared within snapshot"))?;
            successor = Some(current_family.current(tenant, id, contract.clone()));
        }
        let mut token = family.current(tenant, id, contract);
        token.id = spent.member_id;
        token.token_blake3 = *digest;
        token.audience.clone_from(&token.contract.audiences);
        token.issued_at = spent.spent_at;
        token.expires_at = spent.expires_at;
        token.revoked_at = Some(spent.spent_at);
        token
    } else {
        if family.digest != *digest {
            return Err(invalid("refresh current index is inconsistent"));
        }
        family.current(tenant, id, contract)
    };
    let prepared_subject = if prepare {
        presented.user_id.and_then(|user| {
            prepared_subject(snapshot, tenant, user, &presented.contract.subject)
                .ok()
                .flatten()
        })
    } else {
        None
    };
    Ok(Some(RefreshTokenSnapshot {
        presented,
        successor: Ok(successor),
        prepared_subject,
    }))
}

struct Lookup {
    tenant: Uuid,
    jti: [u8; 32],
    client: String,
    subject: String,
    user_id: Option<String>,
    subject_type: Option<String>,
    client_epoch: Option<i64>,
    user_epoch: Option<i64>,
}

fn revoked(snapshot: &Snapshot<'_>, input: &Lookup) -> Result<bool, RepositoryError> {
    if read_snapshot::<Revocation>(snapshot, &key(REVOCATION, input.tenant, &input.jti))?.is_some()
    {
        return Ok(true);
    }
    let Some(client_epoch) = input.client_epoch else {
        return Ok(input.user_epoch.is_some());
    };
    if client_epoch < 0 || input.user_epoch.is_some_and(|e| e < 0) {
        return Ok(true);
    }
    let user_epoch = match (input.subject_type.as_deref(), input.user_epoch) {
        (Some("client"), None) if input.user_id.is_none() => None,
        (Some("user"), Some(epoch)) => Some(epoch),
        _ => return Ok(true),
    };
    let client: Option<Uuid> = read_snapshot(
        snapshot,
        &key(CLIENT_PUBLIC_ID, input.tenant, input.client.as_bytes()),
    )?;
    let Some(client) = client else {
        return Ok(true);
    };
    if !read_snapshot::<ClientPrincipal>(
        snapshot,
        &key(CLIENT_PRINCIPAL, input.tenant, client.as_bytes()),
    )?
    .is_some_and(|c| c.active && c.epoch == client_epoch)
    {
        return Ok(true);
    }
    if let Some(epoch) = user_epoch {
        let user = match input.user_id.as_deref() {
            Some(id) => match Uuid::parse_str(id) {
                Ok(id) => Some(id),
                Err(_) => return Ok(true),
            },
            None => read_snapshot(
                snapshot,
                &key(SUBJECT, input.tenant, input.subject.as_bytes()),
            )?,
        };
        let Some(user) = user else { return Ok(true) };
        if !read_snapshot::<Principal>(
            snapshot,
            &key(USER_PRINCIPAL, input.tenant, user.as_bytes()),
        )?
        .is_some_and(|p| p.active && p.authorization_epoch == epoch)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn revoke_jti(
    tx: &Tx<'_>,
    tenant: Uuid,
    client: Uuid,
    digest: &[u8; 32],
    expiry: Timestamp,
) -> Result<(), RepositoryError> {
    let record_key = key(REVOCATION, tenant, digest);
    let deadline = retention(expiry)?;
    if let Some(existing) = read_tx::<Revocation>(tx, &record_key, true)? {
        if existing.client_id != client {
            return Err(invalid("conflicting token revocation ownership"));
        }
        if existing.expires_at >= deadline {
            return Ok(());
        }
    }
    put_expiring(
        tx,
        &record_key,
        &Revocation {
            client_id: client,
            expires_at: deadline,
        },
        deadline,
    )
}

fn revoke_family(
    tx: &Tx<'_>,
    tenant: Uuid,
    client: Uuid,
    id: Uuid,
) -> Result<usize, RepositoryError> {
    let record_key = key(FAMILY, tenant, id.as_bytes());
    let Some(mut family) = read_tx::<Family>(tx, &record_key, true)? else {
        return Ok(0);
    };
    if family.client_id != client || family.revoked_at.is_some() {
        return Ok(0);
    }
    family.revoked_at = Some(Timestamp::now());
    put_expiring(tx, &record_key, &family, family.expires_at)?;
    Ok(1)
}

/// Call after exclusively locking the principal whose authority is terminated.
/// Issuance shares that principal lock, so no newly created family can escape.
pub(crate) fn revoke_families(
    tx: &Tx<'_>,
    tenant: Uuid,
    client: Option<Uuid>,
    user: Option<Uuid>,
) -> Result<usize, RepositoryError> {
    revoke_families_with_reason(tx, tenant, client, user, None)
}

pub(crate) fn revoke_families_with_reason(
    tx: &Tx<'_>,
    tenant: Uuid,
    client: Option<Uuid>,
    user: Option<Uuid>,
    reason: Option<&str>,
) -> Result<usize, RepositoryError> {
    let (table, id) = if let Some(client) = client {
        (BY_CLIENT, client)
    } else if let Some(user) = user {
        (BY_USER, user)
    } else {
        return Err(invalid("family revocation requires an owner"));
    };
    let prefix = key(table, tenant, id.as_bytes());
    let mut count = 0;
    for item in tx.iterator(IteratorMode::From(&prefix, Direction::Forward)) {
        let (index, _) = item.map_err(map_error)?;
        if !index.starts_with(&prefix) {
            break;
        }
        let family_id = Uuid::from_slice(&index[prefix.len()..])
            .map_err(|_| invalid("invalid family index"))?;
        let family_key = key(FAMILY, tenant, family_id.as_bytes());
        if let Some(mut family) = read_tx::<Family>(tx, &family_key, true)?
            && user.is_none_or(|id| family.user_id == Some(id))
            && family.revoked_at.is_none()
        {
            family.revoked_at = Some(Timestamp::now());
            put_expiring(tx, &family_key, &family, family.expires_at)?;
            if let Some(reason) = reason {
                append_in_tx(
                    tx,
                    &SecurityAuditEvent {
                        event_id: Uuid::now_v7(),
                        event_type: "refresh_family_security_revoked".into(),
                        event_category: "token_lifecycle".into(),
                        payload: serde_json::json!({
                            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                            "tenant_id": tenant, "event_category": "token_lifecycle",
                            "token_family_id": family_id, "client_id": family.client_id,
                            "user_id": family.user_id, "reason": reason,
                        }),
                        occurred_at: Timestamp::now(),
                    },
                )?;
            }
            count += 1;
        }
    }
    Ok(count)
}

/// Removes a family's fixed-size secondary state. Spent proofs have their own
/// expiry entries, so even a public family's long history needs no unbounded scan.
pub(crate) fn cleanup_family(
    tx: &Tx<'_>,
    record_key: &[u8],
    raw: &[u8],
) -> Result<(), RepositoryError> {
    let tenant =
        Uuid::from_slice(&record_key[1..17]).map_err(|_| invalid("invalid family tenant key"))?;
    let family_id =
        Uuid::from_slice(&record_key[17..]).map_err(|_| invalid("invalid family key"))?;
    let family: Family = decode(raw)?;
    tx.delete(key(CONTRACT, tenant, family_id.as_bytes()))
        .map_err(map_error)?;
    tx.delete(key(CURRENT, tenant, &family.digest))
        .map_err(map_error)?;
    tx.delete(key(
        BY_CLIENT,
        tenant,
        &joined(&family.client_id, family_id.as_bytes()),
    ))
    .map_err(map_error)?;
    if let Some(user) = family.user_id {
        tx.delete(key(BY_USER, tenant, &joined(&user, family_id.as_bytes())))
            .map_err(map_error)?;
    }
    Ok(())
}

impl TokenRepositoryPort for RocksDb {
    fn machine_client_active(
        &self,
        tenant: Uuid,
        client: Uuid,
        epoch: i64,
    ) -> TokenFuture<'_, bool> {
        Box::pin(async move {
            self.run(move |store| {
                let tx = store.transaction();
                Ok(read_tx::<ClientPrincipal>(
                    &tx,
                    &key(CLIENT_PRINCIPAL, tenant, client.as_bytes()),
                    false,
                )?
                .is_some_and(|c| c.active && c.epoch == epoch))
            })
            .await
            .map_err(token_error)
        })
    }

    fn token_principal_state<'a>(
        &'a self,
        tenant: Uuid,
        client_epoch: i64,
        user: Option<Uuid>,
        subject: &'a str,
    ) -> TokenFuture<'a, TokenPrincipalState> {
        let subject = subject.to_owned();
        Box::pin(async move {
            self.run(move |store| {
                let snapshot = store.db.snapshot();
                let epoch = user
                    .map(|id| {
                        read_snapshot::<Principal>(
                            &snapshot,
                            &key(USER_PRINCIPAL, tenant, id.as_bytes()),
                        )
                        .map(|p| p.map_or(0, |p| p.authorization_epoch))
                    })
                    .transpose()?;
                let bound: Option<Uuid> = if user.is_some_and(|id| subject != id.to_string()) {
                    read_snapshot(&snapshot, &key(SUBJECT, tenant, subject.as_bytes()))?
                } else {
                    None
                };
                if bound.is_some() && bound != user {
                    return Err(invalid("subject ownership collision"));
                }
                Ok(TokenPrincipalState {
                    client_epoch,
                    user_epoch: epoch,
                    subject_bound: bound.is_some(),
                })
            })
            .await
            .map_err(token_error)
        })
    }

    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
        Box::pin(async move {
            self.run(move |store| commit(store, input))
                .await
                .map_err(token_error)
        })
    }

    fn single_use_redemption<'a>(
        &'a self,
        tenant: Uuid,
        client: Uuid,
        grant: &'a str,
    ) -> TokenFuture<'a, Option<SingleUseRedemption>> {
        let digest = *blake3::hash(grant.as_bytes()).as_bytes();
        Box::pin(async move {
            self.run(move |store| {
                let receipt: Option<Receipt> =
                    crate::db::read(&store.db, &key(RECEIPT, tenant, &joined(&client, &digest)))?;
                receipt
                    .filter(|r| r.retain_until > Timestamp::now())
                    .map(|r| {
                        Ok(SingleUseRedemption {
                            authorization_code_holder: r
                                .holder
                                .map(|value| {
                                    nazo_auth::AuthorizationCodeHolderEvidence::from_persisted(
                                        value,
                                    )
                                    .ok_or_else(|| invalid("invalid stored code holder"))
                                })
                                .transpose()?,
                            access_token_jti: r.access_token_jti,
                            access_token_expires_at: r.access_token_expires_at,
                            refresh_token_family_id: r.refresh_token_family_id,
                        })
                    })
                    .transpose()
            })
            .await
            .map_err(token_error)
        })
    }

    fn userinfo_snapshot<'a>(
        &'a self,
        tenant: Uuid,
        claims: &'a nazo_auth::Claims,
    ) -> TokenFuture<'a, Option<UserinfoSnapshot>> {
        let claims = claims.clone();
        Box::pin(async move {
            self.run(move |store| {
                if tenant.is_nil()
                    || Uuid::parse_str(&claims.tenant_id).ok() != Some(tenant)
                    || claims.subject_type != "user"
                {
                    return Ok(None);
                }
                let legacy = match (claims.client_epoch, claims.user_epoch) {
                    (None, None) => true,
                    (Some(c), Some(u)) if c >= 0 && u >= 0 => false,
                    _ => return Ok(None),
                };
                let snapshot = store.db.snapshot();
                let input = Lookup {
                    tenant,
                    jti: *blake3::hash(claims.jti.as_bytes()).as_bytes(),
                    client: claims.client_id.clone(),
                    subject: claims.sub.clone(),
                    user_id: claims.user_id.clone(),
                    subject_type: Some(claims.subject_type.clone()),
                    client_epoch: claims.client_epoch,
                    user_epoch: claims.user_epoch,
                };
                if revoked(&snapshot, &input)? {
                    return Ok(None);
                }
                let user = match claims.user_id.as_deref().map(Uuid::parse_str) {
                    Some(Ok(id)) => Some(id),
                    Some(Err(_)) if !legacy => return Ok(None),
                    _ => read_snapshot::<Uuid>(
                        &snapshot,
                        &key(SUBJECT, tenant, claims.sub.as_bytes()),
                    )?,
                };
                let Some(user) = user else { return Ok(None) };
                let Some(principal) = read_snapshot::<Principal>(
                    &snapshot,
                    &key(USER_PRINCIPAL, tenant, user.as_bytes()),
                )?
                .filter(|p| p.active) else {
                    return Ok(None);
                };
                if !legacy && Some(principal.authorization_epoch) != claims.user_epoch {
                    return Ok(None);
                }
                let subject = read_snapshot::<SubjectClaims>(
                    &snapshot,
                    &key(USER_CLAIMS, tenant, user.as_bytes()),
                )?
                .ok_or_else(|| invalid("active subject has no claims"))?;
                let client_id: Option<Uuid> = read_snapshot(
                    &snapshot,
                    &key(CLIENT_PUBLIC_ID, tenant, claims.client_id.as_bytes()),
                )?;
                let client = client_id
                    .map(|id| crate::clients::client_userinfo(&snapshot, tenant, id))
                    .transpose()?
                    .flatten();
                Ok(Some(UserinfoSnapshot { subject, client }))
            })
            .await
            .map_err(token_error)
        })
    }

    fn refresh_token<'a>(
        &'a self,
        tenant: Uuid,
        raw: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        let digest = *blake3::hash(raw.as_bytes()).as_bytes();
        Box::pin(async move {
            self.run(move |store| {
                presentation(&store.db.snapshot(), tenant, &digest, None, false)
                    .map(|p| p.map(|p| p.presented))
            })
            .await
            .map_err(token_error)
        })
    }

    fn refresh_token_snapshot<'a>(
        &'a self,
        tenant: Uuid,
        raw: &'a str,
        client: Uuid,
        retry_at: Timestamp,
        prepare: bool,
    ) -> TokenFuture<'a, Option<RefreshTokenSnapshot>> {
        let digest = *blake3::hash(raw.as_bytes()).as_bytes();
        Box::pin(async move {
            self.run(move |store| {
                presentation(
                    &store.db.snapshot(),
                    tenant,
                    &digest,
                    Some((client, retry_at)),
                    prepare,
                )
            })
            .await
            .map_err(token_error)
        })
    }

    fn active_subject_claims<'a>(
        &'a self,
        tenant: Uuid,
        user: Uuid,
        subject: &'a str,
    ) -> TokenFuture<'a, Option<PreparedTokenSubject>> {
        let subject = subject.to_owned();
        Box::pin(async move {
            self.run(move |store| prepared_subject(&store.db.snapshot(), tenant, user, &subject))
                .await
                .map_err(token_error)
        })
    }

    fn active_subject_id(&self, tenant: Uuid, user: Uuid) -> TokenFuture<'_, Option<Uuid>> {
        Box::pin(async move {
            self.run(move |store| {
                Ok(crate::db::read::<Principal>(
                    &store.db,
                    &key(USER_PRINCIPAL, tenant, user.as_bytes()),
                )?
                .is_some_and(|p| p.active)
                .then_some(user))
            })
            .await
            .map_err(token_error)
        })
    }

    fn active_subject_id_by_access_token<'a>(
        &'a self,
        tenant: Uuid,
        _jti: &'a str,
        subject: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>> {
        let subject = subject.to_owned();
        Box::pin(async move {
            self.run(move |store| {
                let snapshot = store.db.snapshot();
                let Some(user) =
                    read_snapshot::<Uuid>(&snapshot, &key(SUBJECT, tenant, subject.as_bytes()))?
                else {
                    return Ok(None);
                };
                Ok(read_snapshot::<Principal>(
                    &snapshot,
                    &key(USER_PRINCIPAL, tenant, user.as_bytes()),
                )?
                .is_some_and(|p| p.active)
                .then_some(user))
            })
            .await
            .map_err(token_error)
        })
    }

    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant: Uuid,
        client: Uuid,
        jti: &'a str,
        expiry: Option<Timestamp>,
        family: Option<Uuid>,
    ) -> TokenFuture<'a, ()> {
        let digest = *blake3::hash(jti.as_bytes()).as_bytes();
        Box::pin(async move {
            self.run(move |store| {
                let tx = store.transaction();
                if let Some(id) = family {
                    revoke_family(&tx, tenant, client, id)?;
                }
                if let Some(expiry) = expiry {
                    revoke_jti(&tx, tenant, client, &digest, expiry)?;
                }
                tx.commit().map_err(map_error)
            })
            .await
            .map_err(token_error)
        })
    }

    fn access_token_revoked<'a>(
        &'a self,
        tenant: Uuid,
        claims: &'a nazo_auth::Claims,
    ) -> TokenFuture<'a, bool> {
        let input = Lookup {
            tenant,
            jti: *blake3::hash(claims.jti.as_bytes()).as_bytes(),
            client: claims.client_id.clone(),
            subject: claims.sub.clone(),
            user_id: claims.user_id.clone(),
            subject_type: Some(claims.subject_type.clone()),
            client_epoch: claims.client_epoch,
            user_epoch: claims.user_epoch,
        };
        Box::pin(async move {
            self.run(move |store| revoked(&store.db.snapshot(), &input))
                .await
                .map_err(token_error)
        })
    }

    fn refresh_family_active(
        &self,
        tenant: Uuid,
        family: Uuid,
        user: Uuid,
    ) -> TokenFuture<'_, bool> {
        Box::pin(async move {
            self.run(move |store| {
                Ok(
                    crate::db::read::<Family>(&store.db, &key(FAMILY, tenant, family.as_bytes()))?
                        .is_some_and(|f| f.user_id == Some(user) && f.active(Timestamp::now())),
                )
            })
            .await
            .map_err(token_error)
        })
    }

    fn revoke_token_with_audit<'a>(
        &'a self,
        input: TokenRevocation<'a>,
        public_id: &'a str,
        source: &'a str,
    ) -> TokenFuture<'a, usize> {
        let (tenant, client, digest, access) = (
            input.tenant_id,
            input.client_id,
            *blake3::hash(input.raw_token.as_bytes()).as_bytes(),
            input.access_token,
        );
        let (public_id, source) = (public_id.to_owned(), source.to_owned());
        Box::pin(async move {
            self.run(move |store| {
            let tx = store.transaction();
            let updated = if let Some(access) = access {
                revoke_jti(&tx, tenant, client, blake3::hash(access.jti.as_bytes()).as_bytes(), access.expires_at)?;
                0
            } else {
                let family: Option<Uuid> = tx.get_pinned(key(CURRENT, tenant, &digest)).map_err(map_error)?.map(|raw| decode(&raw)).transpose()?;
                let family = match family { Some(id) => Some(id), None => tx.get_pinned(key(SPENT, tenant, &digest)).map_err(map_error)?
                    .map(|raw| decode::<Spent>(&raw)).transpose()?.map(|s| s.family_id) };
                match family { Some(id) => revoke_family(&tx, tenant, client, id)?, None => 0 }
            };
            append_in_tx(&tx, &SecurityAuditEvent {
                event_id: Uuid::now_v7(), event_type: "token_revoked".into(), event_category: "token_lifecycle".into(),
                payload: serde_json::json!({ "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                    "event_category": "token_lifecycle", "tenant_id": tenant, "client_id": public_id,
                    "token_hash": blake3::Hash::from_bytes(digest).to_hex().to_string(), "updated": updated, "source_ip_hash": source }),
                occurred_at: Timestamp::now(),
            })?;
            tx.commit().map_err(map_error)?;
            Ok(updated)
        }).await.map_err(token_error)
        })
    }
}

impl AccessTokenRevocationLookup for RocksDb {
    fn is_revoked<'a>(
        &'a self,
        input: RevocationLookupKey<'a>,
    ) -> ResourceServerPortFuture<'a, Result<bool, ProtectedResourceDependencyError>> {
        Box::pin(async move {
            let tenant = Uuid::parse_str(input.tenant_id)
                .map_err(|_| ProtectedResourceDependencyError::InvalidTenantBoundary)?;
            let lookup = Lookup {
                tenant,
                jti: *blake3::hash(input.jti.as_bytes()).as_bytes(),
                client: input.client_id.to_owned(),
                subject: input.subject.to_owned(),
                user_id: input.user_id.map(str::to_owned),
                subject_type: input.subject_type.map(str::to_owned),
                client_epoch: input.client_epoch,
                user_epoch: input.user_epoch,
            };
            self.run(move |store| revoked(&store.db.snapshot(), &lookup))
                .await
                .map_err(|_| ProtectedResourceDependencyError::RevocationLookupUnavailable)
        })
    }
}

#[derive(Deserialize, Serialize)]
struct RecoveryRecord {
    request_hash: String,
    state_epoch: Uuid,
    not_before: Timestamp,
    revoked_refresh_tokens: u64,
}

impl nazo_persistence::RecoveryInvalidationStore for RocksDb {
    fn invalidate_after_restore<'a>(
        &'a self,
        operation_id: Uuid,
        request_hash: &'a str,
        state_epoch: Uuid,
        not_before: Timestamp,
        completed_at: Timestamp,
    ) -> nazo_persistence::OperatorPersistenceFuture<'a, nazo_persistence::RecoveryInvalidation>
    {
        let request_hash = request_hash.to_owned();
        Box::pin(self.run(move |store| {
            if state_epoch.is_nil()
                || request_hash.len() != 64
                || !request_hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("invalid restore invalidation identity"));
            }
            // Restore runs with ingress and writers stopped. This lock orders
            // recovery commands; it intentionally adds no lock to live issuance.
            let tx = store.transaction();
            let _ = tx.get_pinned_for_update([0x5c], true).map_err(map_error)?;
            let record_key = key(0x5d, Uuid::nil(), operation_id.as_bytes());
            if let Some(record) = read_tx::<RecoveryRecord>(&tx, &record_key, true)? {
                if record.request_hash != request_hash || record.state_epoch != state_epoch {
                    return Err(RepositoryError::Conflict);
                }
                return Ok(nazo_persistence::RecoveryInvalidation {
                    state_epoch: record.state_epoch,
                    not_before: record.not_before,
                    revoked_refresh_tokens: record.revoked_refresh_tokens,
                });
            }
            let epoch_key = key(0x5e, Uuid::nil(), state_epoch.as_bytes());
            if tx
                .get_pinned_for_update(&epoch_key, true)
                .map_err(map_error)?
                .is_some()
            {
                return Err(RepositoryError::Conflict);
            }
            let mut revoked_refresh_tokens = 0;
            for item in tx.iterator(IteratorMode::From(&[FAMILY], Direction::Forward)) {
                let (family_key, _) = item.map_err(map_error)?;
                if family_key.first() != Some(&FAMILY) {
                    break;
                }
                if let Some(mut family) = read_tx::<Family>(&tx, &family_key, true)?
                    && family.revoked_at.is_none()
                {
                    family.revoked_at = Some(completed_at);
                    put_expiring(&tx, &family_key, &family, family.expires_at)?;
                    revoked_refresh_tokens += 1;
                }
            }
            put(
                &tx,
                &record_key,
                &RecoveryRecord {
                    request_hash,
                    state_epoch,
                    not_before,
                    revoked_refresh_tokens,
                },
            )?;
            put(&tx, &epoch_key, &operation_id)?;
            tx.commit().map_err(map_error)?;
            Ok(nazo_persistence::RecoveryInvalidation {
                state_epoch,
                not_before,
                revoked_refresh_tokens,
            })
        }))
    }
}

#[cfg(test)]
#[path = "../tests/unit/tokens.rs"]
mod tests;
