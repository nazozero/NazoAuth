use chrono::{DateTime, Duration, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, OptionalExtension, QueryDsl,
    SelectableHelper, sql_query, sql_types,
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE, MAX_SPENT_PROOFS_PER_REFRESH_FAMILY, NewRefreshToken,
    RefreshContract, RefreshToken, RefreshTokenPersistResult,
};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::SecurityAuditEvent;
use nazo_resource_server::{
    AccessTokenRevocationLookup, ProtectedResourceDependencyError, ResourceServerPortFuture,
    RevocationLookupKey,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    DbPool, get_conn,
    repositories::audit_ledger::append_fresh_security_audit_on_connection,
    rows::auth::{RefreshContractRow, RefreshFamilyRow, SpentRefreshTokenRow},
    schema::{
        access_token_revocations, oauth_refresh_contracts, oauth_refresh_families,
        oauth_refresh_spent_tokens, recovery_invalidations,
    },
};

use super::access_token_revocation::{
    NewAccessTokenRevocation, access_token_revocation_deadline, upsert_access_token_revocations,
};

pub(crate) const LOST_REFRESH_TOKEN_RETRY_SECONDS: i64 = 60;

#[derive(Clone)]
pub struct TokenRepository {
    pool: DbPool,
}

/// Durable outcome of one post-restore invalidation. The operation id and
/// request hash make a crash/retry return the original authority boundary
/// rather than revoking a newly issued token set a second time.
pub use nazo_persistence::RecoveryInvalidation;

impl TokenRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Atomically revoke every active refresh token in the restored tenant
    /// database and publish the one durable ingress-reopen boundary.
    pub async fn invalidate_after_restore(
        &self,
        operation_id: Uuid,
        request_hash: &str,
        tenant_id: Uuid,
        state_epoch: Uuid,
        not_before: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> Result<RecoveryInvalidation, RepositoryError> {
        if state_epoch.is_nil() {
            return Err(RepositoryError::Consistency(
                "recovery state epoch must not be nil".to_owned(),
            ));
        }
        if !is_lower_sha256(request_hash) {
            return Err(RepositoryError::Consistency(
                "recovery request hash must be lowercase sha256 hex".to_owned(),
            ));
        }
        let mut connection = self.connection().await?;
        connection
            .transaction::<RecoveryInvalidation, diesel::result::Error, _>(async |connection| {
                lock_recovery_invalidation_scope(connection, tenant_id).await?;
                if let Some((
                    stored_hash,
                    stored_tenant,
                    stored_epoch,
                    stored_not_before,
                    stored_count,
                )) = recovery_invalidations::table
                    .filter(recovery_invalidations::operation_id.eq(operation_id))
                    .select((
                        recovery_invalidations::request_hash,
                        recovery_invalidations::tenant_id,
                        recovery_invalidations::state_epoch,
                        recovery_invalidations::not_before,
                        recovery_invalidations::revoked_refresh_tokens,
                    ))
                    .first::<(String, Uuid, Uuid, DateTime<Utc>, i64)>(connection)
                    .await
                    .optional()?
                {
                    if stored_hash != request_hash
                        || stored_tenant != tenant_id
                        || stored_epoch != state_epoch
                    {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    return Ok(RecoveryInvalidation {
                        state_epoch: stored_epoch,
                        not_before: stored_not_before,
                        revoked_refresh_tokens: stored_count as u64,
                    });
                }
                if recovery_invalidations::table
                    .filter(recovery_invalidations::tenant_id.eq(tenant_id))
                    .filter(recovery_invalidations::state_epoch.eq(state_epoch))
                    .select(recovery_invalidations::operation_id)
                    .first::<Uuid>(connection)
                    .await
                    .optional()?
                    .is_some()
                {
                    return Err(diesel::result::Error::RollbackTransaction);
                }
                let revoked = diesel::update(
                    oauth_refresh_families::table
                        .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
                        .filter(oauth_refresh_families::revoked_at.is_null()),
                )
                .set(oauth_refresh_families::revoked_at.eq(completed_at))
                .execute(connection)
                .await?;
                diesel::insert_into(recovery_invalidations::table)
                    .values((
                        recovery_invalidations::operation_id.eq(operation_id),
                        recovery_invalidations::request_hash.eq(request_hash),
                        recovery_invalidations::tenant_id.eq(tenant_id),
                        recovery_invalidations::state_epoch.eq(state_epoch),
                        recovery_invalidations::not_before.eq(not_before),
                        recovery_invalidations::revoked_refresh_tokens.eq(revoked as i64),
                        recovery_invalidations::completed_at.eq(completed_at),
                    ))
                    .execute(connection)
                    .await?;
                Ok(RecoveryInvalidation {
                    state_epoch,
                    not_before,
                    revoked_refresh_tokens: revoked as u64,
                })
            })
            .await
            .map_err(|error| {
                if matches!(error, diesel::result::Error::RollbackTransaction) {
                    RepositoryError::Conflict
                } else {
                    map_error(error)
                }
            })
    }

    pub async fn by_raw_refresh_token(
        &self,
        tenant_id: Uuid,
        raw_token: &str,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        let digest = blake3::hash(raw_token.as_bytes());
        let mut connection = self.connection().await?;
        lookup_refresh_token(&mut connection, tenant_id, digest.as_bytes())
            .await
            .map_err(map_error)
    }

    /// Apply a refresh-token mutation inside a caller-owned transaction.
    ///
    /// This helper deliberately performs no pool acquisition and never starts
    /// a nested transaction. The caller's transaction therefore owns the
    /// refresh-family locks, rotation, capacity eviction and any resulting
    /// compromise decision.
    pub(crate) async fn persist_refresh_token_on_connection(
        connection: &mut AsyncPgConnection,
        token: NewRefreshToken,
        issuance_id: Uuid,
        prepared_contract: &PreparedRefreshContract,
    ) -> Result<RefreshTokenPersistResult, RepositoryError> {
        validate_new_refresh_token(&token)?;
        persist_refresh_token_inner(connection, &token, issuance_id, prepared_contract)
            .await
            .map_err(map_error)
    }

    pub async fn inspect_lost_response_successor(
        &self,
        token: &RefreshToken,
        client_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        let mut connection = self.connection().await?;
        lost_response_successor(&mut connection, token, client_id, now)
            .await
            .map_err(map_error)
    }

    pub async fn family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::select(diesel::dsl::exists(
            oauth_refresh_families::table
                .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
                .filter(oauth_refresh_families::token_family_id.eq(family_id))
                .filter(oauth_refresh_families::user_id.eq(user_id))
                .filter(oauth_refresh_families::revoked_at.is_null())
                .filter(oauth_refresh_families::reuse_detected_at.is_null())
                .filter(oauth_refresh_families::current_expires_at.gt(Utc::now())),
        ))
        .get_result::<bool>(&mut connection)
        .await
        .map_err(map_error)
    }

    pub async fn access_token_revoked(
        &self,
        tenant_id: Uuid,
        jti: &str,
    ) -> Result<bool, RepositoryError> {
        let jti_blake3 = blake3_hex(jti);
        let mut connection = self.connection().await?;
        diesel::select(diesel::dsl::exists(
            access_token_revocations::table
                .filter(access_token_revocations::tenant_id.eq(tenant_id))
                .filter(access_token_revocations::access_token_jti_blake3.eq(jti_blake3)),
        ))
        .get_result::<bool>(&mut connection)
        .await
        .map_err(map_error)
    }

    /// Revokes a refresh-token family or records an access-token JTI in one transaction.
    /// The family lock is shared with rotation so a successor cannot escape revocation.
    pub(crate) async fn revoke_for_client(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        raw_token: &str,
        access_token: Option<&nazo_auth::AccessTokenRevocation>,
    ) -> Result<usize, RepositoryError> {
        // The revocation fact covers the token's full verifier acceptance
        // window; plain input conversion happens before a connection or
        // transaction is acquired.
        let revocation_deadline = access_token
            .map(|access_token| access_token_revocation_deadline(access_token.expires_at))
            .transpose()?;
        let raw_token_blake3 = blake3::hash(raw_token.as_bytes());
        let new_revocation =
            access_token
                .zip(revocation_deadline)
                .map(|(access_token, deadline)| NewAccessTokenRevocation {
                    id: Uuid::now_v7(),
                    access_token_jti_blake3: blake3_hex(&access_token.jti),
                    client_id,
                    tenant_id,
                    revoked_at: Utc::now(),
                    expires_at: deadline,
                });
        let mut connection = self.connection().await?;
        connection
            .transaction::<usize, diesel::result::Error, _>(async |connection| {
                let family_id = refresh_family_id_for_digest(
                    connection,
                    tenant_id,
                    client_id,
                    raw_token_blake3.as_bytes(),
                )
                .await?;
                if let Some(family_id) = family_id {
                    lock_refresh_family(connection, family_id).await?;
                    return diesel::update(
                        oauth_refresh_families::table
                            .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
                            .filter(oauth_refresh_families::client_id.eq(client_id))
                            .filter(oauth_refresh_families::token_family_id.eq(family_id))
                            .filter(oauth_refresh_families::revoked_at.is_null()),
                    )
                    .set(oauth_refresh_families::revoked_at.eq(diesel::dsl::now))
                    .execute(connection)
                    .await;
                }
                if let Some(new_revocation) = new_revocation {
                    upsert_access_token_revocations(connection, &[new_revocation]).await?;
                }
                Ok(0)
            })
            .await
            .map_err(map_error)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

impl nazo_persistence::RecoveryInvalidationStore for TokenRepository {
    fn invalidate_after_restore<'a>(
        &'a self,
        operation_id: Uuid,
        request_hash: &'a str,
        tenant_id: Uuid,
        state_epoch: Uuid,
        not_before: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> nazo_persistence::OperatorPersistenceFuture<'a, RecoveryInvalidation> {
        Box::pin(async move {
            TokenRepository::invalidate_after_restore(
                self,
                operation_id,
                request_hash,
                tenant_id,
                state_epoch,
                not_before,
                completed_at,
            )
            .await
        })
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl AccessTokenRevocationLookup for TokenRepository {
    fn is_revoked<'a>(
        &'a self,
        key: RevocationLookupKey<'a>,
    ) -> ResourceServerPortFuture<'a, Result<bool, ProtectedResourceDependencyError>> {
        Box::pin(async move {
            let tenant_id = Uuid::parse_str(key.tenant_id)
                .map_err(|_| ProtectedResourceDependencyError::InvalidTenantBoundary)?;
            self.access_token_revoked(tenant_id, key.jti)
                .await
                .map_err(|_| ProtectedResourceDependencyError::RevocationLookupUnavailable)
        })
    }
}

/// The persisted contract subset mirrored by `oauth_refresh_contracts`.
/// `nonce` and `id_token_sid` are always null here: the nonce has no
/// refresh-time reader and the ID-token session id is per-generation state on
/// the family row.
#[derive(Debug, Deserialize)]
struct PersistedRefreshContract {
    subject: String,
    scopes: Vec<String>,
    audiences: Vec<String>,
    #[serde(default)]
    authorization_details: Value,
    authentication_context: nazo_auth::RefreshTokenAuthenticationContext,
}

fn validate_new_refresh_token(token: &NewRefreshToken) -> Result<(), RepositoryError> {
    if !token.authentication_context.is_well_formed()
        || token.audiences.is_empty()
        || token
            .audiences
            .iter()
            .any(|audience| audience.trim().is_empty())
        || token.authentication_context.auth_time > token.issued_at.timestamp()
    {
        return Err(RepositoryError::Consistency(
            "refresh token requires a complete current authentication contract".to_owned(),
        ));
    }
    Ok(())
}

fn persisted_contract(contract: &RefreshContract) -> Result<(Vec<u8>, Value), RepositoryError> {
    let persisted = contract.persisted();
    let value = serde_json::to_value(&persisted).map_err(|error| {
        RepositoryError::Consistency(format!("refresh contract could not be serialized: {error}"))
    })?;
    Ok((persisted.blake3_digest().to_vec(), value))
}

/// Connection-free refresh-contract preparation: the persisted JSON shape
/// and its BLAKE3 digest are pure functions of the token, so callers compute
/// them before borrowing a connection. Everything that depends on database
/// state still runs inside the caller's transaction unchanged.
#[derive(Debug)]
pub(crate) struct PreparedRefreshContract {
    contract_blake3: Vec<u8>,
    contract_value: Value,
}

pub(crate) fn prepare_refresh_contract(
    token: &NewRefreshToken,
) -> Result<PreparedRefreshContract, RepositoryError> {
    let (contract_blake3, contract_value) =
        persisted_contract(&token.contract()).map_err(|error| {
            // Preserve the pre-hoist classification: a prepare failure used to
            // surface as a diesel deserialization error inside the persist
            // transaction, which callers mapped to RepositoryError::Unexpected.
            RepositoryError::Unexpected(error.to_string())
        })?;
    Ok(PreparedRefreshContract {
        contract_blake3,
        contract_value,
    })
}

fn parse_contract(row: &RefreshContractRow) -> Result<PersistedRefreshContract, RepositoryError> {
    serde_json::from_value::<PersistedRefreshContract>(row.contract.clone()).map_err(|error| {
        RepositoryError::Unexpected(format!("invalid persisted refresh contract: {error}"))
    })
}

fn digest32(bytes: &[u8]) -> Result<[u8; 32], RepositoryError> {
    bytes.try_into().map_err(|_| {
        RepositoryError::Unexpected("refresh digest must be exactly 32 bytes".to_owned())
    })
}

fn token_from_current(
    family: RefreshFamilyRow,
    contract: &PersistedRefreshContract,
) -> Result<RefreshToken, RepositoryError> {
    let mut context = contract.authentication_context.clone();
    context.id_token_sid = family.current_id_token_sid.clone();
    Ok(RefreshToken {
        id: family.current_member_id,
        token_blake3: digest32(&family.current_token_blake3)?,
        tenant_id: family.tenant_id,
        token_family_id: family.token_family_id,
        client_id: family.client_id,
        user_id: family.user_id,
        scopes: serde_json::json!(contract.scopes),
        audience: family.current_audience.clone(),
        authorization_details: contract.authorization_details.clone(),
        issued_at: family.current_issued_at,
        expires_at: family.current_expires_at,
        revoked_at: family.revoked_at,
        subject: contract.subject.clone(),
        dpop_jkt: family.dpop_jkt.clone(),
        mtls_x5t_s256: family.mtls_x5t_s256.clone(),
        client_attestation_jkt: family.client_attestation_jkt.clone(),
        authentication_context: context,
    })
}

/// A spent presentation resolves to its member identity and spent facts; the
/// authorization payload is the family contract (members never diverge), and
/// the audience is the original grant audience — the current narrowing belongs
/// to the live member only.
fn token_from_spent(
    spent: SpentRefreshTokenRow,
    family: RefreshFamilyRow,
    contract: &PersistedRefreshContract,
) -> Result<RefreshToken, RepositoryError> {
    let mut context = contract.authentication_context.clone();
    context.id_token_sid = family.current_id_token_sid.clone();
    Ok(RefreshToken {
        id: spent.member_id,
        token_blake3: digest32(&spent.refresh_token_blake3)?,
        tenant_id: family.tenant_id,
        token_family_id: family.token_family_id,
        client_id: family.client_id,
        user_id: family.user_id,
        scopes: serde_json::json!(contract.scopes),
        audience: serde_json::json!(contract.audiences),
        authorization_details: contract.authorization_details.clone(),
        // The member's own issuance time is not retained; `spent_at` is the
        // last instant the member was the family's current token.
        issued_at: spent.spent_at,
        expires_at: spent.expires_at,
        revoked_at: Some(spent.spent_at),
        subject: contract.subject.clone(),
        dpop_jkt: family.dpop_jkt.clone(),
        mtls_x5t_s256: family.mtls_x5t_s256.clone(),
        client_attestation_jkt: family.client_attestation_jkt.clone(),
        authentication_context: context,
    })
}

/// Presentation lookup: the current member by digest, else a spent proof.
/// Each branch reads its family and contract in one statement; the contract
/// join is a LEFT JOIN so a missing referenced contract still surfaces as a
/// consistency error instead of silently turning the presentation into
/// "token not found". A spent proof without a live family row is unreachable
/// (the foreign key cascades), so a missing family means the proof row is
/// gone as well.
async fn lookup_refresh_token(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    digest: &[u8],
) -> Result<Option<RefreshToken>, diesel::result::Error> {
    if let Some((family, contract_row)) = oauth_refresh_families::table
        .left_join(
            oauth_refresh_contracts::table.on(oauth_refresh_contracts::tenant_id
                .eq(oauth_refresh_families::tenant_id)
                .and(
                    oauth_refresh_contracts::contract_blake3
                        .eq(oauth_refresh_families::contract_blake3),
                )),
        )
        .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
        .filter(oauth_refresh_families::current_token_blake3.eq(digest))
        .select((
            RefreshFamilyRow::as_select(),
            Option::<RefreshContractRow>::as_select(),
        ))
        .first::<(RefreshFamilyRow, Option<RefreshContractRow>)>(connection)
        .await
        .optional()?
    {
        let Some(contract_row) = contract_row else {
            return Err(diesel::result::Error::DeserializationError(
                "refresh family references a missing contract".into(),
            ));
        };
        let contract = parse_contract(&contract_row).map_err(|error| {
            diesel::result::Error::DeserializationError(error.to_string().into())
        })?;
        return token_from_current(family, &contract)
            .map(Some)
            .map_err(|error| {
                diesel::result::Error::DeserializationError(error.to_string().into())
            });
    }
    if let Some((spent, family, contract_row)) = oauth_refresh_spent_tokens::table
        .inner_join(
            oauth_refresh_families::table.on(oauth_refresh_families::tenant_id
                .eq(oauth_refresh_spent_tokens::tenant_id)
                .and(
                    oauth_refresh_families::token_family_id
                        .eq(oauth_refresh_spent_tokens::token_family_id),
                )),
        )
        .left_join(
            oauth_refresh_contracts::table.on(oauth_refresh_contracts::tenant_id
                .eq(oauth_refresh_families::tenant_id)
                .and(
                    oauth_refresh_contracts::contract_blake3
                        .eq(oauth_refresh_families::contract_blake3),
                )),
        )
        .filter(oauth_refresh_spent_tokens::tenant_id.eq(tenant_id))
        .filter(oauth_refresh_spent_tokens::refresh_token_blake3.eq(digest))
        .select((
            SpentRefreshTokenRow::as_select(),
            RefreshFamilyRow::as_select(),
            Option::<RefreshContractRow>::as_select(),
        ))
        .first::<(
            SpentRefreshTokenRow,
            RefreshFamilyRow,
            Option<RefreshContractRow>,
        )>(connection)
        .await
        .optional()?
    {
        let Some(contract_row) = contract_row else {
            return Err(diesel::result::Error::DeserializationError(
                "refresh family references a missing contract".into(),
            ));
        };
        let contract = parse_contract(&contract_row).map_err(|error| {
            diesel::result::Error::DeserializationError(error.to_string().into())
        })?;
        return token_from_spent(spent, family, &contract)
            .map(Some)
            .map_err(|error| {
                diesel::result::Error::DeserializationError(error.to_string().into())
            });
    }
    Ok(None)
}

async fn load_family(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    family_id: Uuid,
) -> diesel::QueryResult<Option<RefreshFamilyRow>> {
    oauth_refresh_families::table
        .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
        .filter(oauth_refresh_families::token_family_id.eq(family_id))
        .select(RefreshFamilyRow::as_select())
        .first::<RefreshFamilyRow>(connection)
        .await
        .optional()
}

async fn persist_refresh_token_inner(
    connection: &mut AsyncPgConnection,
    token: &NewRefreshToken,
    issuance_id: Uuid,
    prepared_contract: &PreparedRefreshContract,
) -> diesel::QueryResult<RefreshTokenPersistResult> {
    // Contract serialization and digest were computed before this
    // connection was borrowed (see prepare_refresh_contract); only the
    // token hash and authoritative in-transaction state work remain here.
    let contract_blake3 = &prepared_contract.contract_blake3;
    let contract_value = &prepared_contract.contract_value;
    let token_blake3 = blake3::hash(token.raw_token.as_bytes());
    lock_refresh_grant_scope(connection, token.tenant_id, token.user_id, token.client_id).await?;
    lock_refresh_family(connection, token.family_id).await?;

    if let Some(rotated_from_id) = token.rotated_from_id {
        // Rotation: the family row must name the presented member as its
        // current generation, stay unrevoked/uncompromised, share the exact
        // same contract content, and keep the grant's sender binding — a
        // binding that drifts mid-family is indistinguishable from a replay
        // of the grant to another key, so it compromises the family.
        let family = load_family(connection, token.tenant_id, token.family_id).await?;
        let family = match family {
            Some(family)
                if family.current_member_id == rotated_from_id
                    && family.client_id == token.client_id
                    && family.user_id == token.user_id
                    && family.revoked_at.is_none()
                    && family.reuse_detected_at.is_none()
                    && family.contract_blake3 == *contract_blake3
                    && family.dpop_jkt == token.dpop_jkt
                    && family.mtls_x5t_s256 == token.mtls_x5t_s256
                    && family.client_attestation_jkt == token.client_attestation_jkt =>
            {
                family
            }
            _ => {
                compromise_family(connection, token.tenant_id, token.family_id).await?;
                return Ok(RefreshTokenPersistResult::RotationConflict);
            }
        };
        if let Some(retry) = token.lost_response_retry {
            // The retry must prove the presented original is the current
            // member's direct spent predecessor within the 60s window.
            let edge = oauth_refresh_spent_tokens::table
                .filter(oauth_refresh_spent_tokens::tenant_id.eq(token.tenant_id))
                .filter(
                    oauth_refresh_spent_tokens::refresh_token_blake3
                        .eq(retry.original_blake3.as_slice()),
                )
                .select((
                    oauth_refresh_spent_tokens::successor_member_id,
                    oauth_refresh_spent_tokens::spent_at,
                ))
                .first::<(Uuid, DateTime<Utc>)>(connection)
                .await
                .optional()?;
            let elapsed =
                edge.map(|(_, spent_at)| retry.retry_started_at.signed_duration_since(spent_at));
            let edge_valid = matches!(
                edge,
                Some((successor_member_id, _))
                    if successor_member_id == rotated_from_id
            ) && matches!(
                elapsed,
                Some(elapsed)
                    if elapsed >= Duration::zero()
                        && elapsed <= Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS)
            );
            if !edge_valid {
                compromise_family(connection, token.tenant_id, token.family_id).await?;
                return Ok(RefreshTokenPersistResult::RotationConflict);
            }
        }
        // The presented generation becomes a compact spent proof; the family
        // row adopts the successor in place. No contract rewrite, no member
        // history row.
        diesel::insert_into(oauth_refresh_spent_tokens::table)
            .values((
                oauth_refresh_spent_tokens::tenant_id.eq(token.tenant_id),
                oauth_refresh_spent_tokens::refresh_token_blake3
                    .eq(family.current_token_blake3.clone()),
                oauth_refresh_spent_tokens::token_family_id.eq(token.family_id),
                oauth_refresh_spent_tokens::member_id.eq(family.current_member_id),
                oauth_refresh_spent_tokens::successor_member_id.eq(token.member_id),
                oauth_refresh_spent_tokens::spent_at.eq(token.issued_at),
                oauth_refresh_spent_tokens::expires_at.eq(family.current_expires_at),
            ))
            .execute(connection)
            .await?;
        // Bound the replay window: keep only the newest
        // MAX_SPENT_PROOFS_PER_REFRESH_FAMILY proofs for this family so spent
        // state cannot grow with rotation count or family age.
        sql_query(
            "DELETE FROM oauth_refresh_spent_tokens \
             WHERE tenant_id = $1 AND token_family_id = $2 \
               AND member_id NOT IN ( \
                 SELECT member_id FROM oauth_refresh_spent_tokens \
                 WHERE tenant_id = $1 AND token_family_id = $2 \
                 ORDER BY spent_at DESC, member_id DESC \
                 LIMIT $3 \
               )",
        )
        .bind::<sql_types::Uuid, _>(token.tenant_id)
        .bind::<sql_types::Uuid, _>(token.family_id)
        .bind::<sql_types::BigInt, _>(MAX_SPENT_PROOFS_PER_REFRESH_FAMILY)
        .execute(connection)
        .await?;
        diesel::update(
            oauth_refresh_families::table
                .filter(oauth_refresh_families::tenant_id.eq(token.tenant_id))
                .filter(oauth_refresh_families::token_family_id.eq(token.family_id)),
        )
        .set((
            oauth_refresh_families::current_member_id.eq(token.member_id),
            oauth_refresh_families::current_token_blake3.eq(token_blake3.as_bytes().to_vec()),
            oauth_refresh_families::current_audience.eq(serde_json::json!(token.audiences)),
            oauth_refresh_families::current_issued_at.eq(token.issued_at),
            oauth_refresh_families::current_expires_at.eq(token.expires_at),
            oauth_refresh_families::current_id_token_sid
                .eq(token.authentication_context.id_token_sid.clone()),
        ))
        .execute(connection)
        .await?;
        return Ok(RefreshTokenPersistResult::Inserted);
    }

    // New family issuance: a same-named family is a collision compromise,
    // then the (tenant, user, client) active-family cap retires the
    // deterministically oldest live families before the insert.
    if load_family(connection, token.tenant_id, token.family_id)
        .await?
        .is_some()
    {
        compromise_family(connection, token.tenant_id, token.family_id).await?;
        return Ok(RefreshTokenPersistResult::RotationConflict);
    }
    if let Some(user_id) = token.user_id {
        retire_families_over_cap(
            connection,
            token.tenant_id,
            user_id,
            token.client_id,
            issuance_id,
        )
        .await?;
    }
    // One narrow call references the contract: an existing key is locked
    // FOR KEY SHARE inside this transaction (the family foreign key can
    // never dangle against a concurrent reclaim); a missing key takes the
    // validated INSERT and a genuine create/reclaim race retries locally.
    sql_query("SELECT public.nazo_oauth_refresh_contract_ensure($1, $2, $3)")
        .bind::<sql_types::Uuid, _>(token.tenant_id)
        .bind::<sql_types::Binary, _>(contract_blake3)
        .bind::<sql_types::Jsonb, _>(contract_value)
        .execute(connection)
        .await?;
    diesel::insert_into(oauth_refresh_families::table)
        .values((
            oauth_refresh_families::tenant_id.eq(token.tenant_id),
            oauth_refresh_families::token_family_id.eq(token.family_id),
            oauth_refresh_families::client_id.eq(token.client_id),
            oauth_refresh_families::user_id.eq(token.user_id),
            oauth_refresh_families::contract_blake3.eq(contract_blake3.clone()),
            oauth_refresh_families::current_member_id.eq(token.member_id),
            oauth_refresh_families::current_token_blake3.eq(token_blake3.as_bytes().to_vec()),
            oauth_refresh_families::current_audience.eq(serde_json::json!(token.audiences)),
            oauth_refresh_families::current_issued_at.eq(token.issued_at),
            oauth_refresh_families::current_expires_at.eq(token.expires_at),
            oauth_refresh_families::current_id_token_sid
                .eq(token.authentication_context.id_token_sid.clone()),
            oauth_refresh_families::dpop_jkt.eq(token.dpop_jkt.clone()),
            oauth_refresh_families::mtls_x5t_s256.eq(token.mtls_x5t_s256.clone()),
            oauth_refresh_families::client_attestation_jkt.eq(token.client_attestation_jkt.clone()),
            oauth_refresh_families::created_at.eq(token.issued_at),
        ))
        .execute(connection)
        .await?;
    Ok(RefreshTokenPersistResult::Inserted)
}

/// Enforce `MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE` inside the grant-scope
/// advisory lock. Live families beyond the nine newest are retired oldest
/// first (by `current_issued_at`, then family id), deleted outright with their
/// spent proofs; each retirement emits a Required audit event so the ledger
/// keeps the deliberate-termination evidence.
async fn retire_families_over_cap(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    issuance_id: Uuid,
) -> diesel::QueryResult<()> {
    #[derive(diesel::QueryableByName)]
    struct LiveFamilyId {
        #[diesel(sql_type = sql_types::Uuid)]
        token_family_id: Uuid,
    }
    // Keep the nine newest live families so the pending insert lands at the
    // cap; everything older is retired. Ordered access makes the set
    // deterministic under identical timestamps.
    let victims = sql_query(
        "WITH ranked AS ( \
             SELECT token_family_id, \
                    row_number() OVER ( \
                        ORDER BY current_issued_at ASC, token_family_id ASC) AS rn, \
                    count(*) OVER () AS total \
             FROM oauth_refresh_families \
             WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 \
               AND revoked_at IS NULL AND reuse_detected_at IS NULL \
               AND current_expires_at > CURRENT_TIMESTAMP \
         ) SELECT token_family_id FROM ranked WHERE rn <= total - $4",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Uuid, _>(client_id)
    .bind::<sql_types::BigInt, _>(MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE - 1)
    .load::<LiveFamilyId>(connection)
    .await?;
    for victim in victims {
        lock_refresh_family(connection, victim.token_family_id).await?;
        let removed = diesel::delete(
            oauth_refresh_families::table
                .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
                .filter(oauth_refresh_families::token_family_id.eq(victim.token_family_id))
                .filter(oauth_refresh_families::revoked_at.is_null())
                .filter(oauth_refresh_families::reuse_detected_at.is_null())
                .filter(oauth_refresh_families::current_expires_at.gt(diesel::dsl::now)),
        )
        .execute(connection)
        .await?;
        if removed == 0 {
            continue;
        }
        // Unreferenced contracts are reclaimed by maintenance after its grace.
        append_fresh_security_audit_on_connection(
            connection,
            &SecurityAuditEvent {
                event_id: Uuid::now_v7(),
                event_type: "refresh_family_capacity_retired".to_owned(),
                event_category: "token_lifecycle".to_owned(),
                payload: serde_json::json!({
                    "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                    "tenant_id": tenant_id,
                    "issuance_id": issuance_id,
                    "event_category": "token_lifecycle",
                    "token_family_id": victim.token_family_id,
                    "client_id": client_id,
                    "user_id": user_id,
                    "reason": "active_family_cap",
                    "max_active_families": MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE,
                }),
                occurred_at: Utc::now(),
            },
        )
        .await?;
    }
    Ok(())
}

/// Resolve a presented digest to its family: current member first, then the
/// spent proofs (a spent presentation still revokes its family).
async fn refresh_family_id_for_digest(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    client_id: Uuid,
    digest: &[u8],
) -> diesel::QueryResult<Option<Uuid>> {
    if let Some(family_id) = oauth_refresh_families::table
        .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
        .filter(oauth_refresh_families::client_id.eq(client_id))
        .filter(oauth_refresh_families::current_token_blake3.eq(digest))
        .select(oauth_refresh_families::token_family_id)
        .first::<Uuid>(connection)
        .await
        .optional()?
    {
        return Ok(Some(family_id));
    }
    sql_query(
        "SELECT s.token_family_id FROM oauth_refresh_spent_tokens AS s \
         JOIN oauth_refresh_families AS f \
           ON f.tenant_id = s.tenant_id AND f.token_family_id = s.token_family_id \
         WHERE s.tenant_id = $1 AND s.refresh_token_blake3 = $2 AND f.client_id = $3",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Binary, _>(digest)
    .bind::<sql_types::Uuid, _>(client_id)
    .get_result::<FamilyIdRow>(connection)
    .await
    .optional()
    .map(|row| row.map(|row| row.token_family_id))
}

#[derive(diesel::QueryableByName)]
struct FamilyIdRow {
    #[diesel(sql_type = sql_types::Uuid)]
    token_family_id: Uuid,
}

async fn lock_recovery_invalidation_scope(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
) -> diesel::QueryResult<()> {
    let bytes = tenant_id.as_bytes();
    let high = i64::from_be_bytes(bytes[..8].try_into().expect("UUID has 16 bytes"));
    let low = i64::from_be_bytes(bytes[8..].try_into().expect("UUID has 16 bytes"));
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<diesel::sql_types::BigInt, _>(high ^ low ^ 0x5245_4356_4552_595f_i64)
        .execute(connection)
        .await?;
    Ok(())
}

/// The advisory key shared by refresh-token writers and the bounded
/// maintenance reclaim. `pg_try_advisory_xact_lock` users must pass exactly
/// this key so a maintenance scan never opens a second lock domain.
pub(super) fn refresh_family_lock_key(family_id: Uuid) -> i64 {
    let bytes = family_id.as_bytes();
    let high = i64::from_be_bytes(bytes[..8].try_into().expect("UUID has 16 bytes"));
    let low = i64::from_be_bytes(bytes[8..].try_into().expect("UUID has 16 bytes"));
    high ^ low
}

pub(super) async fn lock_refresh_family(
    connection: &mut AsyncPgConnection,
    family_id: Uuid,
) -> diesel::QueryResult<()> {
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<diesel::sql_types::BigInt, _>(refresh_family_lock_key(family_id))
        .execute(connection)
        .await?;
    Ok(())
}

pub(super) async fn lock_refresh_grant_scope(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
    client_id: Uuid,
) -> diesel::QueryResult<()> {
    let mut hasher = blake3::Hasher::new_derive_key("nazo.refresh-grant-advisory-lock.v1");
    hasher.update(tenant_id.as_bytes());
    match user_id {
        Some(user_id) => {
            hasher.update(&[1]);
            hasher.update(user_id.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(client_id.as_bytes());
    let key = i64::from_be_bytes(
        hasher.finalize().as_bytes()[..8]
            .try_into()
            .expect("BLAKE3 output contains eight bytes"),
    );
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<diesel::sql_types::BigInt, _>(key)
        .execute(connection)
        .await?;
    Ok(())
}

/// Family compromise is one row, one fact: idempotent on repeat conflict.
async fn compromise_family(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    family_id: Uuid,
) -> diesel::QueryResult<()> {
    diesel::update(
        oauth_refresh_families::table
            .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
            .filter(oauth_refresh_families::token_family_id.eq(family_id))
            .filter(oauth_refresh_families::reuse_detected_at.is_null()),
    )
    .set((
        oauth_refresh_families::reuse_detected_at.eq(diesel::dsl::now),
        oauth_refresh_families::revoked_at.eq(diesel::dsl::sql::<
            diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
        >("COALESCE(revoked_at, CURRENT_TIMESTAMP)")),
    ))
    .execute(connection)
    .await?;
    Ok(())
}

/// Lost-response recovery for a spent presentation: the presented token must
/// be a known spent proof, still inside the 60s window, and the family must
/// still carry the named direct successor as its live current member. Sender
/// constraints are family-level facts, so the successor cannot carry a weaker
/// binding than the token it replaced.
/// One statement: the presented digest's spent edge joined to the family row
/// that still names it as the direct predecessor (`current_member_id =
/// successor_member_id`), then to its contract. A revoked, compromised,
/// re-rotated, or expired family simply yields no row.
async fn lost_response_successor(
    connection: &mut AsyncPgConnection,
    token: &RefreshToken,
    client_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<RefreshToken>, diesel::result::Error> {
    if token.dpop_jkt.is_none() && token.mtls_x5t_s256.is_none() {
        return Ok(None);
    }
    let Some(row) = sql_query(
        "SELECT \
             f.tenant_id, f.token_family_id, f.client_id, f.user_id, \
             f.contract_blake3, f.current_member_id, f.current_token_blake3, \
             f.current_audience, f.current_issued_at, f.current_expires_at, \
             f.current_id_token_sid, f.dpop_jkt, f.mtls_x5t_s256, \
             f.client_attestation_jkt, f.revoked_at, \
             f.reuse_detected_at, c.contract, s.spent_at \
         FROM oauth_refresh_spent_tokens AS s \
         JOIN oauth_refresh_families AS f \
           ON f.tenant_id = s.tenant_id AND f.token_family_id = s.token_family_id \
         LEFT JOIN oauth_refresh_contracts AS c \
           ON c.tenant_id = f.tenant_id AND c.contract_blake3 = f.contract_blake3 \
         WHERE s.tenant_id = $1 AND s.refresh_token_blake3 = $2 \
           AND f.client_id = $3 \
           AND f.current_member_id = s.successor_member_id \
           AND f.revoked_at IS NULL AND f.reuse_detected_at IS NULL \
           AND f.current_expires_at > $4",
    )
    .bind::<sql_types::Uuid, _>(token.tenant_id)
    .bind::<sql_types::Binary, _>(token.token_blake3.as_slice())
    .bind::<sql_types::Uuid, _>(client_id)
    .bind::<sql_types::Timestamptz, _>(now)
    .get_result::<LostResponseJoinRow>(connection)
    .await
    .optional()?
    else {
        return Ok(None);
    };
    if row.token_family_id != token.token_family_id {
        return Ok(None);
    }
    let elapsed = now.signed_duration_since(row.spent_at);
    if elapsed < Duration::zero() || elapsed > Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS) {
        return Ok(None);
    }
    let Some(contract_json) = row.contract else {
        return Err(diesel::result::Error::DeserializationError(
            "refresh family references a missing contract".into(),
        ));
    };
    let contract = parse_contract(&RefreshContractRow {
        contract: contract_json,
    })
    .map_err(|error| diesel::result::Error::DeserializationError(error.to_string().into()))?;
    token_from_current(
        RefreshFamilyRow {
            tenant_id: row.tenant_id,
            token_family_id: row.token_family_id,
            client_id: row.client_id,
            user_id: row.user_id,
            contract_blake3: row.contract_blake3,
            current_member_id: row.current_member_id,
            current_token_blake3: row.current_token_blake3,
            current_audience: row.current_audience,
            current_issued_at: row.current_issued_at,
            current_expires_at: row.current_expires_at,
            current_id_token_sid: row.current_id_token_sid,
            dpop_jkt: row.dpop_jkt,
            mtls_x5t_s256: row.mtls_x5t_s256,
            client_attestation_jkt: row.client_attestation_jkt,
            revoked_at: row.revoked_at,
            reuse_detected_at: row.reuse_detected_at,
        },
        &contract,
    )
    .map(Some)
    .map_err(|error| diesel::result::Error::DeserializationError(error.to_string().into()))
}

#[derive(diesel::QueryableByName)]
struct LostResponseJoinRow {
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    token_family_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    user_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Binary)]
    contract_blake3: Vec<u8>,
    #[diesel(sql_type = sql_types::Uuid)]
    current_member_id: Uuid,
    #[diesel(sql_type = sql_types::Binary)]
    current_token_blake3: Vec<u8>,
    #[diesel(sql_type = sql_types::Jsonb)]
    current_audience: Value,
    #[diesel(sql_type = sql_types::Timestamptz)]
    current_issued_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    current_expires_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Varchar>)]
    current_id_token_sid: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Varchar>)]
    dpop_jkt: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Varchar>)]
    mtls_x5t_s256: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Varchar>)]
    client_attestation_jkt: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    reuse_detected_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Jsonb>)]
    contract: Option<Value>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    spent_at: DateTime<Utc>,
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/tokens.rs"]
mod tests;
