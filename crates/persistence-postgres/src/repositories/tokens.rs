use chrono::{DateTime, Duration, Utc};
use diesel::{
    ExpressionMethods, OptionalExtension, QueryDsl, QueryableByName, SelectableHelper, sql_query,
    sql_types,
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE, PreparedTokenSubject, RefreshContract, RefreshToken,
    RefreshTokenCommit, RefreshTokenPersistResult, refresh_spent_proof_limit,
};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::SecurityAuditEvent;
use nazo_resource_server::{
    AccessTokenRevocationLookup, ProtectedResourceDependencyError, ResourceServerPortFuture,
    RevocationLookupKey,
};
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

/// Adapter-local lookup after the public string tenant boundary is parsed.
pub(super) struct TypedRevocationLookupKey<'a> {
    pub(super) tenant_id: Uuid,
    pub(super) jti: &'a str,
    pub(super) client_id: &'a str,
    pub(super) subject: &'a str,
    pub(super) user_id: Option<&'a str>,
    pub(super) subject_type: Option<&'a str>,
    pub(super) client_epoch: Option<i64>,
    pub(super) user_epoch: Option<i64>,
}

#[derive(Clone)]
pub struct TokenRepository {
    pool: DbPool,
}

/// Durable outcome of one post-restore invalidation. The operation id and
/// request hash make a crash/retry return the original authority boundary
/// rather than revoking a newly issued token set a second time.
pub use nazo_persistence::RecoveryInvalidation;

enum RecoveryInvalidationFailure {
    Query(diesel::result::Error),
    Conflict,
    UnsupportedCoverage,
}

impl From<diesel::result::Error> for RecoveryInvalidationFailure {
    fn from(error: diesel::result::Error) -> Self {
        Self::Query(error)
    }
}

impl TokenRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Atomically revoke every unrevoked refresh family in the restored database.
    /// Ingress and old writers must remain stopped until the returned boundary;
    /// this transaction does not fence later family insertion.
    pub async fn invalidate_after_restore(
        &self,
        operation_id: Uuid,
        request_hash: &str,
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
        // Keep the existing system namespace and advisory key shared with old writers.
        let tenant_id = nazo_identity::TenantContext::default_system()
            .tenant_id
            .as_uuid();
        let mut connection = self.connection().await?;
        connection
            .transaction::<RecoveryInvalidation, RecoveryInvalidationFailure, _>(async |connection| {
                lock_recovery_invalidation_scope(connection, tenant_id).await?;
                if let Some((
                    stored_hash,
                    stored_tenant,
                    stored_epoch,
                    stored_not_before,
                    stored_count,
                    coverage_version,
                )) = recovery_invalidations::table
                    .filter(recovery_invalidations::operation_id.eq(operation_id))
                    .select((
                        recovery_invalidations::request_hash,
                        recovery_invalidations::tenant_id,
                        recovery_invalidations::state_epoch,
                        recovery_invalidations::not_before,
                        recovery_invalidations::revoked_refresh_tokens,
                        recovery_invalidations::coverage_version,
                    ))
                    .first::<(String, Uuid, Uuid, DateTime<Utc>, i64, i16)>(connection)
                    .await
                    .optional()?
                {
                    if stored_hash != request_hash
                        || stored_tenant != tenant_id
                        || stored_epoch != state_epoch
                    {
                        return Err(RecoveryInvalidationFailure::Conflict);
                    }
                    if coverage_version != 1 {
                        return Err(RecoveryInvalidationFailure::UnsupportedCoverage);
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
                    return Err(RecoveryInvalidationFailure::Conflict);
                }
                let revoked = diesel::update(
                    oauth_refresh_families::table.filter(oauth_refresh_families::revoked_at.is_null()),
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
                        recovery_invalidations::coverage_version.eq(1_i16),
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
            .map_err(|error| match error {
                RecoveryInvalidationFailure::Conflict => RepositoryError::Conflict,
                RecoveryInvalidationFailure::UnsupportedCoverage => RepositoryError::Consistency(
                    "recovery receipt has unsupported coverage; a new signed operation and epoch are required".to_owned(),
                ),
                RecoveryInvalidationFailure::Query(error) => map_error(error),
            })
    }

    pub async fn by_raw_refresh_token(
        &self,
        tenant_id: Uuid,
        raw_token: &str,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        let digest = blake3::hash(raw_token.as_bytes());
        let mut connection = self.connection().await?;
        let presentation =
            lookup_refresh_token(&mut connection, tenant_id, digest.as_bytes(), None)
                .await
                .map_err(map_error)?;
        drop(connection);
        presentation
            .map(|row| {
                row.into_presentation(None)
                    .map(|snapshot| snapshot.presented)
            })
            .transpose()
            .map_err(map_error)
    }

    pub(super) async fn refresh_token_snapshot(
        &self,
        tenant_id: Uuid,
        raw_token: &str,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
        prepare_oidc_subject: bool,
    ) -> Result<Option<RefreshPresentation>, RepositoryError> {
        let digest = blake3::hash(raw_token.as_bytes());
        let mut connection = self.connection().await?;
        let row = lookup_refresh_token(
            &mut connection,
            tenant_id,
            digest.as_bytes(),
            prepare_oidc_subject.then_some(client_id),
        )
        .await
        .map_err(map_error)?;
        drop(connection);
        row.map(|row| row.into_presentation(Some((client_id, retry_started_at))))
            .transpose()
            .map_err(map_error)
    }

    /// Apply a refresh-token mutation inside a caller-owned transaction.
    ///
    /// This helper deliberately performs no pool acquisition and never starts
    /// a nested transaction. The caller's transaction therefore owns the
    /// refresh-family locks, rotation, capacity eviction and any resulting
    /// compromise decision.
    pub(super) async fn persist_refresh_token_on_connection(
        connection: &mut AsyncPgConnection,
        refresh: &RefreshTokenCommit,
        client_type: &str,
        issuance_id: Uuid,
        prepared_contract: Option<&PreparedRefreshContract>,
        native_sso_source: Option<&nazo_auth::NativeSsoSourceFence>,
    ) -> Result<(RefreshTokenPersistResult, Option<RetiredNativeSsoSource>), RepositoryError> {
        persist_refresh_token_inner(
            connection,
            refresh,
            client_type,
            issuance_id,
            prepared_contract,
            native_sso_source,
        )
        .await
        .map_err(map_error)
    }

    pub async fn inspect_lost_response_successor(
        &self,
        token: &RefreshToken,
        client_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        if token.dpop_jkt.is_none() && token.mtls_x5t_s256.is_none() {
            return Ok(None);
        }
        let mut connection = self.connection().await?;
        let row = load_lost_response_successor(&mut connection, token, client_id, now)
            .await
            .map_err(map_error)?;
        drop(connection);
        let Some(row) = row else {
            return Ok(None);
        };
        token_from_lost_response_successor(row, token, now).map_err(map_error)
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

    /// One indexed state read for both individual and principal-wide revocation.
    /// Epoch-less tokens retain the previous JTI contract during migration.
    pub async fn access_token_state_revoked(
        &self,
        key: RevocationLookupKey<'_>,
    ) -> Result<bool, RepositoryError> {
        let tenant_id = Uuid::parse_str(key.tenant_id)
            .map_err(|_| RepositoryError::Consistency("invalid token tenant".to_owned()))?;
        self.access_token_state_revoked_typed(TypedRevocationLookupKey {
            tenant_id,
            jti: key.jti,
            client_id: key.client_id,
            subject: key.subject,
            user_id: key.user_id,
            subject_type: key.subject_type,
            client_epoch: key.client_epoch,
            user_epoch: key.user_epoch,
        })
        .await
    }

    pub(super) async fn access_token_state_revoked_typed(
        &self,
        key: TypedRevocationLookupKey<'_>,
    ) -> Result<bool, RepositoryError> {
        let tenant_id = key.tenant_id;
        let Some(client_epoch) = key.client_epoch else {
            if key.user_epoch.is_some() {
                return Ok(true);
            }
            return self.access_token_revoked(tenant_id, key.jti).await;
        };
        if client_epoch < 0 || key.user_epoch.is_some_and(|value| value < 0) {
            return Ok(true);
        }
        let user_id = match key.user_id {
            Some(value) => match Uuid::parse_str(value) {
                Ok(value) => Some(value),
                Err(_) => return Ok(true),
            },
            None => None,
        };
        #[derive(diesel::QueryableByName)]
        struct State {
            #[diesel(sql_type = sql_types::Bool)]
            revoked: bool,
        }
        let mut connection = self.connection().await?;
        let state = sql_query(
            "SELECT EXISTS (SELECT 1 FROM access_token_revocations WHERE tenant_id = $1 AND access_token_jti_blake3 = $2) \
             OR NOT EXISTS ( \
               SELECT 1 FROM oauth_clients c \
               LEFT JOIN users u ON $7 = 'user' AND u.tenant_id = c.tenant_id AND u.id = COALESCE($6::uuid, \
                 (SELECT b.user_id FROM oauth_subject_bindings b WHERE b.tenant_id = $1 AND b.subject = $5)) \
               WHERE c.tenant_id = $1 AND c.client_id = $3 AND c.is_active AND c.access_token_epoch = $4 \
                 AND (($7 = 'client' AND $6::uuid IS NULL AND $8::bigint IS NULL) \
                   OR ($7 = 'user' AND u.is_active AND u.access_token_epoch = $8)) \
             ) AS revoked"
        ).bind::<sql_types::Uuid, _>(tenant_id)
            .bind::<sql_types::Text, _>(blake3_hex(key.jti))
            .bind::<sql_types::Text, _>(key.client_id)
            .bind::<sql_types::BigInt, _>(client_epoch)
            .bind::<sql_types::Text, _>(key.subject)
            .bind::<sql_types::Nullable<sql_types::Uuid>, _>(user_id)
            .bind::<sql_types::Nullable<sql_types::Text>, _>(key.subject_type)
            .bind::<sql_types::Nullable<sql_types::BigInt>, _>(key.user_epoch)
            .get_result::<State>(&mut connection).await.map_err(map_error)?;
        Ok(state.revoked)
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
        self.revoke_for_client_with_audit(tenant_id, client_id, raw_token, access_token, None)
            .await
    }

    pub(crate) async fn revoke_for_client_with_audit(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        raw_token: &str,
        access_token: Option<&nazo_auth::AccessTokenRevocation>,
        audit_context: Option<(&str, &str)>,
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
        let mut guard = crate::pool::DiscardOnDrop(Some(self.connection().await?));
        let result = guard
            .connection()
            .transaction::<usize, diesel::result::Error, _>(async |connection| {
                // A verified access token remains access-only authority, with
                // zero refresh-member count; do not reinterpret its bytes as RT.
                let family_id = if access_token.is_none() {
                    refresh_family_id_for_digest(
                        connection,
                        tenant_id,
                        client_id,
                        raw_token_blake3.as_bytes(),
                    )
                    .await?
                } else {
                    None
                };
                let updated = if let Some(family_id) = family_id {
                    lock_refresh_family(connection, family_id).await?;
                    diesel::update(
                        oauth_refresh_families::table
                            .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
                            .filter(oauth_refresh_families::client_id.eq(client_id))
                            .filter(oauth_refresh_families::token_family_id.eq(family_id))
                            .filter(oauth_refresh_families::revoked_at.is_null()),
                    )
                    .set(oauth_refresh_families::revoked_at.eq(diesel::dsl::now))
                    .execute(connection)
                    .await?
                } else {
                    if let Some(new_revocation) = new_revocation {
                        upsert_access_token_revocations(connection, &[new_revocation]).await?;
                    }
                    0
                };
                if let Some((client_public_id, source_ip_hash)) = audit_context {
                    let event = SecurityAuditEvent {
                        event_id: Uuid::now_v7(),
                        event_type: "token_revoked".to_owned(),
                        event_category: "token_lifecycle".to_owned(),
                        payload: serde_json::json!({
                            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                            "event_category": "token_lifecycle", "tenant_id": tenant_id,
                            "client_id": client_public_id,
                            "token_hash": raw_token_blake3.to_hex().to_string(),
                            "updated": updated, "source_ip_hash": source_ip_hash,
                        }),
                        occurred_at: Utc::now(),
                    };
                    append_fresh_security_audit_on_connection(connection, &event).await?;
                }
                Ok(updated)
            })
            .await
            .map_err(map_error);
        if result.is_ok() {
            guard.return_to_pool();
        }
        result
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
        state_epoch: Uuid,
        not_before: DateTime<Utc>,
        completed_at: DateTime<Utc>,
    ) -> nazo_persistence::OperatorPersistenceFuture<'a, RecoveryInvalidation> {
        Box::pin(async move {
            TokenRepository::invalidate_after_restore(
                self,
                operation_id,
                request_hash,
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
            Uuid::parse_str(key.tenant_id)
                .map_err(|_| ProtectedResourceDependencyError::InvalidTenantBoundary)?;
            self.access_token_state_revoked(key)
                .await
                .map_err(|_| ProtectedResourceDependencyError::RevocationLookupUnavailable)
        })
    }
}

fn validate_refresh_commit(refresh: &RefreshTokenCommit) -> Result<(), RepositoryError> {
    let contract = refresh.contract();
    let valid_audiences = |values: &[String]| {
        !values.is_empty() && values.iter().all(|value| !value.trim().is_empty())
    };
    if !contract.authentication_context.is_well_formed()
        || contract.subject.trim().is_empty()
        || !valid_audiences(&contract.audiences)
        || contract.authentication_context.nonce.is_some()
        || contract.authentication_context.id_token_sid.is_some()
    {
        return Err(RepositoryError::Consistency(
            "refresh token requires a complete immutable authentication contract".to_owned(),
        ));
    }
    match refresh {
        RefreshTokenCommit::IssueNew { token, contract } => {
            if token.rotated_from_id.is_some()
                || token.lost_response_retry.is_some()
                || token.audiences != contract.audiences
            {
                return Err(RepositoryError::Consistency(
                    "new refresh family must retain the complete original grant".to_owned(),
                ));
            }
        }
        RefreshTokenCommit::UseExisting {
            authority,
            rotation,
        } => {
            if authority.family_id.is_nil()
                || authority.member_id.is_nil()
                || !valid_audiences(&authority.current_audiences)
                || !nazo_auth::is_subset(&authority.current_audiences, &contract.audiences)
            {
                return Err(RepositoryError::Consistency(
                    "refresh source audience exceeds its original grant".to_owned(),
                ));
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
                return Err(RepositoryError::Consistency(
                    "refresh replacement does not preserve its source authority".to_owned(),
                ));
            }
        }
    }
    if let Some(token) = refresh.token()
        && (token.family_id.is_nil()
            || token.member_id.is_nil()
            || token.raw_token.is_empty()
            || !valid_audiences(&token.audiences)
            || contract.authentication_context.auth_time > token.issued_at.timestamp()
            || token.expires_at <= token.issued_at)
    {
        return Err(RepositoryError::Consistency(
            "refresh token requires a complete current authentication contract".to_owned(),
        ));
    }
    Ok(())
}

fn persisted_contract(contract: &RefreshContract) -> Result<(Vec<u8>, Value), RepositoryError> {
    let value = serde_json::to_value(contract).map_err(|error| {
        RepositoryError::Consistency(format!("refresh contract could not be serialized: {error}"))
    })?;
    Ok((contract.blake3_digest().to_vec(), value))
}

/// Only new families serialize/hash their original contract before borrowing
/// a connection. Existing families keep their persisted key and revalidate
/// the original content in the locked source query; there is no rekeying.
#[derive(Debug)]
pub(crate) struct PreparedRefreshContract {
    contract_blake3: Vec<u8>,
    contract_value: Value,
}

pub(crate) fn prepare_refresh_contract(
    refresh: &RefreshTokenCommit,
) -> Result<Option<PreparedRefreshContract>, RepositoryError> {
    validate_refresh_commit(refresh)?;
    let RefreshTokenCommit::IssueNew { contract, .. } = refresh else {
        return Ok(None);
    };
    let (contract_blake3, contract_value) = persisted_contract(contract)?;
    Ok(Some(PreparedRefreshContract {
        contract_blake3,
        contract_value,
    }))
}

fn parse_contract(value: Value) -> Result<RefreshContract, RepositoryError> {
    serde_json::from_value::<RefreshContract>(value).map_err(|error| {
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
    contract: RefreshContract,
) -> Result<RefreshToken, RepositoryError> {
    let mut context = contract.authentication_context;
    context.id_token_sid = family.current_id_token_sid;
    Ok(RefreshToken {
        id: family.current_member_id,
        token_blake3: digest32(&family.current_token_blake3)?,
        tenant_id: family.tenant_id,
        token_family_id: family.token_family_id,
        client_id: family.client_id,
        user_id: family.user_id,
        contract_key: digest32(&family.contract_blake3)?,
        contract_audiences: contract.audiences,
        scopes: Value::Array(contract.scopes.into_iter().map(Value::String).collect()),
        audience: family.current_audience,
        authorization_details: contract.authorization_details,
        issued_at: family.current_issued_at,
        expires_at: family.current_expires_at,
        revoked_at: family.revoked_at,
        subject: contract.subject,
        dpop_jkt: family.dpop_jkt,
        mtls_x5t_s256: family.mtls_x5t_s256,
        client_attestation_jkt: family.client_attestation_jkt,
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
    contract: RefreshContract,
) -> Result<RefreshToken, RepositoryError> {
    let mut context = contract.authentication_context;
    context.id_token_sid = family.current_id_token_sid;
    Ok(RefreshToken {
        id: spent.member_id,
        token_blake3: digest32(&spent.refresh_token_blake3)?,
        tenant_id: family.tenant_id,
        token_family_id: family.token_family_id,
        client_id: family.client_id,
        user_id: family.user_id,
        contract_key: digest32(&family.contract_blake3)?,
        contract_audiences: contract.audiences.clone(),
        scopes: Value::Array(contract.scopes.into_iter().map(Value::String).collect()),
        audience: Value::Array(contract.audiences.into_iter().map(Value::String).collect()),
        authorization_details: contract.authorization_details,
        // The member's own issuance time is not retained; `spent_at` is the
        // last instant the member was the family's current token.
        issued_at: spent.spent_at,
        expires_at: spent.expires_at,
        revoked_at: Some(spent.spent_at),
        subject: contract.subject,
        dpop_jkt: family.dpop_jkt,
        mtls_x5t_s256: family.mtls_x5t_s256,
        client_attestation_jkt: family.client_attestation_jkt,
        authentication_context: context,
    })
}

fn deserialization_error(error: RepositoryError) -> diesel::result::Error {
    diesel::result::Error::DeserializationError(error.to_string().into())
}

fn require_contract(row: Option<RefreshContractRow>) -> diesel::QueryResult<RefreshContract> {
    let row = row.ok_or_else(|| {
        diesel::result::Error::DeserializationError(
            "refresh family references a missing contract".into(),
        )
    })?;
    parse_contract(row.contract).map_err(deserialization_error)
}

const REFRESH_LOOKUP_PREFIX: &str = r#"WITH presentation AS (
             SELECT tenant_id, token_family_id, 0 AS priority, NULL::bytea AS spent_digest, NULL::uuid AS spent_member_id, NULL::timestamptz AS spent_at, NULL::timestamptz AS spent_expires_at, NULL::uuid AS successor_member_id FROM oauth_refresh_families WHERE tenant_id = "#;

const REFRESH_LOOKUP_AFTER_TENANT: &str = r#" AND current_token_blake3 = "#;

const PLAIN_REFRESH_LOOKUP_SUFFIX: &str = r#"
             UNION ALL SELECT tenant_id, token_family_id, 1, refresh_token_blake3, member_id, spent_at, expires_at, successor_member_id FROM oauth_refresh_spent_tokens WHERE tenant_id = $1 AND refresh_token_blake3 = $2
         ), selected AS (SELECT * FROM presentation ORDER BY priority LIMIT 1)
         SELECT f.*, c.contract, p.spent_digest, p.spent_member_id, p.spent_at, p.spent_expires_at, p.successor_member_id, NULL::jsonb AS prepared_subject
         FROM selected AS p
         JOIN oauth_refresh_families AS f ON f.tenant_id = p.tenant_id AND f.token_family_id = p.token_family_id
         LEFT JOIN oauth_refresh_contracts AS c ON c.tenant_id = f.tenant_id AND c.contract_blake3 = f.contract_blake3 "#;

const PREPARED_REFRESH_LOOKUP_BEFORE_CLIENT: &str = concat!(
    r#"
             UNION ALL SELECT tenant_id, token_family_id, 1, refresh_token_blake3, member_id, spent_at, expires_at, successor_member_id FROM oauth_refresh_spent_tokens WHERE tenant_id = $1 AND refresh_token_blake3 = $2
         ), selected AS (SELECT * FROM presentation ORDER BY priority LIMIT 1)
         SELECT f.*, c.contract, p.spent_digest, p.spent_member_id, p.spent_at, p.spent_expires_at, p.successor_member_id, CASE WHEN profile.id IS NULL THEN NULL::jsonb ELSE to_jsonb(profile) END AS prepared_subject
         FROM selected AS p
         JOIN oauth_refresh_families AS f ON f.tenant_id = p.tenant_id AND f.token_family_id = p.token_family_id
         LEFT JOIN oauth_refresh_contracts AS c ON c.tenant_id = f.tenant_id AND c.contract_blake3 = f.contract_blake3"#,
    " ",
    r#"
         LEFT JOIN LATERAL (
             SELECT u.id, u.tenant_id, u.realm_id, u.organization_id,
                    u.username, u.email, u.is_active, u.updated_at,
                    u.email_verified, u.display_name, u.avatar_url, u.given_name,
                    u.family_name, u.middle_name, u.nickname, u.profile_url,
                    u.website_url, u.gender, u.birthdate, u.zoneinfo,
                    u.locale, u.role, u.admin_level, u.address_formatted,
                    u.address_street_address, u.address_locality, u.address_region, u.address_postal_code,
                    u.address_country, u.phone_number, u.phone_number_verified,
                    u.access_token_epoch AS user_epoch,
                    CASE WHEN c.contract->>'subject' <> u.id::text THEN (
                        SELECT binding.user_id FROM oauth_subject_bindings AS binding
                        WHERE binding.tenant_id = f.tenant_id
                          AND binding.subject = c.contract->>'subject'
                    ) ELSE NULL::uuid END AS bound_user
             FROM users AS u
             WHERE p.spent_digest IS NULL AND f.client_id = "#
);

const PREPARED_REFRESH_LOOKUP_AFTER_CLIENT: &str = r#"
               AND f.revoked_at IS NULL AND f.reuse_detected_at IS NULL
               AND f.current_expires_at > CURRENT_TIMESTAMP
               AND c.contract->'scopes' ? 'openid'
               AND u.tenant_id = f.tenant_id AND u.id = f.user_id
               AND u.is_active
         ) AS profile ON true"#;

// These two private query types have fixed SQL and distinct cache identities.
// Only bound values vary; every execution still reads one fresh MVCC snapshot.
// Raw SqlQuery disables statement caching even when its SQL text is constant.
struct PlainRefreshLookup<'a> {
    tenant_id: Uuid,
    digest: &'a [u8],
}

impl diesel::query_builder::QueryId for PlainRefreshLookup<'_> {
    type QueryId = PlainRefreshLookup<'static>;

    const HAS_STATIC_QUERY_ID: bool = true;
}

impl diesel::query_builder::Query for PlainRefreshLookup<'_> {
    type SqlType = sql_types::Untyped;
}

impl<Conn> diesel::RunQueryDsl<Conn> for PlainRefreshLookup<'_> {}

impl diesel::query_builder::QueryFragment<diesel::pg::Pg> for PlainRefreshLookup<'_> {
    fn walk_ast<'b>(
        &'b self,
        mut out: diesel::query_builder::AstPass<'_, 'b, diesel::pg::Pg>,
    ) -> diesel::QueryResult<()> {
        out.push_sql(REFRESH_LOOKUP_PREFIX);
        out.push_bind_param::<sql_types::Uuid, _>(&self.tenant_id)?;
        out.push_sql(REFRESH_LOOKUP_AFTER_TENANT);
        out.push_bind_param::<sql_types::Binary, _>(self.digest)?;
        out.push_sql(PLAIN_REFRESH_LOOKUP_SUFFIX);
        Ok(())
    }
}

struct PreparedRefreshLookup<'a> {
    tenant_id: Uuid,
    digest: &'a [u8],
    client_id: Uuid,
}

impl diesel::query_builder::QueryId for PreparedRefreshLookup<'_> {
    type QueryId = PreparedRefreshLookup<'static>;

    const HAS_STATIC_QUERY_ID: bool = true;
}

impl diesel::query_builder::Query for PreparedRefreshLookup<'_> {
    type SqlType = sql_types::Untyped;
}

impl<Conn> diesel::RunQueryDsl<Conn> for PreparedRefreshLookup<'_> {}

impl diesel::query_builder::QueryFragment<diesel::pg::Pg> for PreparedRefreshLookup<'_> {
    fn walk_ast<'b>(
        &'b self,
        mut out: diesel::query_builder::AstPass<'_, 'b, diesel::pg::Pg>,
    ) -> diesel::QueryResult<()> {
        out.push_sql(REFRESH_LOOKUP_PREFIX);
        out.push_bind_param::<sql_types::Uuid, _>(&self.tenant_id)?;
        out.push_sql(REFRESH_LOOKUP_AFTER_TENANT);
        out.push_bind_param::<sql_types::Binary, _>(self.digest)?;
        out.push_sql(PREPARED_REFRESH_LOOKUP_BEFORE_CLIENT);
        out.push_bind_param::<sql_types::Uuid, _>(&self.client_id)?;
        out.push_sql(PREPARED_REFRESH_LOOKUP_AFTER_CLIENT);
        Ok(())
    }
}

/// Current presentation takes precedence over a spent proof in the same
/// statement snapshot. LEFT JOIN keeps missing contracts observable. Family
/// facts and the direct successor edge come from this statement, never a second
/// pool checkout; no lock or authorization is implied by this read.
async fn lookup_refresh_token(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    digest: &[u8],
    profile_client_id: Option<Uuid>,
) -> diesel::QueryResult<Option<RefreshPresentationRow>> {
    let row = if let Some(client_id) = profile_client_id {
        PreparedRefreshLookup {
            tenant_id,
            digest,
            client_id,
        }
        .get_result::<RefreshPresentationRow>(connection)
        .await
    } else {
        PlainRefreshLookup { tenant_id, digest }
            .get_result::<RefreshPresentationRow>(connection)
            .await
    };
    row.optional()
}

#[derive(diesel::QueryableByName)]
struct RefreshPresentationRow {
    #[diesel(embed)]
    family: RefreshFamilyRow,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Jsonb>)]
    contract: Option<Value>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    spent_digest: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    spent_member_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    spent_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    spent_expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    successor_member_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Jsonb>)]
    prepared_subject: Option<Value>,
}

pub(super) struct RefreshPresentation {
    pub(super) presented: RefreshToken,
    pub(super) successor: Result<Option<RefreshToken>, RepositoryError>,
    pub(super) prepared_subject: Option<PreparedTokenSubject>,
}

impl RefreshPresentationRow {
    fn into_presentation(
        self,
        retry: Option<(Uuid, DateTime<Utc>)>,
    ) -> diesel::QueryResult<RefreshPresentation> {
        let prepared_subject = self.prepared_subject;
        let contract = require_contract(
            self.contract
                .map(|contract| RefreshContractRow { contract }),
        )?;
        let (presented, successor) = match (
            self.spent_digest,
            self.spent_member_id,
            self.spent_at,
            self.spent_expires_at,
            self.successor_member_id,
        ) {
            (None, None, None, None, None) => (
                token_from_current(self.family, contract).map_err(deserialization_error)?,
                Ok(None),
            ),
            (
                Some(refresh_token_blake3),
                Some(member_id),
                Some(spent_at),
                Some(expires_at),
                Some(successor_member_id),
            ) => {
                let eligible = retry.is_some_and(|(client_id, now)| {
                    let elapsed = now.signed_duration_since(spent_at);
                    self.family.client_id == client_id
                        && (self.family.dpop_jkt.is_some() || self.family.mtls_x5t_s256.is_some())
                        && self.family.current_member_id == successor_member_id
                        && self.family.revoked_at.is_none()
                        && self.family.reuse_detected_at.is_none()
                        && self.family.current_expires_at > now
                        && elapsed >= Duration::zero()
                        && elapsed <= Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS)
                });
                // Preserve dependency-error ordering: candidate projection errors
                // are returned only after the application authenticates the holder.
                let successor = if eligible {
                    token_from_current(self.family.clone(), contract.clone()).map(Some)
                } else {
                    Ok(None)
                };
                let presented = token_from_spent(
                    SpentRefreshTokenRow {
                        refresh_token_blake3,
                        member_id,
                        spent_at,
                        expires_at,
                    },
                    self.family,
                    contract,
                )
                .map_err(deserialization_error)?;
                (presented, successor)
            }
            _ => {
                return Err(diesel::result::Error::DeserializationError(
                    "refresh presentation has incomplete spent proof".into(),
                ));
            }
        };
        let prepared_subject = prepare_refresh_subject(prepared_subject, &presented);
        Ok(RefreshPresentation {
            presented,
            successor,
            prepared_subject,
        })
    }
}

#[derive(serde::Deserialize)]
struct RefreshSubjectProjection {
    #[serde(flatten)]
    claims: crate::rows::identity::SubjectClaimsRow,
    user_epoch: i64,
    bound_user: Option<Uuid>,
}

fn prepare_refresh_subject(
    projection: Option<Value>,
    token: &RefreshToken,
) -> Option<PreparedTokenSubject> {
    let projection: RefreshSubjectProjection = serde_json::from_value(projection?).ok()?;
    if projection.claims.tenant_id != token.tenant_id
        || Some(projection.claims.id) != token.user_id
        || projection.user_epoch < 0
    {
        return None;
    }
    // Failures do not advance an error ahead of holder/scope validation:
    // absence of successful preparation retains the original late claims read.
    let (claims, user_epoch, subject_bound) = super::users::prepare_subject_claims(
        projection.claims,
        projection.user_epoch,
        projection.bound_user,
    )
    .ok()?;
    Some(PreparedTokenSubject {
        tenant_id: token.tenant_id,
        claims,
        user_epoch,
        token_subject: token.subject.clone(),
        subject_bound,
    })
}

struct LockedRefreshFamily {
    family: RefreshFamilyRow,
    contract: Option<Value>,
}

/// One locked family read, with the immutable payload checked independently
/// of its stable content key. Both row-lock modes fence direct family UPDATE
/// writers which do not take the advisory lock; Preserve readers may overlap.
async fn load_family(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    family_id: Uuid,
    preserve: bool,
) -> diesel::QueryResult<Option<LockedRefreshFamily>> {
    // Keep the immutable contract as a correlated scalar subquery. The row
    // lock applies only to the outer family row, so different families that
    // reference one contract do not contend with each other.
    let contract = oauth_refresh_contracts::table
        .select(oauth_refresh_contracts::contract)
        .filter(oauth_refresh_contracts::tenant_id.eq(oauth_refresh_families::tenant_id))
        .filter(
            oauth_refresh_contracts::contract_blake3.eq(oauth_refresh_families::contract_blake3),
        )
        .single_value();
    let query = oauth_refresh_families::table
        .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
        .filter(oauth_refresh_families::token_family_id.eq(family_id))
        .select((RefreshFamilyRow::as_select(), contract));
    let row = if preserve {
        query
            .for_share()
            .get_result::<(RefreshFamilyRow, Option<Value>)>(connection)
            .await
    } else {
        query
            .for_update()
            .get_result::<(RefreshFamilyRow, Option<Value>)>(connection)
            .await
    };
    row.optional()
        .map(|row| row.map(|(family, contract)| LockedRefreshFamily { family, contract }))
}

async fn persist_refresh_token_inner(
    connection: &mut AsyncPgConnection,
    refresh: &RefreshTokenCommit,
    client_type: &str,
    issuance_id: Uuid,
    prepared_contract: Option<&PreparedRefreshContract>,
    native_sso_source: Option<&nazo_auth::NativeSsoSourceFence>,
) -> diesel::QueryResult<(RefreshTokenPersistResult, Option<RetiredNativeSsoSource>)> {
    let (tenant_id, user_id, client_id, family_id) = match refresh {
        RefreshTokenCommit::IssueNew { token, .. } => (
            token.tenant_id,
            token.user_id,
            token.client_id,
            token.family_id,
        ),
        RefreshTokenCommit::UseExisting { authority, .. } => (
            authority.tenant_id,
            authority.user_id,
            authority.client_id,
            authority.family_id,
        ),
    };
    // Preserve owns no capacity mutation and never acquires scope after family.
    // Rotation and creation retain the established scope -> family order.
    if refresh.token().is_some() {
        lock_refresh_grant_scope(connection, tenant_id, user_id, client_id).await?;
    }
    let preserve = matches!(
        refresh,
        RefreshTokenCommit::UseExisting { rotation: None, .. }
    );
    if preserve {
        // Compatible readers still fence maintenance's exclusive try-lock:
        // an expiring source must be skipped, not stall the reclaim batch.
        sql_query("SELECT pg_advisory_xact_lock_shared($1)")
            .bind::<sql_types::BigInt, _>(refresh_family_lock_key(family_id))
            .execute(connection)
            .await?;
    } else {
        lock_refresh_family(connection, family_id).await?;
    }

    if let RefreshTokenCommit::UseExisting {
        authority,
        rotation,
    } = refresh
    {
        let Some(locked) = load_family(connection, tenant_id, family_id, preserve).await? else {
            return Ok((RefreshTokenPersistResult::InvalidSource, None));
        };
        let family = locked.family;
        // Read the clock only after all source locks have been acquired.
        let transition_at = Utc::now();
        if family.revoked_at.is_some()
            || family.reuse_detected_at.is_some()
            || family.current_expires_at <= transition_at
        {
            return Ok((RefreshTokenPersistResult::InvalidSource, None));
        }
        let contract = locked.contract.ok_or_else(|| {
            deserialization_error(RepositoryError::Consistency(
                "refresh family references a missing contract".to_owned(),
            ))
        })?;
        let contract = parse_contract(contract).map_err(deserialization_error)?;
        let source_matches = family.current_member_id == authority.member_id
            && family.current_token_blake3 == authority.token_blake3.as_slice()
            && family.client_id == authority.client_id
            && family.user_id == authority.user_id
            && family.contract_blake3 == authority.contract_key.as_slice()
            && contract == authority.contract
            && family.current_audience == serde_json::json!(authority.current_audiences)
            && family.current_id_token_sid == authority.id_token_sid
            && family.dpop_jkt == authority.dpop_jkt
            && family.mtls_x5t_s256 == authority.mtls_x5t_s256
            && family.client_attestation_jkt == authority.client_attestation_jkt;
        if !source_matches {
            if rotation.is_some() {
                compromise_family(connection, tenant_id, family_id).await?;
                return Ok((RefreshTokenPersistResult::RotationConflict, None));
            }
            return Ok((RefreshTokenPersistResult::InvalidSource, None));
        }
        let Some(token) = rotation.as_ref() else {
            return Ok((RefreshTokenPersistResult::Inserted, None));
        };
        let rotated_from_id = authority.member_id;
        let token_blake3 = blake3::hash(token.raw_token.as_bytes());
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
                return Ok((RefreshTokenPersistResult::RotationConflict, None));
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
                oauth_refresh_spent_tokens::spent_at.eq(transition_at),
                oauth_refresh_spent_tokens::expires_at.eq(family.current_expires_at),
            ))
            .execute(connection)
            .await?;
        // Core owns the retention policy. The client classification is locked
        // by the caller; the family bindings were read and checked above.
        // Never trim an unexpired unbound public proof merely by generation.
        if let Some(limit) = refresh_spent_proof_limit(
            client_type,
            family.dpop_jkt.as_deref(),
            family.mtls_x5t_s256.as_deref(),
        ) {
            sql_query(
                "DELETE FROM oauth_refresh_spent_tokens AS spent \
                 USING ( \
                     SELECT refresh_token_blake3 FROM oauth_refresh_spent_tokens \
                     WHERE tenant_id = $1 AND token_family_id = $2 \
                     ORDER BY spent_at DESC, member_id DESC \
                     OFFSET $3 \
                 ) AS excess \
                 WHERE spent.tenant_id = $1 AND spent.token_family_id = $2 \
                   AND spent.refresh_token_blake3 = excess.refresh_token_blake3",
            )
            .bind::<sql_types::Uuid, _>(token.tenant_id)
            .bind::<sql_types::Uuid, _>(token.family_id)
            .bind::<sql_types::BigInt, _>(limit)
            .execute(connection)
            .await?;
        }
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
            oauth_refresh_families::current_id_token_sid.eq(token.id_token_sid.clone()),
        ))
        .execute(connection)
        .await?;
        return Ok((RefreshTokenPersistResult::Inserted, None));
    }

    let RefreshTokenCommit::IssueNew { token, .. } = refresh else {
        unreachable!("existing refresh source returned above");
    };
    let prepared_contract = prepared_contract.ok_or_else(|| {
        deserialization_error(RepositoryError::Consistency(
            "new refresh family has no prepared contract".to_owned(),
        ))
    })?;
    let contract_blake3 = &prepared_contract.contract_blake3;
    let contract_value = &prepared_contract.contract_value;
    let token_blake3 = blake3::hash(token.raw_token.as_bytes());
    // New family issuance: a same-named family is a collision compromise,
    // then the (tenant, user, client) active-family cap retires the
    // deterministically oldest live families before the insert.
    // Only existence matters here. Do not fetch/decode the current member,
    // audience and sender bindings for a new family; rotation above still
    // reads those authoritative facts under the same locks.
    // Do not retain a named prepared plan for this miss-heavy probe. A plan
    // chosen while the family table is empty can keep a sequential scan as
    // issuance grows the table, until statistics invalidate it. SqlQuery is
    // uncached, so this primary-key lookup is planned against the current size.
    #[derive(diesel::QueryableByName)]
    struct FamilyPresence {
        #[diesel(sql_type = sql_types::Bool)]
        present: bool,
    }
    if sql_query(
        "SELECT EXISTS (SELECT 1 FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2) AS present",
    )
    .bind::<sql_types::Uuid, _>(token.tenant_id)
    .bind::<sql_types::Uuid, _>(token.family_id)
    .get_result::<FamilyPresence>(connection)
    .await?
    .present
    {
        compromise_family(connection, token.tenant_id, token.family_id).await?;
        return Ok((RefreshTokenPersistResult::RotationConflict, None));
    }
    let retired_native_source = if let Some(user_id) = token.user_id {
        retire_families_over_cap(
            connection,
            token.tenant_id,
            user_id,
            token.client_id,
            issuance_id,
            native_sso_source,
        )
        .await?
    } else {
        None
    };
    // One narrow call references the contract: an existing key is locked
    // FOR KEY SHARE inside this transaction (the family foreign key can
    // never dangle against a concurrent reclaim); a missing key takes the
    // validated INSERT and a genuine create/reclaim race retries locally.
    EnsureRefreshContractQuery {
        tenant_id: token.tenant_id,
        digest: contract_blake3,
        contract: contract_value,
    }
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
            oauth_refresh_families::current_id_token_sid.eq(token.id_token_sid.clone()),
            oauth_refresh_families::dpop_jkt.eq(token.dpop_jkt.clone()),
            oauth_refresh_families::mtls_x5t_s256.eq(token.mtls_x5t_s256.clone()),
            oauth_refresh_families::client_attestation_jkt.eq(token.client_attestation_jkt.clone()),
            oauth_refresh_families::created_at.eq(token.issued_at),
        ))
        .execute(connection)
        .await?;
    Ok((RefreshTokenPersistResult::Inserted, retired_native_source))
}

/// Locked facts from this transaction's successful source-family retirement.
#[derive(diesel::QueryableByName)]
pub(super) struct RetiredNativeSsoSource {
    #[diesel(sql_type = sql_types::Uuid)]
    pub tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    pub user_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Uuid)]
    pub token_family_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    pub source_client_id: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    pub expires_at: DateTime<Utc>,
}

/// Enforce `MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE` inside the grant-scope
/// advisory lock. Live families beyond the nine newest are retired oldest
/// first (by `current_issued_at`, then family id) by setting `revoked_at`;
/// each retirement emits a Required audit event in the same transaction.
/// Bounded maintenance later drains the family's spent proofs and row.
async fn retire_families_over_cap(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
    issuance_id: Uuid,
    native_sso_source: Option<&nazo_auth::NativeSsoSourceFence>,
) -> diesel::QueryResult<Option<RetiredNativeSsoSource>> {
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
    let mut retired_native_source = None;
    for victim in victims {
        lock_refresh_family(connection, victim.token_family_id).await?;
        let revoked = sql_query(
            "UPDATE oauth_refresh_families AS family SET revoked_at=CURRENT_TIMESTAMP \
             WHERE family.tenant_id=$1 AND family.token_family_id=$2 \
               AND family.revoked_at IS NULL AND family.reuse_detected_at IS NULL \
               AND family.current_expires_at>CURRENT_TIMESTAMP \
             RETURNING family.tenant_id, family.user_id, family.token_family_id, \
                       family.current_expires_at AS expires_at, \
                       (SELECT client.client_id FROM oauth_clients AS client \
                        WHERE client.tenant_id=family.tenant_id AND client.id=family.client_id) AS source_client_id",
        )
        .bind::<sql_types::Uuid,_>(tenant_id)
        .bind::<sql_types::Uuid,_>(victim.token_family_id)
        .get_result::<RetiredNativeSsoSource>(connection).await.optional()?;
        let Some(revoked) = revoked else {
            continue;
        };
        if native_sso_source.is_some_and(|source| source.family_id == revoked.token_family_id) {
            // The proof comes only from this successful UPDATE RETURNING; its
            // row lock is held until the destination transaction commits.
            retired_native_source = Some(revoked);
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
    Ok(retired_native_source)
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
async fn load_lost_response_successor(
    connection: &mut AsyncPgConnection,
    token: &RefreshToken,
    client_id: Uuid,
    now: DateTime<Utc>,
) -> diesel::QueryResult<Option<LostResponseJoinRow>> {
    sql_query(
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
    .optional()
}

fn token_from_lost_response_successor(
    row: LostResponseJoinRow,
    token: &RefreshToken,
    now: DateTime<Utc>,
) -> diesel::QueryResult<Option<RefreshToken>> {
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
    let contract = parse_contract(contract_json).map_err(deserialization_error)?;
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
        contract,
    )
    .map(Some)
    .map_err(deserialization_error)
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

// Fixed SQL and bind types give the existing per-connection statement cache a stable identity.
struct EnsureRefreshContractQuery<'a> {
    tenant_id: Uuid,
    digest: &'a [u8],
    contract: &'a serde_json::Value,
}
impl diesel::query_builder::QueryId for EnsureRefreshContractQuery<'_> {
    type QueryId = EnsureRefreshContractQuery<'static>;
    const HAS_STATIC_QUERY_ID: bool = true;
}
impl diesel::query_builder::Query for EnsureRefreshContractQuery<'_> {
    type SqlType = diesel::sql_types::Untyped;
}
impl<Conn> diesel::RunQueryDsl<Conn> for EnsureRefreshContractQuery<'_> {}
impl diesel::query_builder::QueryFragment<diesel::pg::Pg> for EnsureRefreshContractQuery<'_> {
    fn walk_ast<'b>(
        &'b self,
        mut out: diesel::query_builder::AstPass<'_, 'b, diesel::pg::Pg>,
    ) -> diesel::QueryResult<()> {
        out.push_sql("SELECT public.nazo_oauth_refresh_contract_ensure(");
        out.push_bind_param::<diesel::sql_types::Uuid, _>(&self.tenant_id)?;
        out.push_sql(", ");
        out.push_bind_param::<diesel::sql_types::Binary, _>(self.digest)?;
        out.push_sql(", ");
        out.push_bind_param::<diesel::sql_types::Jsonb, _>(self.contract)?;
        out.push_sql(")");
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/tokens.rs"]
mod tests;
