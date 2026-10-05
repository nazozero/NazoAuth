use chrono::{DateTime, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, NullableExpressionMethods,
    OptionalExtension, QueryDsl, QueryableByName, SelectableHelper, sql_query, sql_types,
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken, RefreshToken,
    RefreshTokenCommit, RefreshTokenPersistResult, SingleUseRedemption, TokenFuture,
    TokenIssuanceMode, TokenPortError, TokenRepositoryPort, TokenRevocation, UserinfoSnapshot,
};
use nazo_identity::{TenantId, UserId, ports::RepositoryError};
use nazo_persistence::SecurityAuditEvent;
use nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS;
use uuid::Uuid;

use crate::{
    DbPool, get_conn,
    pool::DiscardOnDrop,
    schema::{oauth_clients, oauth_subject_bindings, oauth_token_issuances, users},
};

use super::{
    AuthorizationRepository, TokenRepository, UserRepository,
    access_token_revocation::{NewAccessTokenRevocation, upsert_access_token_revocations},
    audit_ledger::append_fresh_security_audit_on_connection,
    clients::OAuthClientRecord,
    tokens::prepare_refresh_contract,
};
use crate::{convert::identity, rows::identity::SubjectClaimsRow};

#[derive(QueryableByName)]
struct OwnedAccessTokenRow {
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    access_token_jti: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

pub(crate) async fn revoke_access_tokens_for_owner_on_connection(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    client_id: Option<Uuid>,
    user_id: Option<Uuid>,
) -> Result<usize, diesel::result::Error> {
    debug_assert!(client_id.is_some() || user_id.is_some());
    let now = Utc::now();
    // Both sources store the full retention deadline (exp + maximum verifier
    // clock skew) so the revocation fact outlives every still-acceptable
    // presentation of the revoked token.
    sql_query(
        "DECLARE nazo_owner_token_revocations NO SCROLL CURSOR WITHOUT HOLD FOR \
         SELECT issuance.client_id, issuance.access_token_jti, \
                issuance.access_token_expires_at + $5 * interval '1 second' AS expires_at \
         FROM oauth_token_issuances AS issuance \
         WHERE issuance.tenant_id = $1 AND NOT issuance.principal_epoch_bound \
           AND issuance.access_token_expires_at > $4 - $5 * interval '1 second' \
           AND ($2::uuid IS NULL OR issuance.client_id = $2) \
           AND ($3::uuid IS NULL OR issuance.user_id = $3) \
         UNION ALL \
         SELECT client.id AS client_id, grant_row.token_id::text AS access_token_jti, \
                grant_row.expires_at + $5 * interval '1 second' AS expires_at \
         FROM openid4vci_access_grants AS grant_row \
         JOIN oauth_clients AS client ON client.tenant_id = grant_row.tenant_id AND client.client_id = grant_row.client_id \
         WHERE grant_row.tenant_id = $1 AND grant_row.revoked_at IS NULL AND grant_row.expires_at > $4 - $5 * interval '1 second' \
           AND ($2::uuid IS NULL OR client.id = $2) \
           AND ($3::uuid IS NULL OR grant_row.subject_id = $3)",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(client_id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(user_id)
    .bind::<sql_types::Timestamptz, _>(now)
    .bind::<sql_types::Integer, _>(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS as i32)
    .execute(connection)
    .await?;
    let mut affected = 0;
    loop {
        let rows = sql_query("FETCH FORWARD 512 FROM nazo_owner_token_revocations")
            .load::<OwnedAccessTokenRow>(connection)
            .await?;
        if rows.is_empty() {
            break;
        }
        // A single INSERT ... ON CONFLICT command must not touch the same
        // authority key twice; deduplicate inside the batch, keeping the
        // longest deadline and rejecting contradictory ownership.
        let mut deduplicated = std::collections::BTreeMap::new();
        for row in rows {
            let jti_digest = blake3::hash(row.access_token_jti.as_bytes())
                .to_hex()
                .to_string();
            let key = (tenant_id, jti_digest.clone());
            match deduplicated.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(NewAccessTokenRevocation {
                        id: Uuid::now_v7(),
                        access_token_jti_blake3: jti_digest,
                        client_id: row.client_id,
                        tenant_id,
                        revoked_at: now,
                        expires_at: row.expires_at,
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let existing: &mut NewAccessTokenRevocation = entry.get_mut();
                    if existing.client_id != row.client_id {
                        return Err(diesel::result::Error::DeserializationError(Box::new(
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "conflicting access-token revocation ownership",
                            ),
                        )));
                    }
                    if row.expires_at > existing.expires_at {
                        existing.expires_at = row.expires_at;
                    }
                }
            }
        }
        let revocations: Vec<NewAccessTokenRevocation> = deduplicated.into_values().collect();
        affected += upsert_access_token_revocations(connection, &revocations).await?;
    }
    sql_query("CLOSE nazo_owner_token_revocations")
        .execute(connection)
        .await?;
    sql_query(
        "UPDATE openid4vci_access_grants AS grant_row SET revoked_at = $4 \
         FROM oauth_clients AS client \
         WHERE client.tenant_id = grant_row.tenant_id AND client.client_id = grant_row.client_id \
           AND grant_row.tenant_id = $1 AND grant_row.revoked_at IS NULL \
           AND ($2::uuid IS NULL OR client.id = $2) \
           AND ($3::uuid IS NULL OR grant_row.subject_id = $3)",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(client_id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(user_id)
    .bind::<sql_types::Timestamptz, _>(now)
    .execute(connection)
    .await?;
    Ok(affected)
}

/// PostgreSQL transaction boundary used by authorization-code and refresh-token issuance.
#[derive(Clone)]
pub struct TokenIssuanceRepository {
    pool: DbPool,
    tokens: TokenRepository,
    authorization: AuthorizationRepository,
    users: UserRepository,
}

impl TokenIssuanceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool: pool.clone(),
            tokens: TokenRepository::new(pool.clone()),
            authorization: AuthorizationRepository::new(pool.clone()),
            users: UserRepository::new(pool),
        }
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }

    /// One-read UserInfo snapshot: resolve the active subject by user UUID or
    /// by a reusable subject binding (legacy JTI fallback), and LEFT JOIN the
    /// already-verified protocol client id in the same statement. The client
    /// join carries no `is_active` or WHERE filtering — the original
    /// `into_domain` conversion and the caller's inactive decision keep their
    /// order. Conversion runs subject-first so corrupt client data cannot
    /// mask a user-side consistency error.
    pub async fn userinfo_snapshot(
        &self,
        tenant_id: Uuid,
        subject: nazo_auth::UserinfoSubjectRef<'_>,
        client_id: &str,
    ) -> Result<Option<UserinfoSnapshot>, RepositoryError> {
        let mut connection = self.connection().await?;
        let client_join = oauth_clients::table.on(oauth_clients::tenant_id
            .eq(users::tenant_id)
            .and(oauth_clients::client_id.eq(client_id)));
        let row = match subject {
            nazo_auth::UserinfoSubjectRef::UserId(user_id) => users::table
                .filter(users::id.eq(user_id))
                .filter(users::tenant_id.eq(tenant_id))
                .filter(users::is_active.eq(true))
                .left_join(client_join)
                .select((
                    SubjectClaimsRow::as_select(),
                    Option::<OAuthClientRecord>::as_select(),
                ))
                .first::<(SubjectClaimsRow, Option<OAuthClientRecord>)>(&mut connection)
                .await
                .optional()
                .map_err(|error| RepositoryError::Unexpected(error.to_string()))?,
            nazo_auth::UserinfoSubjectRef::AccessToken { subject, jti } => {
                let bound = users::table
                    .inner_join(
                        oauth_subject_bindings::table.on(users::id
                            .eq(oauth_subject_bindings::user_id)
                            .and(users::tenant_id.eq(oauth_subject_bindings::tenant_id))),
                    )
                    .left_join(client_join)
                    .filter(oauth_subject_bindings::tenant_id.eq(tenant_id))
                    .filter(oauth_subject_bindings::subject.eq(subject))
                    .filter(users::is_active.eq(true))
                    .select((
                        SubjectClaimsRow::as_select(),
                        Option::<OAuthClientRecord>::as_select(),
                    ))
                    .first::<(SubjectClaimsRow, Option<OAuthClientRecord>)>(&mut connection)
                    .await
                    .optional()
                    .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
                if bound.is_some() {
                    bound
                } else {
                    let horizon =
                        Utc::now() - chrono::Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS);
                    users::table
                        .inner_join(
                            oauth_token_issuances::table.on(users::id
                                .nullable()
                                .eq(oauth_token_issuances::user_id)
                                .and(users::tenant_id.eq(oauth_token_issuances::tenant_id))),
                        )
                        .left_join(client_join)
                        .filter(oauth_token_issuances::tenant_id.eq(tenant_id))
                        .filter(oauth_token_issuances::access_token_jti.eq(jti))
                        .filter(oauth_token_issuances::access_token_expires_at.gt(horizon))
                        .filter(users::is_active.eq(true))
                        .select((
                            SubjectClaimsRow::as_select(),
                            Option::<OAuthClientRecord>::as_select(),
                        ))
                        .first::<(SubjectClaimsRow, Option<OAuthClientRecord>)>(&mut connection)
                        .await
                        .optional()
                        .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
                }
            }
        };
        let Some((claims_row, client_row)) = row else {
            return Ok(None);
        };
        let subject = identity::active_subject_claims(claims_row)
            .map_err(|error| RepositoryError::Consistency(error.0))?;
        let client = client_row.map(OAuthClientRecord::into_domain).transpose()?;
        Ok(Some(UserinfoSnapshot { subject, client }))
    }

    /// Resolve a verified non-public subject through its reusable binding.
    /// Only legacy tokens fall back to issuance ownership within retention.
    pub async fn active_subject_id_by_access_token(
        &self,
        tenant_id: Uuid,
        jti: &str,
        subject: &str,
    ) -> Result<Option<Uuid>, RepositoryError> {
        let mut connection = self.connection().await?;
        let bound = users::table
            .inner_join(
                oauth_subject_bindings::table.on(users::id
                    .eq(oauth_subject_bindings::user_id)
                    .and(users::tenant_id.eq(oauth_subject_bindings::tenant_id))),
            )
            .filter(oauth_subject_bindings::tenant_id.eq(tenant_id))
            .filter(oauth_subject_bindings::subject.eq(subject))
            .filter(users::is_active.eq(true))
            .select(users::id)
            .first::<Uuid>(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        if bound.is_some() {
            return Ok(bound);
        }
        let horizon = Utc::now() - chrono::Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS);
        users::table
            .inner_join(
                oauth_token_issuances::table.on(users::id
                    .nullable()
                    .eq(oauth_token_issuances::user_id)
                    .and(users::tenant_id.eq(oauth_token_issuances::tenant_id))),
            )
            .filter(oauth_token_issuances::tenant_id.eq(tenant_id))
            .filter(oauth_token_issuances::access_token_jti.eq(jti))
            .filter(oauth_token_issuances::access_token_expires_at.gt(horizon))
            .filter(users::is_active.eq(true))
            .select(users::id)
            .get_result(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
}

enum CommitTransactionError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
    /// Aborts the transaction so the already inserted single-use row rolls
    /// back; the outer boundary maps this to `CommitTokenIssuanceResult::GrantExpired`.
    GrantExpired,
    NativeSsoSourceUnavailable,
    NativeSsoDependencyUnavailable,
}
impl From<diesel::result::Error> for CommitTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

/// This is the last authority check before required audit and COMMIT. NOWAIT
/// avoids cross-client capacity wait cycles; a busy source is a retryable
/// dependency failure, while an invalid source aborts all destination writes.
async fn fence_native_sso_source(
    connection: &mut diesel_async::AsyncPgConnection,
    source: &nazo_auth::NativeSsoSourceFence,
    retired: Option<&super::tokens::RetiredNativeSsoSource>,
) -> Result<(), CommitTransactionError> {
    if let Some(retired) = retired {
        let now = Utc::now();
        if retired.tenant_id == source.tenant_id
            && retired.user_id == Some(source.user_id)
            && retired.token_family_id == source.family_id
            && retired.source_client_id == source.source_client_id
            && retired.expires_at > now
            && source.device_secret_expires_at > now
        {
            return Ok(());
        }
        return Err(CommitTransactionError::NativeSsoSourceUnavailable);
    }
    #[derive(QueryableByName)]
    struct SourceState {
        #[diesel(sql_type = sql_types::Timestamptz)]
        expires_at: DateTime<Utc>,
        #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
        revoked_at: Option<DateTime<Utc>>,
        #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
        reuse_detected_at: Option<DateTime<Utc>>,
    }
    let state = sql_query(
        "SELECT family.current_expires_at AS expires_at, family.revoked_at, family.reuse_detected_at \
         FROM oauth_refresh_families AS family \
         JOIN oauth_clients AS client ON client.tenant_id=family.tenant_id AND client.id=family.client_id \
         WHERE family.tenant_id=$1 AND family.user_id=$2 AND client.client_id=$3 AND family.token_family_id=$4 \
         FOR SHARE OF family NOWAIT",
    ).bind::<sql_types::Uuid,_>(source.tenant_id)
        .bind::<sql_types::Uuid,_>(source.user_id)
        .bind::<sql_types::Text,_>(&source.source_client_id)
        .bind::<sql_types::Uuid,_>(source.family_id)
        .get_result::<SourceState>(connection).await.optional()
        .map_err(|error| { tracing::warn!(%error, "Native SSO source row could not be fenced"); CommitTransactionError::NativeSsoDependencyUnavailable })?;
    let now = Utc::now();
    if state.is_some_and(|state| {
        state.revoked_at.is_none()
            && state.reuse_detected_at.is_none()
            && state.expires_at > now
            && source.device_secret_expires_at > now
    }) {
        Ok(())
    } else {
        Err(CommitTransactionError::NativeSsoSourceUnavailable)
    }
}

fn validate_commit_input(input: &CommitTokenIssuance) -> Result<(), RepositoryError> {
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
        return Err(RepositoryError::Consistency(
            "token issuance commit input is malformed".to_owned(),
        ));
    }
    if let TokenIssuanceMode::SingleUse { grant_key, .. }
    | TokenIssuanceMode::AuthorizationCode {
        code_identity: grant_key,
        ..
    } = &input.mode
        && grant_key.trim().is_empty()
    {
        return Err(RepositoryError::Consistency(
            "single-use token issuance grant key is empty".to_owned(),
        ));
    }
    if let TokenIssuanceMode::SingleUse { grant_key, .. } = &input.mode
        && grant_key.starts_with("authorization_code:")
    {
        return Err(RepositoryError::Consistency(
            "authorization codes require the code identity and holder contract".to_owned(),
        ));
    }
    if let TokenIssuanceMode::AuthorizationCode {
        code_identity,
        holder,
        ..
    } = &input.mode
        && (!code_identity.starts_with("authorization_code:v2:") || !holder.is_well_formed())
    {
        return Err(RepositoryError::Consistency(
            "authorization code holder contract is malformed".to_owned(),
        ));
    }
    let expected_authorization_id = input
        .refresh_token
        .as_ref()
        .map(RefreshTokenCommit::family_id)
        .unwrap_or(input.issuance_id);
    if input
        .authorization_id
        .is_some_and(|id| id != expected_authorization_id)
    {
        return Err(RepositoryError::Consistency(
            "authorization reference does not match issuance source".to_owned(),
        ));
    }
    if let Some(refresh) = input.refresh_token.as_ref() {
        let (tenant_id, client_id, user_id) = match refresh {
            RefreshTokenCommit::IssueNew { token, .. } => {
                (token.tenant_id, token.client_id, token.user_id)
            }
            RefreshTokenCommit::UseExisting { authority, .. } => {
                if !matches!(input.mode, TokenIssuanceMode::Fresh) {
                    return Err(RepositoryError::Consistency(
                        "refresh source cannot also redeem a single-use grant".to_owned(),
                    ));
                }
                (authority.tenant_id, authority.client_id, authority.user_id)
            }
        };
        if tenant_id != input.tenant_id
            || client_id != input.client_id
            || user_id != input.user_id
            || refresh.contract().subject != input.subject
        {
            return Err(RepositoryError::Consistency(
                "refresh token owner or subject does not match token issuance".to_owned(),
            ));
        }
    }
    if let Some(source) = input.native_sso_source.as_ref()
        && (source.tenant_id != input.tenant_id
            || Some(source.user_id) != input.user_id
            || source.family_id.is_nil()
            || source.source_client_id.is_empty()
            || !matches!(input.mode, TokenIssuanceMode::Fresh)
            || !matches!(
                input.refresh_token,
                Some(RefreshTokenCommit::IssueNew { .. })
            ))
    {
        return Err(RepositoryError::Consistency(
            "Native SSO source fence does not match destination issuance".to_owned(),
        ));
    }
    DateTime::<Utc>::from_timestamp(input.access_token_expires_at, 0).ok_or_else(|| {
        RepositoryError::Consistency("token issuance access-token expiry is invalid".to_owned())
    })?;
    Ok(())
}

/// One durable audit event per committed issuance. A rotation is the same
/// logical operation, so its `rotated_from_id` fact rides on this event
/// instead of producing a second ledger row — the two facts share the
/// issuance identity and transaction either way.
fn token_issued_audit_event(
    input: &CommitTokenIssuance,
    refresh: Option<&RefreshTokenCommit>,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        // One identity for the operation and its required event; the pending
        // audit key rejects duplicates while present. Fresh has no generic
        // replay contract or permanent per-token uniqueness record.
        event_id: input.issuance_id,
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: serde_json::json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION, "tenant_id": input.tenant_id, "issuance_id": input.issuance_id,
            "event_category": "token_lifecycle", "user_id": input.user_id,
            "client_id": input.audit_fields.client_id, "subject_hash": input.audit_fields.subject_hash, "scope": input.audit_fields.scope,
            "audience": input.audit_fields.audience, "access_token_jti": input.access_token_jti,
            "refresh_token_family_id": refresh.map(RefreshTokenCommit::family_id),
            "rotated_from_id": refresh.and_then(RefreshTokenCommit::token).and_then(|token| token.rotated_from_id),
        }),
        occurred_at: Utc::now(),
    }
}
fn refresh_reuse_audit_event(
    input: &CommitTokenIssuance,
    refresh: &NewRefreshToken,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "refresh_reuse_detected".to_owned(),
        event_category: "token_replay".to_owned(),
        payload: serde_json::json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION, "tenant_id": input.tenant_id, "issuance_id": input.issuance_id,
            "event_category": "token_replay",
            "client_id": input.audit_fields.client_id, "token_family_id": refresh.family_id, "rotated_from_id": refresh.rotated_from_id,
            "source_token_id": refresh.lost_response_retry.map(|retry| retry.original_id),
        }),
        occurred_at: Utc::now(),
    }
}

/// Result row of the single-use insert: `RETURNING` only exists for rows that
/// were actually inserted, so a missing row means the grant key is used.
#[derive(QueryableByName)]
struct SingleUseInsertRow {
    #[diesel(sql_type = sql_types::Bool)]
    grant_valid: bool,
}

impl TokenRepositoryPort for TokenIssuanceRepository {
    fn token_principal_state<'a>(
        &'a self,
        tenant_id: Uuid,
        client_epoch: i64,
        user_id: Option<Uuid>,
        subject: &'a str,
    ) -> TokenFuture<'a, nazo_auth::TokenPrincipalState> {
        Box::pin(async move {
            let mut connection = self.connection().await.map_err(map_repository_error)?;
            super::token_principals::snapshot(
                &mut connection,
                tenant_id,
                client_epoch,
                user_id,
                subject,
            )
            .await
            .map_err(map_repository_error)
        })
    }

    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
        Box::pin(async move {
            validate_commit_input(&input).map_err(map_repository_error)?;
            let access_token_expires_at =
                DateTime::<Utc>::from_timestamp(input.access_token_expires_at, 0)
                    .ok_or(TokenPortError::CorruptData)?;
            let ownership_horizon = access_token_expires_at
                .checked_add_signed(chrono::Duration::seconds(
                    MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS,
                ))
                .ok_or(TokenPortError::CorruptData)?;
            // A SingleUse receipt retains replay-revocation evidence until the
            // token acceptance window and grant deadline both close. Fresh
            // has no receipt and persists neither deadline.
            let (single_use, retain_until) = match &input.mode {
                TokenIssuanceMode::Fresh => (None, ownership_horizon),
                TokenIssuanceMode::SingleUse {
                    grant_key,
                    grant_expires_at,
                }
                | TokenIssuanceMode::AuthorizationCode {
                    code_identity: grant_key,
                    grant_expires_at,
                    ..
                } => (
                    Some((
                        <[u8; 32]>::from(blake3::hash(grant_key.as_bytes())),
                        *grant_expires_at,
                    )),
                    std::cmp::max(ownership_horizon, *grant_expires_at),
                ),
            };
            let authorization_code_holder = match &input.mode {
                TokenIssuanceMode::AuthorizationCode { holder, .. } => {
                    Some(serde_json::to_value(holder).map_err(|_| TokenPortError::CorruptData)?)
                }
                _ => None,
            };
            // Pure preparation before the connection checkout: contract
            // serialization and its digest carry no database state, so they
            // must not occupy pool occupancy time. Authoritative state
            // validation stays inside the transaction unchanged.
            let prepared_contract = input
                .refresh_token
                .as_ref()
                .map(prepare_refresh_contract)
                .transpose()
                .map_err(map_repository_error)?
                .flatten();
            // Keep the transaction's sequential SQL and its connection driver
            // on the same runtime. A request crosses that boundary once instead
            // of waking another runtime for each statement. Dropping JoinSet
            // cancels the operation; DiscardOnDrop still discards an unconfirmed
            // transaction's physical connection.
            let pool = self.pool.clone();
            let mut operation = tokio::task::JoinSet::new();
            operation.spawn_on(
                async move {
                    let mut guard = DiscardOnDrop(Some(
                        get_conn(&pool)
                            .await
                            .map_err(|_| TokenPortError::Unavailable)?,
                    ));
                    let transaction = guard
                        .connection()
                        .transaction::<CommitTokenIssuanceResult, CommitTransactionError, _>(
                            async |connection| {
                                diesel::sql_query("SET LOCAL lock_timeout = '2s'")
                                    .execute(connection)
                                    .await?;
                                let client_type = match
                                    super::token_principals::lock_and_recheck(connection, &input)
                                        .await?
                                {
                                    Ok(client_type) => client_type,
                                    Err(result) => return Ok(result),
                                };
                                if let Some((digest, grant_expires_at)) = single_use {
                                    let inserted = sql_query(
                                        "INSERT INTO oauth_token_issuances (\
                                         issuance_id, tenant_id, client_id, user_id, \
                                         single_use_key_blake3, access_token_jti, \
                                         access_token_expires_at, retain_until, \
                                         refresh_token_family_id, principal_epoch_bound, \
                                         receipt_contract_version, authorization_code_holder) \
                                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE, 2, $11) \
                                     ON CONFLICT (tenant_id, client_id, single_use_key_blake3) \
                                       WHERE single_use_key_blake3 IS NOT NULL \
                                     DO NOTHING \
                                     RETURNING (clock_timestamp() < $10) AS grant_valid",
                                    )
                                    .bind::<sql_types::Uuid, _>(input.issuance_id)
                                    .bind::<sql_types::Uuid, _>(input.tenant_id)
                                    .bind::<sql_types::Uuid, _>(input.client_id)
                                    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(None::<Uuid>)
                                    .bind::<sql_types::Binary, _>(digest.as_slice())
                                    .bind::<sql_types::Varchar, _>(input.access_token_jti.as_str())
                                    .bind::<sql_types::Timestamptz, _>(access_token_expires_at)
                                    .bind::<sql_types::Timestamptz, _>(retain_until)
                                    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(
                                        input
                                            .refresh_token
                                            .as_ref()
                                            .map(RefreshTokenCommit::family_id),
                                    )
                                    .bind::<sql_types::Timestamptz, _>(grant_expires_at)
                                    .bind::<sql_types::Nullable<sql_types::Jsonb>, _>(
                                        authorization_code_holder.as_ref(),
                                    )
                                    .get_result::<SingleUseInsertRow>(connection)
                                    .await
                                    .optional()?;
                                    match inserted {
                                        None => {
                                            return Ok(CommitTokenIssuanceResult::AlreadyUsed);
                                        }
                                        Some(row) if !row.grant_valid => {
                                            return Err(CommitTransactionError::GrantExpired);
                                        }
                                        Some(_) => {}
                                    }
                                }
                                let mut retired_native_source = None;
                                if let Some(refresh) = input.refresh_token.as_ref() {
                                    match TokenRepository::persist_refresh_token_on_connection(
                                        connection,
                                        refresh,
                                        &client_type,
                                        input.issuance_id,
                                        prepared_contract.as_ref(),
                                        input.native_sso_source.as_ref(),
                                    )
                                    .await
                                    .map_err(CommitTransactionError::Repository)?
                                    {
                                        (RefreshTokenPersistResult::Inserted, retired) => { retired_native_source = retired; }
                                        (RefreshTokenPersistResult::InvalidSource, _) => {
                                            return Ok(CommitTokenIssuanceResult::RefreshGrantUnavailable);
                                        }
                                        (RefreshTokenPersistResult::RotationConflict, _) => {
                                            // Keep the family compromise written by the
                                            // rotation attempt, drop only this request's
                                            // issuance row, and commit the reuse audit.
                                            if single_use.is_some() {
                                                diesel::delete(
                                                    oauth_token_issuances::table
                                                        .filter(
                                                            oauth_token_issuances::issuance_id
                                                                .eq(input.issuance_id),
                                                        )
                                                        .filter(
                                                            oauth_token_issuances::tenant_id
                                                                .eq(input.tenant_id),
                                                        ),
                                                )
                                                .execute(connection)
                                                .await?;
                                            }
                                            append_fresh_security_audit_on_connection(
                                                connection,
                                                &refresh_reuse_audit_event(
                                                    &input,
                                                    refresh.token().expect("only a rotation or new-family collision compromises"),
                                                ),
                                            )
                                            .await?;
                                            return Ok(CommitTokenIssuanceResult::RotationConflict);
                                        }
                                    }
                                }
                                super::token_principals::ensure_subject_binding(connection, &input)
                                    .await?;
                                if let Some(source) = input.native_sso_source.as_ref() {
                                    fence_native_sso_source(connection, source, retired_native_source.as_ref()).await?;
                                }
                                append_fresh_security_audit_on_connection(
                                    connection,
                                    &token_issued_audit_event(&input, input.refresh_token.as_ref()),
                                )
                                .await?;
                                Ok(CommitTokenIssuanceResult::Committed)
                            },
                        )
                        .await;
                    match transaction {
                        Ok(result) => {
                            guard.return_to_pool();
                            Ok(result)
                        }
                        Err(CommitTransactionError::GrantExpired) => {
                            // Rollback completed cleanly; the connection is healthy.
                            guard.return_to_pool();
                            Ok(CommitTokenIssuanceResult::GrantExpired)
                        }
                        Err(CommitTransactionError::NativeSsoSourceUnavailable) => {
                            guard.return_to_pool();
                            Ok(CommitTokenIssuanceResult::RefreshGrantUnavailable)
                        }
                        Err(CommitTransactionError::NativeSsoDependencyUnavailable) => {
                            guard.return_to_pool();
                            Err(TokenPortError::Unavailable)
                        }
                        Err(CommitTransactionError::Repository(error)) => {
                            Err(map_repository_error(error))
                        }
                        Err(CommitTransactionError::Diesel(error)) => Err(map_diesel_error(error)),
                    }
                },
                &self.pool.runtime,
            );
            operation
                .join_next()
                .await
                .expect("issuance transaction task was registered")
                .map_err(|error| {
                    tracing::warn!(%error, "token issuance runtime ended before completion");
                    TokenPortError::Unavailable
                })?
        })
    }
    fn single_use_redemption<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        grant_key: &'a str,
    ) -> TokenFuture<'a, Option<SingleUseRedemption>> {
        Box::pin(async move {
            let digest = blake3::hash(grant_key.as_bytes());
            let row = oauth_token_issuances::table
                .filter(oauth_token_issuances::tenant_id.eq(tenant_id))
                .filter(oauth_token_issuances::client_id.eq(client_id))
                .filter(oauth_token_issuances::single_use_key_blake3.eq(digest.as_bytes().to_vec()))
                .select((
                    oauth_token_issuances::access_token_jti,
                    oauth_token_issuances::access_token_expires_at,
                    oauth_token_issuances::refresh_token_family_id,
                    oauth_token_issuances::authorization_code_holder,
                ))
                .first::<(
                    String,
                    DateTime<Utc>,
                    Option<Uuid>,
                    Option<serde_json::Value>,
                )>(&mut self.connection().await.map_err(map_repository_error)?)
                .await
                .optional()
                .map_err(map_diesel_error)?;
            row.map(
                |(access_token_jti, access_token_expires_at, refresh_token_family_id, holder)| {
                    let authorization_code_holder = holder
                        .map(|value| {
                            nazo_auth::AuthorizationCodeHolderEvidence::from_persisted(value)
                                .ok_or(TokenPortError::CorruptData)
                        })
                        .transpose()
                        .map_err(|_| TokenPortError::CorruptData)?;
                    if authorization_code_holder
                        .as_ref()
                        .is_some_and(|holder| !holder.is_well_formed())
                    {
                        return Err(TokenPortError::CorruptData);
                    }
                    Ok(SingleUseRedemption {
                        authorization_code_holder,
                        access_token_jti,
                        access_token_expires_at,
                        refresh_token_family_id,
                    })
                },
            )
            .transpose()
        })
    }

    fn userinfo_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        subject: nazo_auth::UserinfoSubjectRef<'a>,
        client_id: &'a str,
    ) -> TokenFuture<'a, Option<UserinfoSnapshot>> {
        Box::pin(async move {
            TokenIssuanceRepository::userinfo_snapshot(self, tenant_id, subject, client_id)
                .await
                .map_err(map_repository_error)
        })
    }
    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        Box::pin(async move {
            self.tokens
                .by_raw_refresh_token(tenant_id, raw_token)
                .await
                .map_err(map_repository_error)
        })
    }
    fn refresh_token_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> TokenFuture<'a, Option<nazo_auth::RefreshTokenSnapshot>> {
        self.refresh_token_snapshot_with_subject(
            tenant_id,
            raw_token,
            client_id,
            retry_started_at,
            false,
        )
    }

    fn refresh_token_snapshot_with_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
        prepare_oidc_subject: bool,
    ) -> TokenFuture<'a, Option<nazo_auth::RefreshTokenSnapshot>> {
        Box::pin(async move {
            self.tokens
                .refresh_token_snapshot(
                    tenant_id,
                    raw_token,
                    client_id,
                    retry_started_at,
                    prepare_oidc_subject,
                )
                .await
                .map_err(map_repository_error)
                .map(|snapshot| {
                    snapshot.map(|snapshot| nazo_auth::RefreshTokenSnapshot {
                        presented: snapshot.presented,
                        successor: snapshot.successor.map_err(map_repository_error),
                        prepared_subject: snapshot.prepared_subject,
                    })
                })
        })
    }

    fn inspect_lost_response_successor<'a>(
        &'a self,
        token: &'a RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        Box::pin(async move {
            self.tokens
                .inspect_lost_response_successor(token, client_id, retry_started_at)
                .await
                .map_err(map_repository_error)
        })
    }
    fn active_subject_claims<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        token_subject: &'a str,
    ) -> TokenFuture<'a, Option<nazo_auth::PreparedTokenSubject>> {
        Box::pin(async move {
            let tenant_id = TenantId::new(tenant_id).map_err(|_| TokenPortError::CorruptData)?;
            let user_id = UserId::new(user_id).map_err(|_| TokenPortError::CorruptData)?;
            self.users
                .active_subject_claims_by_tenant_id(tenant_id, user_id, token_subject)
                .await
                .map(|snapshot| {
                    snapshot.map(|(claims, user_epoch, subject_bound)| {
                        nazo_auth::PreparedTokenSubject {
                            tenant_id: tenant_id.as_uuid(),
                            claims,
                            user_epoch,
                            token_subject: token_subject.to_owned(),
                            subject_bound,
                        }
                    })
                })
                .map_err(map_repository_error)
        })
    }
    fn active_subject_id(&self, tenant_id: Uuid, user_id: Uuid) -> TokenFuture<'_, Option<Uuid>> {
        Box::pin(async move {
            let tenant_id = TenantId::new(tenant_id).map_err(|_| TokenPortError::CorruptData)?;
            let user_id = UserId::new(user_id).map_err(|_| TokenPortError::CorruptData)?;
            self.users
                .active_subject_id_by_tenant_id(tenant_id, user_id)
                .await
                .map_err(map_repository_error)
        })
    }
    fn active_subject_id_by_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
        subject: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>> {
        Box::pin(async move {
            TokenIssuanceRepository::active_subject_id_by_access_token(
                self, tenant_id, jti, subject,
            )
            .await
            .map_err(map_repository_error)
        })
    }
    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.authorization
                .revoke_issued_tokens(
                    tenant_id,
                    client_id,
                    access_token_jti,
                    access_token_expires_at,
                    refresh_token_family_id,
                )
                .await
                .map_err(map_repository_error)
        })
    }
    fn access_token_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        claims: &'a nazo_auth::Claims,
    ) -> TokenFuture<'a, bool> {
        Box::pin(async move {
            self.tokens
                .access_token_state_revoked(nazo_resource_server::RevocationLookupKey {
                    tenant_id: &tenant_id.to_string(),
                    jti: &claims.jti,
                    client_id: &claims.client_id,
                    subject: &claims.sub,
                    user_id: claims.user_id.as_deref(),
                    subject_type: Some(&claims.subject_type),
                    client_epoch: claims.client_epoch,
                    user_epoch: claims.user_epoch,
                })
                .await
                .map_err(map_repository_error)
        })
    }
    fn refresh_family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, bool> {
        Box::pin(async move {
            self.tokens
                .family_active(tenant_id, family_id, user_id)
                .await
                .map_err(map_repository_error)
        })
    }
    fn revoke_token<'a>(&'a self, input: TokenRevocation<'a>) -> TokenFuture<'a, usize> {
        Box::pin(async move {
            self.tokens
                .revoke_for_client(
                    input.tenant_id,
                    input.client_id,
                    input.raw_token,
                    input.access_token.as_ref(),
                )
                .await
                .map_err(map_repository_error)
        })
    }
    fn revoke_token_with_audit<'a>(
        &'a self,
        input: TokenRevocation<'a>,
        client_public_id: &'a str,
        source_ip_hash: &'a str,
    ) -> TokenFuture<'a, usize> {
        Box::pin(async move {
            self.tokens
                .revoke_for_client_with_audit(
                    input.tenant_id,
                    input.client_id,
                    input.raw_token,
                    input.access_token.as_ref(),
                    Some((client_public_id, source_ip_hash)),
                )
                .await
                .map_err(map_repository_error)
        })
    }
}

fn map_repository_error(error: RepositoryError) -> TokenPortError {
    match error {
        RepositoryError::Unavailable => TokenPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => TokenPortError::Conflict,
        RepositoryError::Consistency(_) => TokenPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => TokenPortError::Unexpected,
    }
}

fn map_diesel_error(error: diesel::result::Error) -> TokenPortError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => TokenPortError::Conflict,
        diesel::result::Error::NotFound => TokenPortError::CorruptData,
        _ => TokenPortError::Unexpected,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/token_issuance.rs"]
mod tests;
