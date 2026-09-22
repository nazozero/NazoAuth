use chrono::{DateTime, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, NullableExpressionMethods,
    OptionalExtension, QueryDsl, QueryableByName, SelectableHelper, sql_query, sql_types,
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken, RefreshToken,
    RefreshTokenPersistResult, SingleUseRedemption, TokenFuture, TokenIssuanceMode, TokenPortError,
    TokenRepositoryPort, TokenRevocation, UserinfoSnapshot,
};
use nazo_identity::{SubjectClaims, TenantId, UserId, ports::RepositoryError};
use nazo_persistence::SecurityAuditEvent;
use nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS;
use uuid::Uuid;

use crate::{
    DbPool, get_conn,
    pool::DiscardOnDrop,
    schema::{oauth_clients, oauth_token_issuances, users},
};

use super::{
    AuthorizationRepository, TokenRepository, UserRepository,
    access_token_revocation::{NewAccessTokenRevocation, upsert_access_token_revocations},
    audit_ledger::append_fresh_security_audit_on_connection,
    clients::OAuthClientRecord,
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
         WHERE issuance.tenant_id = $1 \
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
    /// by access-token JTI through its issuance row, and LEFT JOIN the
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
            nazo_auth::UserinfoSubjectRef::AccessTokenJti(jti) => {
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
        };
        let Some((claims_row, client_row)) = row else {
            return Ok(None);
        };
        let subject = identity::active_subject_claims(claims_row)
            .map_err(|error| RepositoryError::Consistency(error.0))?;
        let client = client_row.map(OAuthClientRecord::into_domain).transpose()?;
        Ok(Some(UserinfoSnapshot { subject, client }))
    }

    /// Ownership lookup for a verified access-token JTI: joins the issuance
    /// join already proves the user is active inside the acceptance window.
    pub async fn active_subject_id_by_access_token(
        &self,
        tenant_id: Uuid,
        jti: &str,
    ) -> Result<Option<Uuid>, RepositoryError> {
        let mut connection = self.connection().await?;
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
}
impl From<diesel::result::Error> for CommitTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

fn validate_commit_input(input: &CommitTokenIssuance) -> Result<(), RepositoryError> {
    if input.issuance_id.is_nil()
        || input.tenant_id.is_nil()
        || input.client_id.is_nil()
        || input.access_token_jti.trim().is_empty()
    {
        return Err(RepositoryError::Consistency(
            "token issuance commit input is malformed".to_owned(),
        ));
    }
    if let TokenIssuanceMode::SingleUse { grant_key, .. } = &input.mode
        && grant_key.trim().is_empty()
    {
        return Err(RepositoryError::Consistency(
            "single-use token issuance grant key is empty".to_owned(),
        ));
    }
    if let Some(refresh) = input.refresh_token.as_ref()
        && (refresh.tenant_id != input.tenant_id
            || refresh.client_id != input.client_id
            || refresh.user_id != input.user_id)
    {
        return Err(RepositoryError::Consistency(
            "refresh token owner does not match token issuance owner".to_owned(),
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
    refresh: Option<&NewRefreshToken>,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: serde_json::json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION, "tenant_id": input.tenant_id, "issuance_id": input.issuance_id,
            "event_category": "token_lifecycle", "user_id": input.user_id,
            "client_id": input.audit_fields.client_id, "subject_hash": input.audit_fields.subject_hash, "scope": input.audit_fields.scope,
            "audience": input.audit_fields.audience, "access_token_jti": input.access_token_jti,
            "refresh_token_family_id": refresh.map(|refresh| refresh.family_id),
            "rotated_from_id": refresh.and_then(|refresh| refresh.rotated_from_id),
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
            // The durable fence retains ownership evidence until the access
            // token's maximum acceptance window closes; a single-use grant
            // additionally retains its own verified deadline so an expired
            // retry is still recognizable.
            let (single_use, retain_until) = match &input.mode {
                TokenIssuanceMode::Fresh => (None, ownership_horizon),
                TokenIssuanceMode::SingleUse {
                    grant_key,
                    grant_expires_at,
                } => (
                    Some((
                        <[u8; 32]>::from(blake3::hash(grant_key.as_bytes())),
                        *grant_expires_at,
                    )),
                    std::cmp::max(ownership_horizon, *grant_expires_at),
                ),
            };
            let mut guard =
                DiscardOnDrop(Some(self.connection().await.map_err(map_repository_error)?));
            let transaction = guard
                .connection()
                .transaction::<CommitTokenIssuanceResult, CommitTransactionError, _>(
                    async |connection| {
                        diesel::sql_query("SET LOCAL lock_timeout = '2s'")
                            .execute(connection)
                            .await?;
                        if let Some(result) = lock_inactive_issuance_principal(
                            connection,
                            input.tenant_id,
                            input.client_id,
                            input.user_id,
                        )
                        .await?
                        {
                            return Ok(result);
                        }
                        match single_use {
                            None => {
                                diesel::insert_into(oauth_token_issuances::table)
                                    .values((
                                        oauth_token_issuances::issuance_id.eq(input.issuance_id),
                                        oauth_token_issuances::tenant_id.eq(input.tenant_id),
                                        oauth_token_issuances::client_id.eq(input.client_id),
                                        oauth_token_issuances::user_id.eq(input.user_id),
                                        oauth_token_issuances::access_token_jti
                                            .eq(input.access_token_jti.as_str()),
                                        oauth_token_issuances::access_token_expires_at
                                            .eq(access_token_expires_at),
                                        oauth_token_issuances::retain_until.eq(retain_until),
                                        oauth_token_issuances::refresh_token_family_id.eq(input
                                            .refresh_token
                                            .as_ref()
                                            .map(|refresh| refresh.family_id)),
                                    ))
                                    .execute(connection)
                                    .await?;
                            }
                            Some((digest, grant_expires_at)) => {
                                let inserted = sql_query(
                                    "INSERT INTO oauth_token_issuances (\
                                         issuance_id, tenant_id, client_id, user_id, \
                                         single_use_key_blake3, access_token_jti, \
                                         access_token_expires_at, retain_until, \
                                         refresh_token_family_id) \
                                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                                     ON CONFLICT (tenant_id, client_id, single_use_key_blake3) \
                                       WHERE single_use_key_blake3 IS NOT NULL \
                                     DO NOTHING \
                                     RETURNING (clock_timestamp() < $10) AS grant_valid",
                                )
                                .bind::<sql_types::Uuid, _>(input.issuance_id)
                                .bind::<sql_types::Uuid, _>(input.tenant_id)
                                .bind::<sql_types::Uuid, _>(input.client_id)
                                .bind::<sql_types::Nullable<sql_types::Uuid>, _>(input.user_id)
                                .bind::<sql_types::Binary, _>(digest.as_slice())
                                .bind::<sql_types::Varchar, _>(input.access_token_jti.as_str())
                                .bind::<sql_types::Timestamptz, _>(access_token_expires_at)
                                .bind::<sql_types::Timestamptz, _>(retain_until)
                                .bind::<sql_types::Nullable<sql_types::Uuid>, _>(
                                    input
                                        .refresh_token
                                        .as_ref()
                                        .map(|refresh| refresh.family_id),
                                )
                                .bind::<sql_types::Timestamptz, _>(grant_expires_at)
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
                        }
                        if let Some(refresh) = input.refresh_token.as_ref() {
                            match TokenRepository::persist_refresh_token_on_connection(
                                connection,
                                refresh.clone(),
                                input.issuance_id,
                            )
                            .await
                            .map_err(CommitTransactionError::Repository)?
                            {
                                RefreshTokenPersistResult::Inserted => {}
                                RefreshTokenPersistResult::RotationConflict => {
                                    // Keep the family compromise written by the
                                    // rotation attempt, drop only this request's
                                    // issuance row, and commit the reuse audit.
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
                                    append_fresh_security_audit_on_connection(
                                        connection,
                                        &refresh_reuse_audit_event(&input, refresh),
                                    )
                                    .await?;
                                    return Ok(CommitTokenIssuanceResult::RotationConflict);
                                }
                            }
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
                Err(CommitTransactionError::Repository(error)) => Err(map_repository_error(error)),
                Err(CommitTransactionError::Diesel(error)) => Err(map_diesel_error(error)),
            }
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
                ))
                .first::<(String, DateTime<Utc>, Option<Uuid>)>(
                    &mut self.connection().await.map_err(map_repository_error)?,
                )
                .await
                .optional()
                .map_err(map_diesel_error)?;
            Ok(row.map(
                |(access_token_jti, access_token_expires_at, refresh_token_family_id)| {
                    SingleUseRedemption {
                        access_token_jti,
                        access_token_expires_at,
                        refresh_token_family_id,
                    }
                },
            ))
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
    fn active_subject_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, Option<SubjectClaims>> {
        Box::pin(async move {
            let tenant_id = TenantId::new(tenant_id).map_err(|_| TokenPortError::CorruptData)?;
            let user_id = UserId::new(user_id).map_err(|_| TokenPortError::CorruptData)?;
            self.users
                .active_subject_claims_by_tenant_id(tenant_id, user_id)
                .await
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
    ) -> TokenFuture<'a, Option<Uuid>> {
        Box::pin(async move {
            TokenIssuanceRepository::active_subject_id_by_access_token(self, tenant_id, jti)
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
    fn access_token_revoked<'a>(&'a self, tenant_id: Uuid, jti: &'a str) -> TokenFuture<'a, bool> {
        Box::pin(async move {
            self.tokens
                .access_token_revoked(tenant_id, jti)
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
}

async fn lock_inactive_issuance_principal(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    client_id: Uuid,
    user_id: Option<Uuid>,
) -> diesel::QueryResult<Option<CommitTokenIssuanceResult>> {
    let client_is_active = oauth_clients::table
        .filter(oauth_clients::tenant_id.eq(tenant_id))
        .filter(oauth_clients::id.eq(client_id))
        .select(oauth_clients::is_active)
        .for_share()
        .first::<bool>(connection)
        .await
        .optional()?;
    if client_is_active != Some(true) {
        return Ok(Some(CommitTokenIssuanceResult::ClientInactive));
    }

    let Some(user_id) = user_id else {
        return Ok(None);
    };
    let user_is_active = users::table
        .filter(users::tenant_id.eq(tenant_id))
        .filter(users::id.eq(user_id))
        .select(users::is_active)
        .for_share()
        .first::<bool>(connection)
        .await
        .optional()?;
    if user_is_active != Some(true) {
        return Ok(Some(CommitTokenIssuanceResult::SubjectInactive));
    }
    Ok(None)
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
