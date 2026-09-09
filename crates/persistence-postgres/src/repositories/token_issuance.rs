use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chrono::{DateTime, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, QueryableByName,
    SelectableHelper, sql_query, sql_types,
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken, OAuthClient, RefreshToken,
    RefreshTokenPersistResult, TokenFuture, TokenIssuanceMode, TokenIssuanceRecord, TokenPortError,
    TokenRepositoryPort, TokenRevocation,
};
use nazo_identity::{SubjectClaims, TenantId, UserId, ports::RepositoryError};
#[cfg(test)]
use nazo_persistence::TokenIssuanceResponseKeyError;
use nazo_persistence::{SecurityAuditEvent, TokenIssuanceResponseKeyRing};
use rand::Rng;
use uuid::Uuid;

use crate::{
    DbPool,
    pool::DiscardOnDrop,
    schema::{access_token_revocations, oauth_token_issuances},
};

use super::{
    AuthorizationRepository, OAuthClientRepository, TokenRepository, UserRepository,
    audit_ledger::append_fresh_security_audit_on_connection,
};

/// The persisted envelope format is deliberately independent from the key id.
/// A format migration can therefore be introduced without pretending that a
/// key rotation changed the ciphertext layout.
pub const TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION: &str = "v1";
const TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE: u8 = 1;
const RESPONSE_NONCE_LEN: usize = 12;
const RESPONSE_MIN_PROTECTED_LEN: usize = 1 + RESPONSE_NONCE_LEN + 16;

#[derive(diesel::Insertable)]
#[diesel(table_name = access_token_revocations)]
struct NewAccessTokenRevocation {
    id: Uuid,
    access_token_jti_blake3: String,
    client_id: Uuid,
    tenant_id: Uuid,
    revoked_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

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
    sql_query(
        "DECLARE nazo_owner_token_revocations NO SCROLL CURSOR WITHOUT HOLD FOR \
         SELECT issuance.client_id, issuance.access_token_jti, issuance.access_token_expires_at AS expires_at \
         FROM oauth_token_issuances AS issuance \
         WHERE issuance.tenant_id = $1 AND issuance.access_token_jti IS NOT NULL \
           AND issuance.access_token_expires_at > $4 \
           AND ($2::uuid IS NULL OR issuance.client_id = $2) \
           AND ($3::uuid IS NULL OR issuance.user_id = $3) \
         UNION ALL \
         SELECT client.id AS client_id, grant_row.token_id::text AS access_token_jti, grant_row.expires_at \
         FROM openid4vci_access_grants AS grant_row \
         JOIN oauth_clients AS client ON client.tenant_id = grant_row.tenant_id AND client.client_id = grant_row.client_id \
         WHERE grant_row.tenant_id = $1 AND grant_row.revoked_at IS NULL AND grant_row.expires_at > $4 \
           AND ($2::uuid IS NULL OR client.id = $2) \
           AND ($3::uuid IS NULL OR grant_row.subject_id = $3)",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(client_id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(user_id)
    .bind::<sql_types::Timestamptz, _>(now)
    .execute(connection)
    .await?;
    let mut inserted = 0;
    loop {
        let rows = sql_query("FETCH FORWARD 512 FROM nazo_owner_token_revocations")
            .load::<OwnedAccessTokenRow>(connection)
            .await?;
        if rows.is_empty() {
            break;
        }
        let revocations = rows
            .into_iter()
            .map(|row| NewAccessTokenRevocation {
                id: Uuid::now_v7(),
                access_token_jti_blake3: blake3::hash(row.access_token_jti.as_bytes())
                    .to_hex()
                    .to_string(),
                client_id: row.client_id,
                tenant_id,
                revoked_at: now,
                expires_at: row.expires_at,
            })
            .collect::<Vec<_>>();
        inserted += diesel::insert_into(access_token_revocations::table)
            .values(&revocations)
            .on_conflict((
                access_token_revocations::tenant_id,
                access_token_revocations::access_token_jti_blake3,
            ))
            .do_nothing()
            .execute(connection)
            .await?;
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
    Ok(inserted)
}

struct ResponseEnvelopeContext<'a> {
    issuance_id: Uuid,
    tenant_id: Uuid,
    client_id: Uuid,
    grant_key_hash: &'a str,
    response_digest: &'a str,
    envelope_version: &'a str,
    key_id: &'a str,
}

/// PostgreSQL transaction boundary used by authorization-code and refresh-token issuance.
#[derive(Clone)]
pub struct TokenIssuanceRepository {
    pool: DbPool,
    response_keys: Option<TokenIssuanceResponseKeyRing>,
    tokens: TokenRepository,
    authorization: AuthorizationRepository,
    users: UserRepository,
    clients: OAuthClientRepository,
}

impl TokenIssuanceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool: pool.clone(),
            response_keys: None,
            tokens: TokenRepository::new(pool.clone()),
            authorization: AuthorizationRepository::new(pool.clone()),
            clients: OAuthClientRepository::new(pool.clone()),
            users: UserRepository::new(pool),
        }
    }

    /// Production constructor. The response body is sealed before it is
    /// persisted. The key ring is supplied independently from client-secret
    /// hashing so that rotating one secret cannot silently invalidate the
    /// other capability.
    #[must_use]
    pub fn new_with_response_key_ring(
        pool: DbPool,
        response_keys: TokenIssuanceResponseKeyRing,
    ) -> Self {
        let mut repository = Self::new(pool);
        repository.response_keys = Some(response_keys);
        repository
    }

    /// Verify only response metadata before admitting token traffic.
    pub async fn validate_response_key_ring(&self) -> Result<(), RepositoryError> {
        let Some(response_keys) = self.response_keys.as_ref() else {
            return Err(RepositoryError::Consistency(
                "token issuance response encryption keys are not configured".to_owned(),
            ));
        };
        let mut connection = self.connection().await?;
        let response_metadata = oauth_token_issuances::table
            .filter(oauth_token_issuances::expires_at.gt(Utc::now()))
            .filter(oauth_token_issuances::access_token_expires_at.gt(Utc::now()))
            .filter(oauth_token_issuances::response_ciphertext.is_not_null())
            .select((
                oauth_token_issuances::response_key_id,
                oauth_token_issuances::response_envelope_version,
            ))
            .distinct()
            .load::<(Option<String>, Option<String>)>(&mut connection)
            .await
            .map_err(|error| {
                RepositoryError::Unexpected(format!(
                    "failed to inspect token issuance response key metadata: {error}"
                ))
            })?;
        validate_response_key_metadata(response_keys, response_metadata)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

#[derive(diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = oauth_token_issuances)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct TokenIssuanceRow {
    issuance_id: Uuid,
    tenant_id: Uuid,
    client_id: Uuid,
    user_id: Option<Uuid>,
    grant_key_blake3: String,
    request_digest: String,
    access_token_jti: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    response_ciphertext: Option<Vec<u8>>,
    response_digest: Option<String>,
    response_envelope_version: Option<String>,
    response_key_id: Option<String>,
    #[allow(dead_code)]
    expires_at: DateTime<Utc>,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
}

impl TokenIssuanceRow {
    fn into_record(
        self,
        response_keys: Option<&TokenIssuanceResponseKeyRing>,
    ) -> Result<TokenIssuanceRecord, RepositoryError> {
        if (self.access_token_jti.is_some()) != self.access_token_expires_at.is_some() {
            return Err(RepositoryError::Consistency(
                "token issuance access-token JTI and expiry are inconsistent".to_owned(),
            ));
        }
        let response_body = match (
            &self.response_ciphertext,
            &self.response_digest,
            &self.response_envelope_version,
            &self.response_key_id,
        ) {
            (None, None, None, None) => None,
            (Some(ciphertext), Some(digest), Some(envelope_version), Some(key_id))
                if envelope_version == TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION
                    && self.access_token_jti.is_some() =>
            {
                // Retention can extend through the refresh token lifetime.
                // Expired responses no longer need their decryption key.
                if self
                    .access_token_expires_at
                    .is_some_and(|expiry| expiry > Utc::now())
                {
                    let Some(response_keys) = response_keys else {
                        return Err(RepositoryError::Consistency(
                            "token issuance response encryption keys are not configured".to_owned(),
                        ));
                    };
                    Some(unseal_response(
                        response_keys,
                        &ResponseEnvelopeContext {
                            issuance_id: self.issuance_id,
                            tenant_id: self.tenant_id,
                            client_id: self.client_id,
                            grant_key_hash: &self.grant_key_blake3,
                            response_digest: digest,
                            envelope_version,
                            key_id,
                        },
                        ciphertext,
                    )?)
                } else {
                    None
                }
            }
            (Some(_), Some(_), Some(_), Some(_)) => {
                return Err(RepositoryError::Consistency(
                    "token issuance response envelope format is unsupported".to_owned(),
                ));
            }
            _ => {
                return Err(RepositoryError::Consistency(
                    "token issuance response envelope is incomplete".to_owned(),
                ));
            }
        };
        Ok(TokenIssuanceRecord {
            issuance_id: self.issuance_id,
            tenant_id: self.tenant_id,
            client_id: self.client_id,
            user_id: self.user_id,
            grant_key: self.grant_key_blake3,
            request_digest: self.request_digest,
            access_token_jti: self.access_token_jti,
            access_token_expires_at: self.access_token_expires_at.map(|value| value.timestamp()),
            response_body,
            response_digest: self.response_digest,
            response_key_version: self.response_envelope_version,
        })
    }
}

fn validate_response_key_metadata(
    response_keys: &TokenIssuanceResponseKeyRing,
    metadata: impl IntoIterator<Item = (Option<String>, Option<String>)>,
) -> Result<(), RepositoryError> {
    for (key_id, envelope_version) in metadata {
        let Some(envelope_version) = envelope_version else {
            return Err(RepositoryError::Consistency(
                "token issuance response envelope format is missing".to_owned(),
            ));
        };
        if envelope_version != TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION {
            return Err(RepositoryError::Consistency(
                "token issuance response envelope format is unsupported".to_owned(),
            ));
        }
        let Some(key_id) = key_id else {
            return Err(RepositoryError::Consistency(
                "token issuance response is missing its encryption key id".to_owned(),
            ));
        };
        if response_keys.key_for(&key_id).is_none() {
            return Err(RepositoryError::Consistency(format!(
                "token issuance response uses an unavailable encryption key: {key_id}"
            )));
        }
    }
    Ok(())
}

fn grant_key_hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn response_aad(context: &ResponseEnvelopeContext<'_>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        16 + 16
            + 16
            + context.grant_key_hash.len()
            + context.response_digest.len()
            + context.envelope_version.len()
            + context.key_id.len(),
    );
    aad.extend_from_slice(context.issuance_id.as_bytes());
    aad.extend_from_slice(context.tenant_id.as_bytes());
    aad.extend_from_slice(context.client_id.as_bytes());
    aad.extend_from_slice(context.grant_key_hash.as_bytes());
    aad.extend_from_slice(context.response_digest.as_bytes());
    aad.extend_from_slice(context.envelope_version.as_bytes());
    aad.extend_from_slice(context.key_id.as_bytes());
    aad
}

fn seal_response(
    response_keys: Option<&TokenIssuanceResponseKeyRing>,
    context: &ResponseEnvelopeContext<'_>,
    response_body: &[u8],
) -> Result<Vec<u8>, RepositoryError> {
    let response_keys = response_keys.ok_or(RepositoryError::Unavailable)?;
    let key = response_keys.current_key();
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| RepositoryError::Consistency("invalid issuance response key".to_owned()))?;
    let mut nonce = [0_u8; RESPONSE_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: response_body,
                aad: &response_aad(context),
            },
        )
        .map_err(|_| {
            RepositoryError::Unexpected("token issuance response encryption failed".to_owned())
        })?;
    let mut protected = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    protected.push(TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE);
    protected.extend_from_slice(&nonce);
    protected.extend_from_slice(&ciphertext);
    Ok(protected)
}

fn unseal_response(
    response_keys: &TokenIssuanceResponseKeyRing,
    context: &ResponseEnvelopeContext<'_>,
    protected: &[u8],
) -> Result<Vec<u8>, RepositoryError> {
    if protected.len() < RESPONSE_MIN_PROTECTED_LEN
        || protected[0] != TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE
    {
        return Err(RepositoryError::Consistency(
            "token issuance response envelope is malformed".to_owned(),
        ));
    }
    let Some(key) = response_keys.key_for(context.key_id) else {
        return Err(RepositoryError::Consistency(
            "token issuance response uses an unavailable encryption key".to_owned(),
        ));
    };
    let (nonce, ciphertext) = protected[1..]
        .split_at_checked(RESPONSE_NONCE_LEN)
        .ok_or_else(|| {
            RepositoryError::Consistency("token issuance response is malformed".to_owned())
        })?;
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| {
        RepositoryError::Consistency("token issuance response nonce is malformed".to_owned())
    })?;
    let plaintext = Aes256Gcm::new_from_slice(key)
        .map_err(|_| RepositoryError::Consistency("invalid issuance response key".to_owned()))?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: &response_aad(context),
            },
        )
        .map_err(|_| {
            RepositoryError::Consistency("token issuance response authentication failed".to_owned())
        })?;
    if blake3::hash(&plaintext).to_hex().to_string() != context.response_digest {
        return Err(RepositoryError::Consistency(
            "token issuance response digest mismatch".to_owned(),
        ));
    }
    Ok(plaintext)
}

enum CommitTransactionError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}
impl From<diesel::result::Error> for CommitTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

#[allow(clippy::type_complexity)]
fn response_material(
    response_keys: Option<&TokenIssuanceResponseKeyRing>,
    input: &CommitTokenIssuance,
    grant_hash: &str,
) -> Result<
    (
        Option<Vec<u8>>,
        Option<String>,
        Option<String>,
        Option<String>,
    ),
    RepositoryError,
> {
    let Some(response_body) = input.response_body.as_deref() else {
        return Ok((None, None, None, None));
    };
    let response_digest = blake3::hash(response_body).to_hex().to_string();
    let Some(response_keys) = response_keys else {
        return Err(RepositoryError::Unavailable);
    };
    let key_id = response_keys.current_id().to_owned();
    let ciphertext = seal_response(
        Some(response_keys),
        &ResponseEnvelopeContext {
            issuance_id: input.issuance_id,
            tenant_id: input.tenant_id,
            client_id: input.client_id,
            grant_key_hash: grant_hash,
            response_digest: &response_digest,
            envelope_version: TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
            key_id: &key_id,
        },
        response_body,
    )?;
    Ok((
        Some(ciphertext),
        Some(response_digest),
        Some(TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION.to_owned()),
        Some(key_id),
    ))
}

fn validate_commit_input(
    input: &CommitTokenIssuance,
    grant_key: &str,
) -> Result<(), RepositoryError> {
    if input.issuance_id.is_nil()
        || input.tenant_id.is_nil()
        || input.client_id.is_nil()
        || grant_key.trim().is_empty()
        || !is_lower_hex_64(&input.request_digest)
        || input.access_token_jti.trim().is_empty()
    {
        return Err(RepositoryError::Consistency(
            "token issuance commit input is malformed".to_owned(),
        ));
    }
    match (&input.mode, input.response_body.is_some()) {
        (TokenIssuanceMode::Idempotent { grant_key }, true) if !grant_key.trim().is_empty() => {}
        (TokenIssuanceMode::Idempotent { .. }, false) => {
            return Err(RepositoryError::Consistency(
                "idempotent token issuance requires a response body".to_owned(),
            ));
        }
        (TokenIssuanceMode::Idempotent { .. }, true) => {
            return Err(RepositoryError::Consistency(
                "idempotent token issuance grant key is empty".to_owned(),
            ));
        }
        (TokenIssuanceMode::Fresh | TokenIssuanceMode::SingleUse { .. }, false) => {}
        (TokenIssuanceMode::Fresh | TokenIssuanceMode::SingleUse { .. }, true) => {
            return Err(RepositoryError::Consistency(
                "non-idempotent token issuance cannot persist a response body".to_owned(),
            ));
        }
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
fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn token_issued_audit_event(
    input: &CommitTokenIssuance,
    refresh_family_id: Option<Uuid>,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: serde_json::json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION, "tenant_id": input.tenant_id, "issuance_id": input.issuance_id,
            "event_category": "token_lifecycle", "user_id": input.user_id,
            "client_id": input.audit_fields.client_id, "subject_hash": input.audit_fields.subject_hash, "scope": input.audit_fields.scope,
            "audience": input.audit_fields.audience, "access_token_jti": input.access_token_jti, "refresh_token_family_id": refresh_family_id,
        }),
        occurred_at: Utc::now(),
    }
}
fn refresh_rotated_audit_event(
    input: &CommitTokenIssuance,
    refresh: &NewRefreshToken,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "refresh_rotated".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: serde_json::json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION, "tenant_id": input.tenant_id, "issuance_id": input.issuance_id,
            "event_category": "token_lifecycle",
            "client_id": input.audit_fields.client_id, "token_family_id": refresh.family_id, "rotated_from_id": refresh.rotated_from_id,
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

impl TokenRepositoryPort for TokenIssuanceRepository {
    fn validate_response_key_ring(&self) -> TokenFuture<'_, ()> {
        Box::pin(async move {
            TokenIssuanceRepository::validate_response_key_ring(self)
                .await
                .map_err(map_repository_error)
        })
    }
    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
        Box::pin(async move {
            let grant_key = input.mode.grant_key(input.issuance_id);
            validate_commit_input(&input, &grant_key).map_err(map_repository_error)?;
            let grant_hash = grant_key_hash(&grant_key);
            let (response_ciphertext, response_digest, response_envelope_version, response_key_id) =
                response_material(self.response_keys.as_ref(), &input, &grant_hash)
                    .map_err(map_repository_error)?;
            let access_token_expires_at =
                DateTime::<Utc>::from_timestamp(input.access_token_expires_at, 0)
                    .ok_or(TokenPortError::CorruptData)?;
            let expires_at = input
                .refresh_token
                .as_ref()
                .map_or(access_token_expires_at, |refresh| {
                    std::cmp::max(access_token_expires_at, refresh.expires_at)
                });
            let mut guard =
                DiscardOnDrop(Some(self.connection().await.map_err(map_repository_error)?));
            let transaction = guard
                .connection()
                .transaction::<CommitTokenIssuanceResult, CommitTransactionError, _>(
                    async |connection| {
                        diesel::sql_query("SET LOCAL lock_timeout = '2s'")
                            .execute(connection)
                            .await?;
                        let now = Utc::now();
                        if matches!(input.mode, TokenIssuanceMode::Idempotent { .. }) {
                            let jti_expired = oauth_token_issuances::access_token_expires_at
                                .is_null()
                                .or(oauth_token_issuances::access_token_expires_at.le(now));
                            diesel::delete(
                                oauth_token_issuances::table
                                    .filter(oauth_token_issuances::tenant_id.eq(input.tenant_id))
                                    .filter(oauth_token_issuances::client_id.eq(input.client_id))
                                    .filter(oauth_token_issuances::grant_key_blake3.eq(&grant_hash))
                                    .filter(oauth_token_issuances::expires_at.le(now))
                                    .filter(jti_expired),
                            )
                            .execute(connection)
                            .await?;
                        }
                        let inserted = diesel::insert_into(oauth_token_issuances::table)
                            .values((
                                oauth_token_issuances::issuance_id.eq(input.issuance_id),
                                oauth_token_issuances::tenant_id.eq(input.tenant_id),
                                oauth_token_issuances::client_id.eq(input.client_id),
                                oauth_token_issuances::user_id.eq(input.user_id),
                                oauth_token_issuances::grant_key_blake3.eq(&grant_hash),
                                oauth_token_issuances::request_digest.eq(&input.request_digest),
                                oauth_token_issuances::access_token_jti
                                    .eq(Some(input.access_token_jti.clone())),
                                oauth_token_issuances::access_token_expires_at
                                    .eq(Some(access_token_expires_at)),
                                oauth_token_issuances::response_ciphertext
                                    .eq(response_ciphertext.clone()),
                                oauth_token_issuances::response_digest.eq(response_digest.clone()),
                                oauth_token_issuances::response_envelope_version
                                    .eq(response_envelope_version.clone()),
                                oauth_token_issuances::response_key_id.eq(response_key_id.clone()),
                                oauth_token_issuances::expires_at.eq(expires_at),
                                oauth_token_issuances::updated_at.eq(now),
                            ))
                            .on_conflict((
                                oauth_token_issuances::tenant_id,
                                oauth_token_issuances::client_id,
                                oauth_token_issuances::grant_key_blake3,
                            ))
                            .do_nothing()
                            .execute(connection)
                            .await?;
                        if inserted == 0 {
                            let row = oauth_token_issuances::table
                                .filter(oauth_token_issuances::tenant_id.eq(input.tenant_id))
                                .filter(oauth_token_issuances::client_id.eq(input.client_id))
                                .filter(oauth_token_issuances::grant_key_blake3.eq(&grant_hash))
                                .select(TokenIssuanceRow::as_select())
                                .first::<TokenIssuanceRow>(connection)
                                .await
                                .optional()?;
                            let Some(row) = row else {
                                return Err(CommitTransactionError::Repository(
                                    RepositoryError::Consistency(
                                        "token issuance conflict row disappeared".to_owned(),
                                    ),
                                ));
                            };
                            let record = row
                                .into_record(self.response_keys.as_ref())
                                .map_err(CommitTransactionError::Repository)?;
                            return Ok(classify_existing_issuance(&input, record));
                        }
                        if let Some(refresh) = input.refresh_token.as_ref() {
                            match TokenRepository::persist_refresh_token_on_connection(
                                connection,
                                refresh.clone(),
                            )
                            .await
                            .map_err(CommitTransactionError::Repository)?
                            {
                                RefreshTokenPersistResult::Inserted => {}
                                RefreshTokenPersistResult::RotationConflict => {
                                    diesel::update(oauth_token_issuances::table.filter(
                                        oauth_token_issuances::issuance_id.eq(input.issuance_id),
                                    ))
                                    .set((
                                        oauth_token_issuances::access_token_jti.eq(None::<String>),
                                        oauth_token_issuances::access_token_expires_at
                                            .eq(None::<DateTime<Utc>>),
                                        oauth_token_issuances::response_ciphertext
                                            .eq(None::<Vec<u8>>),
                                        oauth_token_issuances::response_digest.eq(None::<String>),
                                        oauth_token_issuances::response_envelope_version
                                            .eq(None::<String>),
                                        oauth_token_issuances::response_key_id.eq(None::<String>),
                                        oauth_token_issuances::updated_at.eq(Utc::now()),
                                    ))
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
                            &token_issued_audit_event(
                                &input,
                                input
                                    .refresh_token
                                    .as_ref()
                                    .map(|refresh| refresh.family_id),
                            ),
                        )
                        .await?;
                        if let Some(refresh) = input
                            .refresh_token
                            .as_ref()
                            .filter(|refresh| refresh.rotated_from_id.is_some())
                        {
                            append_fresh_security_audit_on_connection(
                                connection,
                                &refresh_rotated_audit_event(&input, refresh),
                            )
                            .await?;
                        }
                        Ok(CommitTokenIssuanceResult::Committed)
                    },
                )
                .await;
            match transaction {
                Ok(result) => {
                    guard.return_to_pool();
                    Ok(result)
                }
                Err(CommitTransactionError::Repository(error)) => Err(map_repository_error(error)),
                Err(CommitTransactionError::Diesel(error)) => Err(map_diesel_error(error)),
            }
        })
    }
    fn token_issuance_by_grant<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        grant_key: &'a str,
    ) -> TokenFuture<'a, Option<TokenIssuanceRecord>> {
        Box::pin(async move {
            let mut connection = self.connection().await.map_err(map_repository_error)?;
            let row = oauth_token_issuances::table
                .filter(oauth_token_issuances::tenant_id.eq(tenant_id))
                .filter(oauth_token_issuances::client_id.eq(client_id))
                .filter(oauth_token_issuances::grant_key_blake3.eq(grant_key_hash(grant_key)))
                .filter(oauth_token_issuances::expires_at.gt(Utc::now()))
                .select(TokenIssuanceRow::as_select())
                .first::<TokenIssuanceRow>(&mut connection)
                .await
                .optional()
                .map_err(map_diesel_error)?;
            row.map(|row| row.into_record(self.response_keys.as_ref()))
                .transpose()
                .map_err(map_repository_error)
        })
    }
    fn client_by_protocol_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> TokenFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            self.clients
                .by_client_id(tenant_id, client_id)
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

fn classify_existing_issuance(
    input: &CommitTokenIssuance,
    record: TokenIssuanceRecord,
) -> CommitTokenIssuanceResult {
    if record.request_digest != input.request_digest {
        return CommitTokenIssuanceResult::Conflict;
    }
    match &input.mode {
        TokenIssuanceMode::Idempotent { .. } if record.response_body.is_some() => {
            CommitTokenIssuanceResult::Existing(Box::new(record))
        }
        TokenIssuanceMode::Fresh | TokenIssuanceMode::SingleUse { .. } => {
            CommitTokenIssuanceResult::AlreadyUsed
        }
        TokenIssuanceMode::Idempotent { .. } => CommitTokenIssuanceResult::Conflict,
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
