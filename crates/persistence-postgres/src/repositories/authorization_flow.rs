use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{
    AuthorizationDecisionCommit, AuthorizationDecisionCommitResult, AuthorizationDecisionKind,
    AuthorizationFuture, AuthorizationPortError, AuthorizationRepositoryPort, DeviceGrantFuture,
    DeviceGrantPortError, DeviceGrantRepositoryPort, DeviceGrantWrite, OAuthClient,
    StoredAuthorizationGrant, stored_grant_covers_requested_authorization,
};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{DbPool, get_conn, pool::DiscardOnDrop};

use super::{GrantRepository, MtlsTrustAnchorRepository, OAuthClientRepository};

/// PostgreSQL implementation of the persistence boundary used by authorization flows.
///
/// The tenant is fixed when the composition root constructs the adapter, so protocol
/// code cannot accidentally query a client from a different tenant.
#[derive(Clone)]
pub struct AuthorizationFlowRepository {
    pool: DbPool,
    clients: OAuthClientRepository,
    grants: GrantRepository,
    mtls_trust: MtlsTrustAnchorRepository,
    tenant_id: Uuid,
}

impl AuthorizationFlowRepository {
    #[must_use]
    pub fn new(pool: DbPool, tenant_id: Uuid) -> Self {
        Self {
            pool: pool.clone(),
            clients: OAuthClientRepository::new(pool.clone()),
            grants: GrantRepository::new(pool.clone()),
            mtls_trust: MtlsTrustAnchorRepository::new(pool),
            tenant_id,
        }
    }
}

impl AuthorizationRepositoryPort for AuthorizationFlowRepository {
    fn commit_decision(
        &self,
        mut input: AuthorizationDecisionCommit,
    ) -> AuthorizationFuture<'_, AuthorizationDecisionCommitResult> {
        Box::pin(async move {
            validate_decision_input(&input, self.tenant_id)?;
            bind_decision_audit_digests(&mut input);
            let pool = self.pool.clone();
            // Same physical-connection protection as token issuance. Cancelling
            // the request aborts the task and discards its unconfirmed connection.
            // An already-sent implicit statement may still commit on the server;
            // cancellation is an unknown outcome, not a confirmed rollback.
            let bridge = crate::perf_diagnostic::Bridge::new();
            let mut operation = tokio::task::JoinSet::new();
            operation.spawn_on(
                bridge.clone().run(async move {
                    let mut guard = DiscardOnDrop(Some(
                        get_conn(&pool)
                            .await
                            .map_err(|_| AuthorizationPortError::Unavailable)?,
                    ));
                    let result = if input.decision != AuthorizationDecisionKind::PromptNone {
                        // Drain the complete result stream before publishing an outcome.
                        // ReadyForQuery confirms the implicit commit; the first row alone
                        // does not. Cancellation still discards the connection.
                        execute_decision(guard.connection(), &input).await
                    } else {
                        guard
                            .connection()
                            .transaction::<AuthorizationDecisionCommitResult, diesel::result::Error, _>(
                                async |connection| {
                                    sql_query("SET LOCAL lock_timeout = '2s'")
                                        .execute(connection)
                                        .await?;
                                    // Keep the canonical coverage policy in the
                                    // core, evaluated against a locked live grant.
                                    // Lock principals first, in token-commit order.
                                    let client = sql_query(
                                        "SELECT id FROM oauth_clients \
                                         WHERE tenant_id = $1 AND client_id = $2 AND is_active \
                                         FOR SHARE",
                                    )
                                    .bind::<sql_types::Uuid, _>(input.tenant_id)
                                    .bind::<sql_types::Text, _>(&input.client_id)
                                    .get_result::<DecisionPrincipalRow>(connection)
                                    .await
                                    .optional()?;
                                    let Some(client) = client else {
                                        return Ok(AuthorizationDecisionCommitResult::ClientUnavailable);
                                    };
                                    let actor = sql_query(
                                        "SELECT id FROM users \
                                         WHERE tenant_id = $1 AND id = $2 AND is_active FOR SHARE",
                                    )
                                    .bind::<sql_types::Uuid, _>(input.tenant_id)
                                    .bind::<sql_types::Uuid, _>(input.user_id)
                                    .get_result::<DecisionPrincipalRow>(connection)
                                    .await
                                    .optional()?;
                                    if actor.is_none() {
                                        return Ok(AuthorizationDecisionCommitResult::ClientUnavailable);
                                    }
                                    let grant = sql_query(
                                        "SELECT last_scopes AS scopes, \
                                                last_resource_indicators AS resource_indicators, \
                                                last_authorization_details AS authorization_details \
                                         FROM user_client_grants \
                                         WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 \
                                         FOR SHARE",
                                    )
                                    .bind::<sql_types::Uuid, _>(input.tenant_id)
                                    .bind::<sql_types::Uuid, _>(input.user_id)
                                    .bind::<sql_types::Uuid, _>(client.id)
                                    .get_result::<DecisionGrantRow>(connection)
                                    .await
                                    .optional()?;
                                    if !grant.is_some_and(|grant| {
                                        stored_grant_covers_requested_authorization(
                                            &StoredAuthorizationGrant {
                                                scopes: grant.scopes,
                                                resource_indicators: grant.resource_indicators,
                                                authorization_details: grant.authorization_details,
                                            },
                                            &input.scopes,
                                            &input.resource_indicators,
                                            &input.authorization_details,
                                        )
                                    }) {
                                        return Ok(AuthorizationDecisionCommitResult::GrantUnavailable);
                                    }
                                    execute_decision(connection, &input).await
                                },
                            )
                            .await
                    };
                    if result.is_ok() {
                        guard.return_to_pool();
                    }
                    result.map_err(|_| AuthorizationPortError::Unexpected)
                }),
                &self.pool.runtime,
            );
            let result = operation
                .join_next()
                .await
                .expect("authorization decision task was registered")
                .map_err(|_| AuthorizationPortError::Unavailable)?;
            bridge.resumed();
            result
        })
    }

    fn mtls_trust_anchor_bundle(&self, client_id: Uuid) -> AuthorizationFuture<'_, String> {
        Box::pin(async move {
            let tenant_id = nazo_identity::TenantId::new(self.tenant_id)
                .map_err(|_| AuthorizationPortError::CorruptData)?;
            self.mtls_trust
                .active_bundle(tenant_id, Some(client_id))
                .await
                .map_err(map_repository_error)
        })
    }

    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            self.clients
                .by_client_id(self.tenant_id, client_id)
                .await
                .map_err(map_repository_error)
        })
    }

    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        Box::pin(async move {
            self.grants
                .authorization(self.tenant_id, user_id, client_id)
                .await
                .map(|grant| {
                    grant.map(|grant| StoredAuthorizationGrant {
                        scopes: grant.scopes,
                        resource_indicators: grant.resource_indicators,
                        authorization_details: grant.authorization_details,
                    })
                })
                .map_err(map_repository_error)
        })
    }

    fn client_authentication_snapshot<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<nazo_auth::ClientAuthenticationSnapshot>> {
        Box::pin(async move {
            self.clients
                .authentication_snapshot(self.tenant_id, client_id)
                .await
                .map(|snapshot| {
                    snapshot.map(|(client, secret_salt, client_epoch)| {
                        nazo_auth::ClientAuthenticationSnapshot {
                            client_epoch,
                            client,
                            secret_salt,
                        }
                    })
                })
                .map_err(map_repository_error)
        })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.clients
                .client_secret_digest_matches(self.tenant_id, client_id, candidate_digest)
                .await
                .map_err(map_repository_error)
        })
    }
}

impl DeviceGrantRepositoryPort for AuthorizationFlowRepository {
    fn upsert_grant<'a>(&'a self, write: DeviceGrantWrite<'a>) -> DeviceGrantFuture<'a, ()> {
        Box::pin(async move {
            if write.tenant_id != self.tenant_id {
                return Err(DeviceGrantPortError::CorruptData);
            }
            self.grants
                .ensure(
                    self.tenant_id,
                    write.user_id,
                    write.client_id,
                    write.scopes,
                    write.resource_indicators,
                    write.authorization_details,
                )
                .await
                .map_err(map_device_repository_error)
        })
    }
}

#[derive(QueryableByName)]
struct DecisionPrincipalRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
}

#[derive(QueryableByName)]
struct DecisionGrantRow {
    #[diesel(sql_type = sql_types::Jsonb)]
    scopes: serde_json::Value,
    #[diesel(sql_type = sql_types::Jsonb)]
    resource_indicators: serde_json::Value,
    #[diesel(sql_type = sql_types::Jsonb)]
    authorization_details: serde_json::Value,
}

#[derive(QueryableByName)]
struct DecisionOutcomeRow {
    #[diesel(sql_type = sql_types::Text)]
    outcome: String,
}

// Only hashes of request handles and detailed authorization enter the audit
// export. Bind them to the exact durable input, never caller-supplied labels.
fn bind_decision_audit_digests(input: &mut AuthorizationDecisionCommit) {
    let digest = |value: &str| {
        serde_json::Value::String(blake3::hash(value.as_bytes()).to_hex().to_string())
    };
    let fields = input
        .audit_fields
        .as_object_mut()
        .expect("validated audit object");
    fields.insert("request_id_hash".to_owned(), digest(&input.request_id));
    for (key, value) in [
        (
            "resource_digest",
            (!input.resource_indicators.is_empty())
                .then(|| input.resource_indicators.join("\u{1f}")),
        ),
        (
            "authorization_details_digest",
            input
                .authorization_details
                .as_array()
                .filter(|details| !details.is_empty())
                .map(|_| input.authorization_details.to_string()),
        ),
        ("pushed_request_uri_hash", input.pushed_request_uri.clone()),
    ] {
        if let Some(value) = value {
            fields.insert(key.to_owned(), digest(&value));
        } else {
            fields.remove(key);
        }
    }
}

fn validate_decision_input(
    input: &AuthorizationDecisionCommit,
    tenant_id: Uuid,
) -> Result<(), AuthorizationPortError> {
    if input.tenant_id != tenant_id
        || input.tenant_id.is_nil()
        || input.user_id.is_nil()
        || input.event_id.is_nil()
        || input.request_id.is_empty()
        || input.request_id.len() > 512
        || input.client_id.is_empty()
        || input.client_id.len() > 512
        || input
            .pushed_request_uri
            .as_ref()
            .is_some_and(|uri| uri.is_empty() || uri.len() > 1024)
        || input.retain_until < input.valid_until
        || input.retain_until < input.occurred_at
        || !input.audit_fields.is_object()
        || !input.authorization_details.is_array()
    {
        return Err(AuthorizationPortError::CorruptData);
    }
    Ok(())
}

// Both execution modes share the exact statement and outcome validation.
async fn execute_decision(
    connection: &mut diesel_async::AsyncPgConnection,
    input: &AuthorizationDecisionCommit,
) -> diesel::QueryResult<AuthorizationDecisionCommitResult> {
    let rows = sql_query(
        "SELECT public.nazo_commit_authorization_decision(\
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) AS outcome",
    )
    .bind::<sql_types::Uuid, _>(input.tenant_id)
    .bind::<sql_types::Uuid, _>(input.user_id)
    .bind::<sql_types::Text, _>(&input.client_id)
    .bind::<sql_types::Text, _>(&input.request_id)
    .bind::<sql_types::Nullable<sql_types::Text>, _>(input.pushed_request_uri.as_deref())
    .bind::<sql_types::Timestamptz, _>(input.valid_until)
    .bind::<sql_types::Timestamptz, _>(input.retain_until)
    .bind::<sql_types::Text, _>(input.decision.as_str())
    .bind::<sql_types::Uuid, _>(input.event_id)
    .bind::<sql_types::Timestamptz, _>(input.occurred_at)
    .bind::<sql_types::Jsonb, _>(&input.audit_fields)
    .bind::<sql_types::Jsonb, _>(serde_json::json!(input.scopes))
    .bind::<sql_types::Jsonb, _>(serde_json::json!(input.resource_indicators))
    .bind::<sql_types::Jsonb, _>(&input.authorization_details)
    .load::<DecisionOutcomeRow>(connection)
    .await?;
    let mut rows = rows.into_iter();
    let row = rows.next().ok_or(diesel::result::Error::NotFound)?;
    if rows.next().is_some() {
        return Err(diesel::result::Error::DeserializationError(Box::new(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "multiple decision outcomes",
            ),
        )));
    }
    match row.outcome.as_str() {
        "committed" => Ok(AuthorizationDecisionCommitResult::Committed),
        "conflict" => Ok(AuthorizationDecisionCommitResult::Conflict),
        "expired" => Ok(AuthorizationDecisionCommitResult::Expired),
        "client_unavailable" => Ok(AuthorizationDecisionCommitResult::ClientUnavailable),
        _ => Err(diesel::result::Error::DeserializationError(Box::new(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown authorization decision outcome",
            ),
        ))),
    }
}

fn map_repository_error(error: RepositoryError) -> AuthorizationPortError {
    match error {
        RepositoryError::Unavailable => AuthorizationPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
            AuthorizationPortError::Conflict
        }
        RepositoryError::Consistency(_) => AuthorizationPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
            AuthorizationPortError::Unexpected
        }
    }
}

fn map_device_repository_error(error: RepositoryError) -> DeviceGrantPortError {
    match error {
        RepositoryError::Unavailable => DeviceGrantPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
            DeviceGrantPortError::Conflict
        }
        RepositoryError::Consistency(_) => DeviceGrantPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
            DeviceGrantPortError::Unexpected
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/authorization_flow.rs"]
mod tests;
