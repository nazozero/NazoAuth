use chrono::{DateTime, Utc};
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::BackchannelLogoutDelivery;
use nazo_identity::ports::RepositoryError;
use nazo_identity::scim::ScimTokenCredential;
use nazo_runtime_modules::{ModuleEventRecord, ModuleEventState, ModuleEventType};
use uuid::Uuid;

use crate::{
    DbPool,
    rows::auth::BackchannelLogoutDeliveryRow,
    schema::{
        backchannel_logout_deliveries, runtime_module_state_events, scim_audit_events, scim_tokens,
    },
};

#[derive(Clone)]
pub struct AuditRepository {
    pool: DbPool,
}

impl AuditRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn active_scim_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<ScimTokenCredential>, RepositoryError> {
        let mut connection = self.connection().await?;
        scim_tokens::table
            .filter(scim_tokens::token_hash.eq(token_hash))
            .filter(scim_tokens::revoked_at.is_null())
            .filter(
                scim_tokens::expires_at
                    .is_null()
                    .or(scim_tokens::expires_at.gt(diesel::dsl::now)),
            )
            .select((scim_tokens::id, scim_tokens::tenant_id, scim_tokens::scopes))
            .first::<(Uuid, Uuid, serde_json::Value)>(&mut connection)
            .await
            .optional()
            .map(|value| {
                value.map(|(id, tenant_id, scopes)| ScimTokenCredential {
                    id,
                    tenant_id,
                    scopes: json_string_array(&scopes),
                })
            })
            .map_err(map_error)
    }

    pub async fn record_scim_token_use(
        &self,
        token_id: Uuid,
        tenant_id: Uuid,
        scopes: &[String],
        ip_hash: Option<String>,
        user_agent_hash: Option<String>,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<(), diesel::result::Error, _>(async |connection| {
                diesel::update(scim_tokens::table.find(token_id))
                    .set((
                        scim_tokens::last_used_at.eq(diesel::dsl::now),
                        scim_tokens::updated_at.eq(diesel::dsl::now),
                    ))
                    .execute(connection)
                    .await?;
                diesel::insert_into(scim_audit_events::table)
                    .values((
                        scim_audit_events::tenant_id.eq(tenant_id),
                        scim_audit_events::scim_token_id.eq(Some(token_id)),
                        scim_audit_events::event_type.eq("scim_token_used"),
                        scim_audit_events::scopes.eq(serde_json::json!(scopes)),
                        scim_audit_events::ip_hash.eq(ip_hash),
                        scim_audit_events::user_agent_hash.eq(user_agent_hash),
                    ))
                    .execute(connection)
                    .await?;
                Ok(())
            })
            .await
            .map_err(map_error)
    }

    pub async fn enqueue_backchannel_logout(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_public_id: &str,
        logout_uri: &str,
        logout_token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::insert_into(backchannel_logout_deliveries::table)
            .values((
                backchannel_logout_deliveries::tenant_id.eq(tenant_id),
                backchannel_logout_deliveries::client_id.eq(client_id),
                backchannel_logout_deliveries::client_public_id.eq(client_public_id),
                backchannel_logout_deliveries::logout_uri.eq(logout_uri),
                backchannel_logout_deliveries::logout_token.eq(logout_token),
                backchannel_logout_deliveries::expires_at.eq(expires_at),
            ))
            .execute(&mut connection)
            .await
            .map_err(map_error)?;
        Ok(())
    }

    pub async fn claim_due_backchannel_logout(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> Result<Vec<BackchannelLogoutDelivery>, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::sql_query(
            r#"
            UPDATE backchannel_logout_deliveries
            SET attempts = attempts + 1, locked_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id IN (
                SELECT id FROM backchannel_logout_deliveries
                WHERE delivered_at IS NULL AND failed_at IS NULL
                  AND expires_at > CURRENT_TIMESTAMP
                  AND next_attempt_at <= CURRENT_TIMESTAMP
                  AND (locked_at IS NULL OR locked_at < CURRENT_TIMESTAMP - ($2::int * INTERVAL '1 second'))
                ORDER BY next_attempt_at ASC, created_at ASC
                FOR UPDATE SKIP LOCKED LIMIT $1
            )
            RETURNING id, logout_uri, logout_token, attempts, expires_at
            "#,
        )
        .bind::<diesel::sql_types::BigInt, _>(limit)
        .bind::<diesel::sql_types::Integer, _>(lock_timeout_seconds)
        .load::<BackchannelLogoutDeliveryRow>(&mut connection)
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(map_error)
    }

    pub async fn complete_backchannel_logout(
        &self,
        delivery_id: Uuid,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::update(backchannel_logout_deliveries::table.find(delivery_id))
            .set((
                backchannel_logout_deliveries::delivered_at.eq(diesel::dsl::now),
                backchannel_logout_deliveries::locked_at.eq::<Option<DateTime<Utc>>>(None),
                backchannel_logout_deliveries::updated_at.eq(diesel::dsl::now),
            ))
            .execute(&mut connection)
            .await
            .map_err(map_error)?;
        Ok(())
    }

    pub async fn fail_backchannel_logout(
        &self,
        delivery_id: Uuid,
        next_attempt_at: Option<DateTime<Utc>>,
        last_error: &str,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        if let Some(next_attempt_at) = next_attempt_at {
            diesel::update(backchannel_logout_deliveries::table.find(delivery_id))
                .set((
                    backchannel_logout_deliveries::next_attempt_at.eq(next_attempt_at),
                    backchannel_logout_deliveries::locked_at.eq::<Option<DateTime<Utc>>>(None),
                    backchannel_logout_deliveries::last_error.eq(Some(last_error)),
                    backchannel_logout_deliveries::updated_at.eq(diesel::dsl::now),
                ))
                .execute(&mut connection)
                .await
                .map_err(map_error)?;
        } else {
            diesel::update(backchannel_logout_deliveries::table.find(delivery_id))
                .set((
                    backchannel_logout_deliveries::failed_at.eq(diesel::dsl::now),
                    backchannel_logout_deliveries::locked_at.eq::<Option<DateTime<Utc>>>(None),
                    backchannel_logout_deliveries::last_error.eq(Some(last_error)),
                    backchannel_logout_deliveries::updated_at.eq(diesel::dsl::now),
                ))
                .execute(&mut connection)
                .await
                .map_err(map_error)?;
        }
        Ok(())
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

pub(super) async fn append_runtime_event(
    connection: &mut AsyncPgConnection,
    event: &ModuleEventRecord,
) -> Result<(), RepositoryError> {
    let event_id = Uuid::parse_str(&event.event_id).map_err(|error| {
        RepositoryError::Unexpected(format!("invalid runtime event id: {error}"))
    })?;
    let actor_id = event
        .actor_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|error| {
            RepositoryError::Unexpected(format!("invalid runtime actor id: {error}"))
        })?;
    diesel::insert_into(runtime_module_state_events::table)
        .values((
            runtime_module_state_events::event_id.eq(event_id),
            runtime_module_state_events::module_id.eq(module_id(event.module_id)),
            runtime_module_state_events::event_type.eq(event_type(event.event_type)),
            runtime_module_state_events::revision.eq(revision(event.revision)?),
            runtime_module_state_events::instance_id.eq(event.instance_id.as_deref()),
            runtime_module_state_events::actor_id.eq(actor_id),
            runtime_module_state_events::reason.eq(event.reason.as_deref()),
            runtime_module_state_events::before_state.eq(event.before.map(event_state)),
            runtime_module_state_events::after_state.eq(event.after.map(event_state)),
            runtime_module_state_events::outcome_code.eq(event.outcome_code.as_deref()),
            runtime_module_state_events::occurred_at.eq(DateTime::<Utc>::from(event.occurred_at)),
        ))
        .execute(connection)
        .await
        .map_err(map_error)?;
    Ok(())
}

pub(super) const fn module_id(value: nazo_runtime_modules::ModuleId) -> &'static str {
    use nazo_runtime_modules::ModuleId;
    match value {
        ModuleId::DeviceAuthorization => "device_authorization",
        ModuleId::TokenExchange => "token_exchange",
        ModuleId::JwtBearerGrant => "jwt_bearer_grant",
        ModuleId::Ciba => "ciba",
        ModuleId::DynamicClientRegistration => "dynamic_client_registration",
        ModuleId::RequestObjects => "request_objects",
        ModuleId::Jarm => "jarm",
        ModuleId::AuthorizationDetails => "authorization_details",
        ModuleId::HttpMessageSignatures => "http_message_signatures",
        ModuleId::Scim => "scim",
        ModuleId::NativeSso => "native_sso",
        ModuleId::FrontchannelLogout => "frontchannel_logout",
        ModuleId::SessionManagement => "session_management",
    }
}

pub(super) const fn desired_mode(value: nazo_runtime_modules::DesiredMode) -> &'static str {
    use nazo_runtime_modules::DesiredMode;
    match value {
        DesiredMode::Inherit => "inherit",
        DesiredMode::Enabled => "enabled",
        DesiredMode::Disabled => "disabled",
    }
}

pub(super) const fn actual_state(value: nazo_runtime_modules::ModuleState) -> &'static str {
    use nazo_runtime_modules::ModuleState;
    match value {
        ModuleState::Disabled => "disabled",
        ModuleState::Starting => "starting",
        ModuleState::Enabled => "enabled",
        ModuleState::Draining => "draining",
        ModuleState::Failed => "failed",
    }
}

const fn event_type(value: ModuleEventType) -> &'static str {
    match value {
        ModuleEventType::DesiredStateChanged => "desired_state_changed",
        ModuleEventType::TransitionStarted => "transition_started",
        ModuleEventType::TransitionCompleted => "transition_completed",
        ModuleEventType::TransitionFailed => "transition_failed",
        ModuleEventType::DrainStarted => "drain_started",
        ModuleEventType::DrainCompleted => "drain_completed",
        ModuleEventType::StaleTransitionDiscarded => "stale_transition_discarded",
    }
}

const fn event_state(value: ModuleEventState) -> &'static str {
    match value {
        ModuleEventState::Desired(mode) => desired_mode(mode),
        ModuleEventState::Actual(state) => actual_state(state),
    }
}

pub(super) fn revision(
    value: nazo_runtime_modules::ModuleRevision,
) -> Result<i64, RepositoryError> {
    i64::try_from(value.get()).map_err(|_| {
        RepositoryError::Unexpected("runtime revision exceeds PostgreSQL BIGINT".to_owned())
    })
}

pub(super) fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

fn json_string_array(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::trim))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
