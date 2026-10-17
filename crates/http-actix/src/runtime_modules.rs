use std::{
    borrow::Cow,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json, Path, Query},
};
use chrono::{DateTime, Utc};
use nazo_identity::{CurrentSession, SessionResolution, SessionService};
use nazo_oauth_server::contracts::runtime_modules::{
    RuntimeModuleAdminError, RuntimeModuleAdministration,
};
use nazo_runtime_modules::{
    DesiredMode, DesiredStateUpdate, DesiredStateUpdateOutcome, DisablePolicy, ModuleEventRecord,
    ModuleEventState, ModuleEventType, ModuleId, ModuleRevision, ModuleState, RuntimeModuleView,
};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};
use serde_json::json;

use crate::{
    SessionCookieConfig, csrf_error, json_response_no_store, json_response_status_no_store,
    oauth_error,
};

const MAX_REASON_CHARS: usize = 500;

/// Focused dependencies for runtime-module administration endpoints.
#[derive(Clone)]
pub struct RuntimeModuleAdminEndpoint {
    sessions: SessionService,
    cookies: SessionCookieConfig,
    administration: Arc<dyn RuntimeModuleAdministration>,
    now: fn() -> SystemTime,
}

impl RuntimeModuleAdminEndpoint {
    #[must_use]
    pub fn new(
        sessions: SessionService,
        cookies: SessionCookieConfig,
        administration: Arc<dyn RuntimeModuleAdministration>,
    ) -> Self {
        Self::with_clock(sessions, cookies, administration, SystemTime::now)
    }

    #[must_use]
    pub fn with_clock(
        sessions: SessionService,
        cookies: SessionCookieConfig,
        administration: Arc<dyn RuntimeModuleAdministration>,
        now: fn() -> SystemTime,
    ) -> Self {
        Self {
            sessions,
            cookies,
            administration,
            now,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeModulePatch {
    desired_state: DesiredMode,
    expected_revision: u64,
    reason: String,
    #[serde(default)]
    cascade: bool,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeModuleEventPageQuery {
    page: Option<i32>,
    page_size: Option<i32>,
}

pub async fn admin_runtime_modules(
    endpoint: Data<RuntimeModuleAdminEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_runtime_admin(&endpoint, &request, false).await {
        return response;
    }
    match endpoint.administration.list().await {
        Ok(items) => json_response_no_store(RuntimeModuleList { items: &items }),
        Err(error) => management_error(error),
    }
}

pub async fn admin_runtime_module_events(
    endpoint: Data<RuntimeModuleAdminEndpoint>,
    request: HttpRequest,
    Query(query): Query<RuntimeModuleEventPageQuery>,
) -> HttpResponse {
    if let Err(response) = require_runtime_admin(&endpoint, &request, false).await {
        return response;
    }
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20);
    if page < 1 || !(1..=100).contains(&page_size) {
        return no_store(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "page and page_size are out of bounds.",
        ));
    }
    let offset = i64::from(page - 1) * i64::from(page_size);
    match endpoint
        .administration
        .events(offset, i64::from(page_size))
        .await
    {
        Ok(result) => json_response_no_store(RuntimeEventPage {
            total: result.total,
            page,
            page_size,
            items: &result.events,
        }),
        Err(error) => management_error(error),
    }
}

pub async fn admin_patch_runtime_module(
    endpoint: Data<RuntimeModuleAdminEndpoint>,
    request: HttpRequest,
    path: Path<String>,
    Json(mut payload): Json<RuntimeModulePatch>,
) -> HttpResponse {
    if !endpoint.cookies.has_valid_csrf_token(&request, None) {
        return no_store(csrf_error());
    }
    let admin = match require_runtime_admin(&endpoint, &request, true).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let Some(module_id) = parse_module_id(&path) else {
        return no_store(oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "Unknown runtime module.",
        ));
    };
    if let Err(description) = validate_reason(&mut payload.reason, payload.cascade) {
        return no_store(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            description,
        ));
    }
    let now = (endpoint.now)();
    let update = DesiredStateUpdate {
        module_id,
        desired_state: payload.desired_state,
        expected_revision: (payload.expected_revision != 0)
            .then(|| ModuleRevision::new(payload.expected_revision)),
        actor_id: admin.user().id().to_string(),
        reason: payload.reason,
        changed_at: now,
    };
    match endpoint.administration.update_desired(update).await {
        Ok(DesiredStateUpdateOutcome::Accepted {
            desired,
            actual_state,
        }) => json_response_status_no_store(
            StatusCode::ACCEPTED,
            json!({
                "module_id": module_id,
                "desired_state": desired.mode,
                "revision": desired.revision.get(),
                "actual_state": actual_state,
                "status_url": "/admin/runtime-modules",
            }),
        ),
        Ok(DesiredStateUpdateOutcome::Stale { current_revision }) => json_response_status_no_store(
            StatusCode::CONFLICT,
            json!({
                "error": "revision_conflict",
                "error_description": "Runtime module desired state changed concurrently.",
                "current_revision": current_revision.map_or(0, ModuleRevision::get),
            }),
        ),
        Err(error) => management_error(error),
    }
}

async fn require_runtime_admin(
    endpoint: &RuntimeModuleAdminEndpoint,
    request: &HttpRequest,
    require_recent_mfa: bool,
) -> Result<Box<CurrentSession<nazo_identity::Principal>>, HttpResponse> {
    let Some(session_id) = endpoint.cookies.session_id(request) else {
        return Err(admin_required());
    };
    let now = (endpoint.now)();
    let now_seconds = unix_timestamp(now);
    let session = match endpoint
        .sessions
        .current_principal(&session_id, now_seconds)
        .await
    {
        Ok(SessionResolution::Present(session)) => session,
        Ok(SessionResolution::Missing | SessionResolution::Invalidated) => {
            return Err(admin_required());
        }
        Err(_) => {
            return Err(no_store(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Session lookup failed.",
            )));
        }
    };
    if session.user().admin_level().unwrap_or(0) < 2 {
        return Err(no_store(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Administrator level 2 is required.",
        )));
    }
    if require_recent_mfa && !recent_mfa(&session, now_seconds) {
        return Err(no_store(oauth_error(
            StatusCode::PRECONDITION_REQUIRED,
            "mfa_step_up_required",
            "Recent MFA verification is required.",
        )));
    }
    Ok(session)
}

fn admin_required() -> HttpResponse {
    no_store(oauth_error(
        StatusCode::FORBIDDEN,
        "access_denied",
        "Administrator access is required.",
    ))
}

fn recent_mfa(session: &CurrentSession<nazo_identity::Principal>, now: i64) -> bool {
    nazo_identity::session::recent_interactive_mfa(session.auth_time(), session.amr(), now)
}

fn validate_reason(reason: &mut String, cascade: bool) -> Result<(), &'static str> {
    let trimmed = reason.trim();
    if trimmed.is_empty() || trimmed.chars().take(MAX_REASON_CHARS + 1).count() > MAX_REASON_CHARS {
        return Err("reason must contain between 1 and 500 characters.");
    }
    if cascade {
        return Err("cascade is not supported; change dependent modules explicitly.");
    }
    let start = reason.len() - reason.trim_start().len();
    let end = start + trimmed.len();
    reason.truncate(end);
    reason.drain(..start);
    Ok(())
}

fn management_error(error: RuntimeModuleAdminError) -> HttpResponse {
    match error {
        RuntimeModuleAdminError::Unavailable => no_store(oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Runtime module state is unavailable.",
        )),
        RuntimeModuleAdminError::ServiceNotConstructed => no_store(oauth_error(
            StatusCode::CONFLICT,
            "service_not_constructed",
            "Runtime module service was not constructed at startup.",
        )),
        RuntimeModuleAdminError::PolicyConflict => no_store(oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "Runtime module dependencies or disable policy reject this change.",
        )),
        RuntimeModuleAdminError::CatalogInconsistent => no_store(oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Runtime module catalog is inconsistent.",
        )),
    }
}

#[derive(Serialize)]
struct RuntimeModuleList<'a> {
    #[serde(serialize_with = "serialize_modules")]
    items: &'a [RuntimeModuleView],
}

fn serialize_modules<S: Serializer>(
    items: &[RuntimeModuleView],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(items.iter().map(RuntimeModuleResponse))
}

#[derive(Serialize)]
struct RuntimeEventPage<'a> {
    total: i64,
    page: i32,
    page_size: i32,
    #[serde(serialize_with = "serialize_events")]
    items: &'a [ModuleEventRecord],
}

fn serialize_events<S: Serializer>(
    items: &[ModuleEventRecord],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(items.iter().map(RuntimeEventResponse))
}

struct AllowedActions<'a>(&'a [DesiredMode]);

impl Serialize for AllowedActions<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().copied().map(action_name))
    }
}

struct RuntimeModuleResponse<'a>(&'a RuntimeModuleView);

impl Serialize for RuntimeModuleResponse<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let module = self.0;
        let mut map = serializer.serialize_map(Some(15))?;
        map.serialize_entry("module_id", &module.module_id)?;
        map.serialize_entry("description", &module_description(module.module_id))?;
        map.serialize_entry("desired_state", &module.desired_state)?;
        map.serialize_entry("resolved_enabled", &module.resolved_enabled)?;
        map.serialize_entry("actual_state", &module.actual_state)?;
        map.serialize_entry("revision", &module.revision.map_or(0, ModuleRevision::get))?;
        map.serialize_entry(
            "transition_revision",
            &module.transition_revision.map(ModuleRevision::get),
        )?;
        map.serialize_entry(
            "applied_revision",
            &module.applied_revision.map(ModuleRevision::get),
        )?;
        map.serialize_entry("dependencies", &module.dependencies)?;
        map.serialize_entry("dependents", &module.dependents)?;
        map.serialize_entry("allowed_actions", &AllowedActions(&module.allowed_actions))?;
        map.serialize_entry(
            "disable_policy",
            &disable_policy_name(module.disable_policy),
        )?;
        map.serialize_entry("drain_deadline", &module.drain_deadline.map(timestamp))?;
        map.serialize_entry("failure_code", &module.failure_code)?;
        map.serialize_entry("updated_at", &timestamp(module.updated_at))?;
        map.end()
    }
}

struct RuntimeEventResponse<'a>(&'a ModuleEventRecord);

impl Serialize for RuntimeEventResponse<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let event = self.0;
        let mut map = serializer.serialize_map(Some(11))?;
        map.serialize_entry("event_id", &event.event_id)?;
        map.serialize_entry("module_id", &event.module_id)?;
        map.serialize_entry("event_type", &event_type_name(event.event_type))?;
        map.serialize_entry("instance_id", &event.instance_id)?;
        map.serialize_entry("actor_id", &event.actor_id)?;
        map.serialize_entry("reason", &event.reason)?;
        map.serialize_entry("before_state", &event.before.map(event_state_name))?;
        map.serialize_entry("after_state", &event.after.map(event_state_name))?;
        map.serialize_entry("revision", &event.revision.get())?;
        map.serialize_entry("outcome_code", &event.outcome_code)?;
        map.serialize_entry("created_at", &timestamp(event.occurred_at))?;
        map.end()
    }
}

fn no_store(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        actix_web::http::header::PRAGMA,
        actix_web::http::header::HeaderValue::from_static("no-cache"),
    );
    response
}

fn parse_module_id(value: &str) -> Option<ModuleId> {
    ModuleId::deserialize(serde::de::value::StrDeserializer::<serde::de::value::Error>::new(value))
        .ok()
}

const fn module_description(value: ModuleId) -> &'static str {
    match value {
        ModuleId::DeviceAuthorization => "Device Authorization Grant",
        ModuleId::TokenExchange => "OAuth Token Exchange",
        ModuleId::JwtBearerGrant => "JWT Bearer Grant",
        ModuleId::Ciba => "Client-Initiated Backchannel Authentication",
        ModuleId::DynamicClientRegistration => "Dynamic Client Registration",
        ModuleId::RequestObjects => "OAuth Request Objects",
        ModuleId::Jarm => "JWT-Secured Authorization Response Mode",
        ModuleId::AuthorizationDetails => "Rich Authorization Requests",
        ModuleId::HttpMessageSignatures => "HTTP Message Signatures",
        ModuleId::Scim => "SCIM",
        ModuleId::ScimSecurityEvents => "SCIM Security Events",
        ModuleId::NativeSso => "Native SSO",
        ModuleId::FrontchannelLogout => "Front-Channel Logout",
        ModuleId::SessionManagement => "OIDC Session Management",
        ModuleId::Openid4vciIssuer => "OpenID4VCI Credential Issuer",
        ModuleId::Openid4vpVerifier => "OpenID4VP Verifier",
    }
}

const fn action_name(value: DesiredMode) -> &'static str {
    match value {
        DesiredMode::Enabled => "enable",
        DesiredMode::Disabled => "disable",
    }
}

const fn actual_state_name(value: ModuleState) -> &'static str {
    match value {
        ModuleState::Disabled => "disabled",
        ModuleState::Starting => "starting",
        ModuleState::Enabled => "enabled",
        ModuleState::Draining => "draining",
        ModuleState::Failed => "failed",
    }
}

fn disable_policy_name(value: DisablePolicy) -> Cow<'static, str> {
    match value {
        DisablePolicy::Immediate => Cow::Borrowed("immediate"),
        DisablePolicy::FinishExecutingRequests => Cow::Borrowed("finish_executing_requests"),
        DisablePolicy::DrainStoredTransactions { max_duration } => Cow::Owned(format!(
            "drain_stored_transactions:{}s",
            max_duration.as_secs()
        )),
        DisablePolicy::NotRuntimeDisableable => Cow::Borrowed("not_runtime_disableable"),
    }
}

const fn event_type_name(value: ModuleEventType) -> &'static str {
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

const fn event_state_name(value: ModuleEventState) -> &'static str {
    match value {
        ModuleEventState::Desired(value) => match value {
            nazo_runtime_modules::HistoricalDesiredMode::Inherit => "inherit",
            nazo_runtime_modules::HistoricalDesiredMode::Enabled => "enabled",
            nazo_runtime_modules::HistoricalDesiredMode::Disabled => "disabled",
        },
        ModuleEventState::Actual(value) => actual_state_name(value),
    }
}

fn timestamp(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339()
}

fn unix_timestamp(value: SystemTime) -> i64 {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "../tests/unit/runtime_modules.rs"]
mod tests;
