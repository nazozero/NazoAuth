use std::time::{Duration, SystemTime};

use actix_web::http::{StatusCode, header};
use actix_web::web::{Data, Json, Path, Query};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use nazo_identity::ports::RepositoryError;
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DisablePolicy, ModuleEventState, ModuleEventType, ModuleId,
    ModuleRevision, ModuleState, ModuleStateRepository, RegistryError,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::runtime_modules::RuntimeModules;
use crate::support::{
    AdminSessionHandles, csrf_error, has_valid_csrf_token_for_cookies, json_response_no_store,
    oauth_error,
};

const MFA_STEP_UP_MAX_AGE: Duration = Duration::from_secs(5 * 60);
const MAX_REASON_CHARS: usize = 500;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeModulePatch {
    desired_state: DesiredMode,
    expected_revision: u64,
    reason: String,
    #[serde(default)]
    cascade: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EventPageQuery {
    page: Option<i32>,
    page_size: Option<i32>,
}

pub(crate) async fn admin_runtime_modules(
    admin_sessions: Data<AdminSessionHandles>,
    modules: Data<RuntimeModules>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_runtime_admin(&admin_sessions, &req, false).await {
        return response;
    }
    match runtime_module_items(&modules).await {
        Ok(items) => json_response_no_store(json!({ "items": items })),
        Err(error) => runtime_repository_error(error, "runtime module state lookup failed"),
    }
}

pub(crate) async fn admin_runtime_module_events(
    admin_sessions: Data<AdminSessionHandles>,
    modules: Data<RuntimeModules>,
    req: HttpRequest,
    Query(query): Query<EventPageQuery>,
) -> HttpResponse {
    if let Err(response) = require_runtime_admin(&admin_sessions, &req, false).await {
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
    match modules
        .repository
        .page_events(offset, i64::from(page_size))
        .await
    {
        Ok(result) => {
            let items: Vec<_> = result.events.iter().map(runtime_event_json).collect();
            json_response_no_store(json!({
                "total": result.total,
                "page": page,
                "page_size": page_size,
                "items": items,
            }))
        }
        Err(error) => runtime_repository_error(error, "runtime module event lookup failed"),
    }
}

pub(crate) async fn admin_patch_runtime_module(
    admin_sessions: Data<AdminSessionHandles>,
    modules: Data<RuntimeModules>,
    req: HttpRequest,
    path: Path<String>,
    Json(payload): Json<RuntimeModulePatch>,
) -> HttpResponse {
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        &req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return no_store(csrf_error());
    }
    let admin = match require_runtime_admin(&admin_sessions, &req, true).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let module_id = match parse_module_id(&path.into_inner()) {
        Some(module_id) => module_id,
        None => {
            return no_store(oauth_error(
                StatusCode::NOT_FOUND,
                "invalid_request",
                "Unknown runtime module.",
            ));
        }
    };
    let reason = match validated_reason(&payload) {
        Ok(reason) => reason,
        Err(description) => {
            return no_store(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                description,
            ));
        }
    };
    let expected_revision =
        (payload.expected_revision != 0).then(|| ModuleRevision::new(payload.expected_revision));
    let outcome = modules
        .registry
        .set_desired_mode(
            module_id,
            payload.desired_state,
            expected_revision,
            Some(admin.user.id().to_string()),
            Some(reason),
            SystemTime::now(),
        )
        .await;
    let desired = match outcome {
        Ok(CasOutcome::Applied(desired)) => desired,
        Ok(CasOutcome::Stale { current }) => {
            return json_response_with_status_no_store(
                StatusCode::CONFLICT,
                json!({
                    "error": "revision_conflict",
                    "error_description": "Runtime module desired state changed concurrently.",
                    "current_revision": current.map_or(0, |value| value.revision.get()),
                }),
            );
        }
        Err(error) => return registry_error(error),
    };
    let actual = match modules
        .repository
        .read_instance(&modules.instance_id, module_id)
        .await
    {
        Ok(actual) => actual.map_or(ModuleState::Disabled, |record| record.state),
        Err(error) => return runtime_repository_error(error, "runtime module state lookup failed"),
    };
    accepted_response(json!({
        "module_id": module_id_name(module_id),
        "desired_state": desired_mode_name(desired.mode),
        "revision": desired.revision.get(),
        "actual_state": actual_state_name(actual),
        "status_url": "/admin/runtime-modules",
    }))
}

async fn require_runtime_admin(
    admin_sessions: &AdminSessionHandles,
    req: &HttpRequest,
    require_recent_mfa: bool,
) -> Result<crate::support::CurrentSession, HttpResponse> {
    let session = match admin_sessions.current_session(req).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return Err(no_store(oauth_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Administrator access is required.",
            )));
        }
        Err(error) => {
            tracing::warn!(%error, "failed to resolve runtime module administrator");
            return Err(no_store(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Session lookup failed.",
            )));
        }
    };
    if session.user.admin_level() < 2 {
        return Err(no_store(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Administrator level 2 is required.",
        )));
    }
    if require_recent_mfa && !recent_mfa(&session, Utc::now().timestamp()) {
        return Err(no_store(oauth_error(
            StatusCode::PRECONDITION_REQUIRED,
            "mfa_step_up_required",
            "Recent MFA verification is required.",
        )));
    }
    Ok(session)
}

fn recent_mfa(session: &crate::support::CurrentSession, now: i64) -> bool {
    recent_mfa_values(&session.amr, session.auth_time, now)
}

fn recent_mfa_values(amr: &[String], auth_time: i64, now: i64) -> bool {
    let max_age = i64::try_from(MFA_STEP_UP_MAX_AGE.as_secs()).expect("MFA max age fits i64");
    amr.iter().any(|method| method == "mfa")
        && auth_time <= now.saturating_add(30)
        && now.saturating_sub(auth_time) <= max_age
}

fn validated_reason(payload: &RuntimeModulePatch) -> Result<String, &'static str> {
    let reason = payload.reason.trim();
    if reason.is_empty() || reason.chars().count() > MAX_REASON_CHARS {
        return Err("reason must contain between 1 and 500 characters.");
    }
    if payload.cascade {
        return Err("cascade is not supported; change dependent modules explicitly.");
    }
    Ok(reason.to_owned())
}

async fn runtime_module_items(modules: &RuntimeModules) -> Result<Vec<Value>, RepositoryError> {
    let snapshot = modules.registry.snapshot();
    let mut items = Vec::with_capacity(ModuleId::ALL.len());
    for module_id in ModuleId::ALL {
        let desired = modules.repository.read_desired(module_id).await?;
        let instance = modules
            .repository
            .read_instance(&modules.instance_id, module_id)
            .await?;
        let mode = desired
            .as_ref()
            .map_or(DesiredMode::Inherit, |record| record.mode);
        let revision = desired.as_ref().map_or(0, |record| record.revision.get());
        let actual_state = instance.as_ref().map_or_else(
            || {
                if snapshot.admits(module_id) {
                    ModuleState::Enabled
                } else {
                    ModuleState::Disabled
                }
            },
            |record| record.state,
        );
        let spec = modules
            .catalog
            .spec(module_id)
            .expect("validated runtime module catalog is complete");
        let dependencies: Vec<_> = spec
            .dependencies
            .iter()
            .copied()
            .map(module_id_name)
            .collect();
        let dependents: Vec<_> = modules
            .catalog
            .specs()
            .values()
            .filter(|candidate| candidate.dependencies.contains(&module_id))
            .map(|candidate| module_id_name(candidate.id))
            .collect();
        let allowed_actions = allowed_actions(modules, module_id, mode, &snapshot.accepting);
        let updated_at = instance
            .as_ref()
            .map(|record| record.updated_at)
            .or_else(|| desired.as_ref().map(|record| record.updated_at))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        items.push(json!({
            "module_id": module_id_name(module_id),
            "description": module_description(module_id),
            "desired_state": desired_mode_name(mode),
            "resolved_enabled": mode.resolve(modules.catalog.inherited_enabled(module_id)),
            "actual_state": actual_state_name(actual_state),
            "revision": revision,
            "transition_revision": instance.as_ref().map(|record| record.transition_revision.get()),
            "applied_revision": instance.as_ref().and_then(|record| record.applied_revision).map(ModuleRevision::get),
            "dependencies": dependencies,
            "dependents": dependents,
            "allowed_actions": allowed_actions,
            "disable_policy": disable_policy_name(spec.disable_policy),
            "drain_deadline": instance.as_ref().and_then(|record| record.drain_deadline).map(timestamp),
            "failure_code": instance.as_ref().and_then(|record| record.error_code.as_deref()),
            "updated_at": timestamp(updated_at),
        }));
    }
    Ok(items)
}

fn allowed_actions(
    modules: &RuntimeModules,
    module_id: ModuleId,
    mode: DesiredMode,
    active: &std::collections::BTreeSet<ModuleId>,
) -> Vec<&'static str> {
    let mut actions = Vec::with_capacity(3);
    if mode != DesiredMode::Inherit {
        actions.push("inherit");
    }
    if mode != DesiredMode::Enabled {
        let dependencies_ready = modules.catalog.spec(module_id).is_some_and(|spec| {
            spec.dependencies
                .iter()
                .all(|dependency| active.contains(dependency))
        });
        if dependencies_ready {
            actions.push("enable");
        }
    }
    if mode != DesiredMode::Disabled
        && !modules.catalog.runtime_disable_blocked(module_id)
        && modules.catalog.spec(module_id).is_some_and(|spec| {
            !matches!(spec.disable_policy, DisablePolicy::NotRuntimeDisableable)
        })
        && modules
            .catalog
            .active_dependents(module_id, active)
            .is_empty()
    {
        actions.push("disable");
    }
    actions
}

fn runtime_event_json(event: &nazo_runtime_modules::ModuleEventRecord) -> Value {
    json!({
        "event_id": event.event_id,
        "module_id": module_id_name(event.module_id),
        "event_type": event_type_name(event.event_type),
        "instance_id": event.instance_id,
        "actor_id": event.actor_id,
        "reason": event.reason,
        "before_state": event.before.map(event_state_name),
        "after_state": event.after.map(event_state_name),
        "revision": event.revision.get(),
        "outcome_code": event.outcome_code,
        "created_at": timestamp(event.occurred_at),
    })
}

fn accepted_response(body: Value) -> HttpResponse {
    json_response_with_status_no_store(StatusCode::ACCEPTED, body)
}

fn json_response_with_status_no_store(status: StatusCode, body: Value) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .json(body)
}

fn no_store(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response
}

fn runtime_repository_error(error: RepositoryError, message: &'static str) -> HttpResponse {
    tracing::warn!(%error, "{message}");
    no_store(oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "Runtime module state is unavailable.",
    ))
}

fn registry_error(error: RegistryError<RepositoryError>) -> HttpResponse {
    match error {
        RegistryError::RuntimeDisableBlocked(_)
        | RegistryError::ActiveDependent { .. }
        | RegistryError::DependencyUnavailable { .. } => no_store(oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "Runtime module dependencies or disable policy reject this change.",
        )),
        RegistryError::Repository(error) => {
            runtime_repository_error(error, "runtime module desired-state update failed")
        }
        RegistryError::MissingDesiredState(_) | RegistryError::MissingCatalogSpec(_) => {
            no_store(oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Runtime module catalog is inconsistent.",
            ))
        }
    }
}

fn parse_module_id(value: &str) -> Option<ModuleId> {
    match value {
        "device_authorization" => Some(ModuleId::DeviceAuthorization),
        "token_exchange" => Some(ModuleId::TokenExchange),
        "jwt_bearer_grant" => Some(ModuleId::JwtBearerGrant),
        "ciba" => Some(ModuleId::Ciba),
        "dynamic_client_registration" => Some(ModuleId::DynamicClientRegistration),
        "request_objects" => Some(ModuleId::RequestObjects),
        "jarm" => Some(ModuleId::Jarm),
        "authorization_details" => Some(ModuleId::AuthorizationDetails),
        "http_message_signatures" => Some(ModuleId::HttpMessageSignatures),
        "scim" => Some(ModuleId::Scim),
        "native_sso" => Some(ModuleId::NativeSso),
        "frontchannel_logout" => Some(ModuleId::FrontchannelLogout),
        "session_management" => Some(ModuleId::SessionManagement),
        _ => None,
    }
}

const fn module_id_name(value: ModuleId) -> &'static str {
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
        ModuleId::NativeSso => "Native SSO",
        ModuleId::FrontchannelLogout => "Front-Channel Logout",
        ModuleId::SessionManagement => "OIDC Session Management",
    }
}

const fn desired_mode_name(value: DesiredMode) -> &'static str {
    match value {
        DesiredMode::Inherit => "inherit",
        DesiredMode::Enabled => "enabled",
        DesiredMode::Disabled => "disabled",
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

fn disable_policy_name(value: DisablePolicy) -> String {
    match value {
        DisablePolicy::Immediate => "immediate".to_owned(),
        DisablePolicy::FinishExecutingRequests => "finish_executing_requests".to_owned(),
        DisablePolicy::DrainStoredTransactions { max_duration } => {
            format!("drain_stored_transactions:{}s", max_duration.as_secs())
        }
        DisablePolicy::NotRuntimeDisableable => "not_runtime_disableable".to_owned(),
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
        ModuleEventState::Desired(value) => desired_mode_name(value),
        ModuleEventState::Actual(value) => actual_state_name(value),
    }
}

fn timestamp(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339()
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/runtime_modules.rs"]
mod tests;
