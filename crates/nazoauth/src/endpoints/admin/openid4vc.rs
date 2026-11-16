//! Administrative control plane for issuer-authoritative credential data.
//!
//! OpenID4VCI defines credential issuance, not the operator API used to
//! maintain the data from which credentials are issued. Keep this surface in
//! the authenticated admin boundary instead of presenting it as an
//! OpenID4VCI protocol endpoint.

use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use crate::http::{
    csrf_error, empty_response_no_store, has_valid_csrf_token_for_cookies, json_response_no_store,
    json_response_status_no_store,
};
use http::StatusCode;
use nazo_openid4vci::application::CredentialHttpError;
use uuid::Uuid;

use crate::endpoints::admin::require_transactional_audit_or_unavailable;
use crate::endpoints::sessions::AdminSessionHandles;
use crate::endpoints::sessions::require_admin_or_forbidden_with_handles;
use crate::endpoints::sessions::require_admin_with_recent_mfa_or_forbidden_with_handles;
use nazo_oauth_server::domain::openid4vc_endpoints::CredentialDatasetAdminService;
use nazo_oauth_server::domain::openid4vc_endpoints::PutCredentialDatasetRequest;

pub async fn admin_put_credential_dataset(
    audit: &dyn nazo_oauth_server::ports::audit::SecurityAudit,
    sessions: &AdminSessionHandles,
    endpoint: &CredentialDatasetAdminService,
    request: &HttpRequest,
    path: (Uuid, String),
    payload: PutCredentialDatasetRequest,
) -> HttpResponse {
    if !valid_csrf(sessions, request) {
        return csrf_error();
    }
    let admin =
        match require_admin_with_recent_mfa_or_forbidden_with_handles(sessions, request).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    let (subject_id, configuration_id) = path;
    if let Err(response) = require_transactional_audit_or_unavailable(audit).await {
        return response;
    }
    match endpoint
        .put_dataset(
            admin.tenant.tenant_id.as_uuid(),
            admin.user_id.as_uuid(),
            subject_id,
            configuration_id,
            payload,
        )
        .await
    {
        Ok(dataset) => json_response_no_store(dataset),
        Err(error) => dataset_error(error),
    }
}

pub async fn admin_get_credential_dataset(
    sessions: &AdminSessionHandles,
    endpoint: &CredentialDatasetAdminService,
    request: &HttpRequest,
    path: (Uuid, String),
) -> HttpResponse {
    let admin = match require_admin_or_forbidden_with_handles(sessions, request).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let (subject_id, configuration_id) = path;
    match endpoint
        .get_dataset(
            admin.tenant.tenant_id.as_uuid(),
            subject_id,
            configuration_id,
        )
        .await
    {
        Ok(dataset) => json_response_no_store(dataset),
        Err(error) => dataset_error(error),
    }
}

pub async fn admin_delete_credential_dataset(
    audit: &dyn nazo_oauth_server::ports::audit::SecurityAudit,
    sessions: &AdminSessionHandles,
    endpoint: &CredentialDatasetAdminService,
    request: &HttpRequest,
    path: (Uuid, String),
) -> HttpResponse {
    if !valid_csrf(sessions, request) {
        return csrf_error();
    }
    let admin =
        match require_admin_with_recent_mfa_or_forbidden_with_handles(sessions, request).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    let (subject_id, configuration_id) = path;
    if let Err(response) = require_transactional_audit_or_unavailable(audit).await {
        return response;
    }
    match endpoint
        .delete_dataset(
            admin.tenant.tenant_id.as_uuid(),
            admin.user_id.as_uuid(),
            subject_id,
            configuration_id,
        )
        .await
    {
        Ok(()) => empty_response_no_store(StatusCode::NO_CONTENT),
        Err(error) => dataset_error(error),
    }
}

pub fn dataset_error(error: CredentialHttpError) -> HttpResponse {
    let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    json_response_status_no_store(
        status,
        serde_json::json!({
            "error": error.error,
            "error_description": error.description,
        }),
    )
}

pub fn valid_csrf(sessions: &AdminSessionHandles, request: &HttpRequest) -> bool {
    let config = sessions.http_config();
    has_valid_csrf_token_for_cookies(
        request,
        None,
        config.session_cookie_name(),
        config.csrf_cookie_name(),
    )
}
