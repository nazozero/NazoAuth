//! 管理端客户端更新端点。
// PATCH 请求只覆盖显式提交的字段，其余字段保持数据库当前值。
use super::create::{trim_optional_string, trim_string_vec};
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct PatchClientRequest {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    allowed_audiences: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    require_dpop_bound_tokens: Option<bool>,
    allow_client_assertion_audience_array: Option<bool>,
    allow_client_assertion_endpoint_audience: Option<bool>,
    require_par_request_object: Option<bool>,
    tls_client_auth_subject_dn: Option<String>,
    tls_client_auth_cert_sha256: Option<String>,
    tls_client_auth_san_dns: Option<Vec<String>>,
    tls_client_auth_san_uri: Option<Vec<String>>,
    tls_client_auth_san_ip: Option<Vec<String>>,
    tls_client_auth_san_email: Option<Vec<String>>,
    jwks: Option<Value>,
    is_active: Option<bool>,
}

/// 局部更新 OAuth 客户端配置。
pub(crate) async fn admin_patch_client(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    Json(payload): Json<PatchClientRequest>,
) -> HttpResponse {
    let client_id = path.into_inner();
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }

    let current = match find_client(&state.diesel_db, &client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该客户端.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for admin update");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };

    let new_client_name = payload
        .client_name
        .unwrap_or_else(|| current.client_name.clone());
    let new_redirect_uris = json!(
        payload
            .redirect_uris
            .unwrap_or_else(|| json_array_to_strings(&current.redirect_uris))
    );
    let new_scopes = json!(
        payload
            .scopes
            .unwrap_or_else(|| json_array_to_strings(&current.scopes))
    );
    let new_allowed_audiences = json!(
        payload
            .allowed_audiences
            .unwrap_or_else(|| json_array_to_strings(&current.allowed_audiences))
    );
    let new_grant_types = json!(
        payload
            .grant_types
            .unwrap_or_else(|| json_array_to_strings(&current.grant_types))
    );
    let new_require_dpop_bound_tokens = payload
        .require_dpop_bound_tokens
        .unwrap_or(current.require_dpop_bound_tokens);
    let new_allow_client_assertion_audience_array = payload
        .allow_client_assertion_audience_array
        .unwrap_or(current.allow_client_assertion_audience_array);
    let new_allow_client_assertion_endpoint_audience = payload
        .allow_client_assertion_endpoint_audience
        .unwrap_or(current.allow_client_assertion_endpoint_audience);
    let new_require_par_request_object = payload
        .require_par_request_object
        .unwrap_or(current.require_par_request_object);
    let new_tls_client_auth_subject_dn = payload
        .tls_client_auth_subject_dn
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.tls_client_auth_subject_dn.clone());
    let new_tls_client_auth_cert_sha256 = payload
        .tls_client_auth_cert_sha256
        .map(Some)
        .map(trim_optional_string)
        .unwrap_or_else(|| current.tls_client_auth_cert_sha256.clone());
    let new_tls_client_auth_san_dns = json!(
        payload
            .tls_client_auth_san_dns
            .map(trim_string_vec)
            .unwrap_or_else(|| json_array_to_strings(&current.tls_client_auth_san_dns))
    );
    let new_tls_client_auth_san_uri = json!(
        payload
            .tls_client_auth_san_uri
            .map(trim_string_vec)
            .unwrap_or_else(|| json_array_to_strings(&current.tls_client_auth_san_uri))
    );
    let new_tls_client_auth_san_ip = json!(
        payload
            .tls_client_auth_san_ip
            .map(trim_string_vec)
            .unwrap_or_else(|| json_array_to_strings(&current.tls_client_auth_san_ip))
    );
    let new_tls_client_auth_san_email = json!(
        payload
            .tls_client_auth_san_email
            .map(trim_string_vec)
            .unwrap_or_else(|| json_array_to_strings(&current.tls_client_auth_san_email))
    );
    let new_jwks = payload.jwks.or_else(|| current.jwks.clone());
    let new_is_active = payload.is_active.unwrap_or(current.is_active);
    let new_redirect_uri_values = json_array_to_strings(&new_redirect_uris);
    let new_scope_values = json_array_to_strings(&new_scopes);
    let new_audience_values = json_array_to_strings(&new_allowed_audiences);
    let new_grant_type_values = json_array_to_strings(&new_grant_types);
    let new_tls_client_auth_san_dns_values = json_array_to_strings(&new_tls_client_auth_san_dns);
    let new_tls_client_auth_san_uri_values = json_array_to_strings(&new_tls_client_auth_san_uri);
    let new_tls_client_auth_san_ip_values = json_array_to_strings(&new_tls_client_auth_san_ip);
    let new_tls_client_auth_san_email_values =
        json_array_to_strings(&new_tls_client_auth_san_email);
    if let Err(error) = validate_client_metadata(ClientMetadata {
        client_type: &current.client_type,
        redirect_uris: &new_redirect_uri_values,
        scopes: &new_scope_values,
        allowed_audiences: &new_audience_values,
        grant_types: &new_grant_type_values,
        token_endpoint_auth_method: &current.token_endpoint_auth_method,
        jwks: new_jwks.as_ref(),
        mtls_binding: Some(&ClientMtlsMetadata {
            tls_client_auth_subject_dn: new_tls_client_auth_subject_dn.clone(),
            tls_client_auth_cert_sha256: new_tls_client_auth_cert_sha256.clone(),
            tls_client_auth_san_dns: new_tls_client_auth_san_dns_values,
            tls_client_auth_san_uri: new_tls_client_auth_san_uri_values,
            tls_client_auth_san_ip: new_tls_client_auth_san_ip_values,
            tls_client_auth_san_email: new_tls_client_auth_san_email_values,
        }),
    }) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端更新失败: {error}"),
        );
    }
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for client update");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端更新失败.",
            );
        }
    };
    let client = match diesel::update(
        oauth_clients::table.filter(oauth_clients::client_id.eq(&current.client_id)),
    )
    .set((
        oauth_clients::client_name.eq(new_client_name),
        oauth_clients::redirect_uris.eq(new_redirect_uris),
        oauth_clients::scopes.eq(new_scopes),
        oauth_clients::allowed_audiences.eq(new_allowed_audiences),
        oauth_clients::grant_types.eq(new_grant_types),
        oauth_clients::require_dpop_bound_tokens.eq(new_require_dpop_bound_tokens),
        oauth_clients::allow_client_assertion_audience_array
            .eq(new_allow_client_assertion_audience_array),
        oauth_clients::allow_client_assertion_endpoint_audience
            .eq(new_allow_client_assertion_endpoint_audience),
        oauth_clients::require_par_request_object.eq(new_require_par_request_object),
        oauth_clients::tls_client_auth_subject_dn.eq(new_tls_client_auth_subject_dn),
        oauth_clients::tls_client_auth_cert_sha256.eq(new_tls_client_auth_cert_sha256),
        oauth_clients::tls_client_auth_san_dns.eq(new_tls_client_auth_san_dns),
        oauth_clients::tls_client_auth_san_uri.eq(new_tls_client_auth_san_uri),
        oauth_clients::tls_client_auth_san_ip.eq(new_tls_client_auth_san_ip),
        oauth_clients::tls_client_auth_san_email.eq(new_tls_client_auth_san_email),
        oauth_clients::jwks.eq(new_jwks),
        oauth_clients::is_active.eq(new_is_active),
        oauth_clients::updated_at.eq(diesel_now),
    ))
    .returning(ClientRow::as_returning())
    .get_result::<ClientRow>(&mut conn)
    .await
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "failed to update oauth client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端更新失败.",
            );
        }
    };

    audit_event(
        "client_updated",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ]),
    );
    json_response(client_json(client))
}
