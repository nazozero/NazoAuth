//! 管理端用户账户接口。
use crate::endpoints::admin::require_transactional_audit_or_unavailable;
use crate::endpoints::sessions::{
    AdminSessionHandles, require_admin_or_forbidden_with_handles,
    require_admin_with_recent_mfa_or_forbidden_with_handles,
};
use crate::endpoints::views::admin_user_json;
use crate::endpoints::views::pagination;
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use http::StatusCode;

use crate::http::{ClientIpConfig, client_ip_with_config};
use crate::http::{csrf_error, has_valid_csrf_token_for_cookies};
use crate::http::{json_response, oauth_error};
use nazo_identity::{
    PublicAccount,
    email::normalize_email_address,
    ports::{AdminUserRepositoryPort, NewUser, RegistrationAccountRepositoryPort, SecretHashPort},
};
use nazo_oauth_server::crypto::blake3_hex;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;
use uuid::Uuid;
// 只处理用户列表与用户状态更新，不包含客户端或授权关系逻辑。

pub async fn admin_users(
    admin_sessions: &AdminSessionHandles,
    users: &dyn AdminUserRepositoryPort,
    req: &HttpRequest,
    q: HashMap<String, String>,
) -> HttpResponse {
    let admin = match require_admin_or_forbidden_with_handles(admin_sessions, req).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let (page, page_size, offset) = pagination(&q);
    let (total, user_rows) = match users
        .page(admin.tenant.tenant_id, page_size as i64, offset)
        .await
    {
        Ok(page) => (page.total, page.users),
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for user list");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户列表查询失败.",
            );
        }
    };
    admin_users_list_response(page, page_size, total, user_rows)
}

pub fn admin_users_list_response(
    page: i32,
    page_size: i32,
    total: i64,
    user_rows: Vec<PublicAccount>,
) -> HttpResponse {
    #[derive(Serialize)]
    struct UsersListResponse<'a> {
        total: i64,
        page: i32,
        page_size: i32,
        #[serde(serialize_with = "serialize_users")]
        items: &'a [PublicAccount],
    }
    fn serialize_users<S: Serializer>(
        users: &[PublicAccount],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(users.iter().map(admin_user_json))
    }
    json_response(UsersListResponse {
        total,
        page,
        page_size,
        items: &user_rows,
    })
}

#[derive(Deserialize)]
pub struct PatchUserRequest {
    pub role: Option<String>,
    pub admin_level: Option<i32>,
    pub is_active: Option<bool>,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SetTenantAdminRequest {
    pub admin_level: i32,
}

#[allow(clippy::too_many_arguments)]
pub async fn system_set_tenant_admin(
    audit: &dyn nazo_oauth_server::ports::audit::SecurityAudit,
    admin_sessions: &AdminSessionHandles,
    users: &dyn AdminUserRepositoryPort,
    registry: &dyn crate::capabilities::TenantAvailability,
    control_tenant: nazo_identity::TenantId,
    client_ip_config: &ClientIpConfig,
    req: &HttpRequest,
    path: (Uuid, Uuid),
    payload: SetTenantAdminRequest,
) -> HttpResponse {
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let admin =
        match require_admin_with_recent_mfa_or_forbidden_with_handles(admin_sessions, req).await {
            Ok(admin) if admin.admin_level().unwrap_or(0) >= 2 => admin,
            Ok(_) => {
                return oauth_error(
                    StatusCode::FORBIDDEN,
                    "access_denied",
                    "需要系统管理员权限.",
                );
            }
            Err(response) => return response,
        };
    if payload.admin_level < 0 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "admin_level 不能为负数.",
        );
    }
    let (tenant_uuid, user_uuid) = path;
    let target_tenant = match nazo_identity::TenantId::new(tenant_uuid) {
        Ok(value) => value,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "tenant_id 格式无效.",
            );
        }
    };
    if target_tenant == control_tenant || !registry.contains_tenant(target_tenant) {
        return crate::http::empty_response(StatusCode::NOT_FOUND);
    }
    let target_user = match nazo_identity::UserId::new(user_uuid) {
        Ok(value) => value,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "user_id 格式无效.",
            );
        }
    };
    if let Err(response) = require_transactional_audit_or_unavailable(audit).await {
        return response;
    }
    match users
        .set_tenant_admin_authorized(
            control_tenant,
            admin.user_id,
            target_tenant,
            target_user,
            payload.admin_level,
            blake3_hex(&client_ip_with_config(req, client_ip_config)),
        )
        .await
    {
        Ok(nazo_identity::AdminUserUpdateOutcome::Updated(user)) => {
            json_response(admin_user_json(&user))
        }
        Ok(nazo_identity::AdminUserUpdateOutcome::TargetNotFound) => {
            crate::http::empty_response(StatusCode::NOT_FOUND)
        }
        Ok(nazo_identity::AdminUserUpdateOutcome::Denied(_)) => oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "不允许修改该租户管理员.",
        ),
        Err(error) => {
            tracing::warn!(%error, "failed to update tenant administrator");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "租户管理员更新失败.",
            )
        }
    }
}

pub async fn admin_create_user(
    audit: &dyn nazo_oauth_server::ports::audit::SecurityAudit,
    password_hasher: &dyn SecretHashPort,
    admin_sessions: &AdminSessionHandles,
    accounts: &dyn RegistrationAccountRepositoryPort,
    client_ip_config: &ClientIpConfig,
    req: &HttpRequest,
    payload: CreateUserRequest,
) -> HttpResponse {
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let admin =
        match require_admin_with_recent_mfa_or_forbidden_with_handles(admin_sessions, req).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    let email = match normalize_email_address(&payload.email) {
        Ok(email) => email,
        Err(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
        }
    };
    if !nazo_identity::registration::valid_new_password_length(&payload.password) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "密码长度必须为 12 到 1024 字节.",
        );
    }
    let password_hash = match password_hasher.hash_secret(payload.password).await {
        Ok(hash) => hash,
        Err(error) => {
            tracing::warn!(%error, "failed to hash administratively provisioned password");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户创建失败.",
            );
        }
    };
    if let Err(response) = require_transactional_audit_or_unavailable(audit).await {
        return response;
    }
    let source_ip_hash = blake3_hex(&client_ip_with_config(req, client_ip_config));
    match accounts
        .create_user_with_required_audit(
            NewUser {
                tenant: admin.tenant,
                username: format!("user_{}", Uuid::now_v7()),
                email,
                password_hash,
                email_verified: true,
            },
            admin.user_id,
            source_ip_hash,
        )
        .await
    {
        Ok(account) => crate::http::json_response_status_no_store(
            StatusCode::CREATED,
            admin_user_json(&account),
        ),
        Err(nazo_identity::ports::RepositoryError::Conflict) => {
            oauth_error(StatusCode::CONFLICT, "invalid_request", "该邮箱已注册.")
        }
        Err(error) => {
            tracing::warn!(%error, "failed to create administratively provisioned user");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户创建失败.",
            )
        }
    }
}

pub async fn admin_patch_user(
    audit: &dyn nazo_oauth_server::ports::audit::SecurityAudit,
    admin_sessions: &AdminSessionHandles,
    users: &dyn AdminUserRepositoryPort,
    client_ip_config: &ClientIpConfig,
    req: &HttpRequest,
    path: Uuid,
    payload: PatchUserRequest,
) -> HttpResponse {
    let user_id = path;
    let session_http = admin_sessions.http_config();
    if !has_valid_csrf_token_for_cookies(
        req,
        None,
        session_http.session_cookie_name(),
        session_http.csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let admin =
        match require_admin_with_recent_mfa_or_forbidden_with_handles(admin_sessions, req).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
    if let Some(response) = patch_user_validation_error(&payload) {
        return response;
    }
    let user_id = match nazo_identity::UserId::new(user_id) {
        Ok(user_id) => user_id,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "user_id 格式无效.",
            );
        }
    };
    if let Err(response) = require_transactional_audit_or_unavailable(audit).await {
        return response;
    }
    let source_ip_hash = blake3_hex(&client_ip_with_config(req, client_ip_config));
    let updated = match users
        .update_authorized_with_required_audit(
            admin.tenant,
            admin.user_id,
            user_id,
            nazo_identity::ports::AdminUserUpdate {
                role: payload.role,
                admin_level: payload.admin_level,
                active: payload.is_active,
            },
            source_ip_hash,
        )
        .await
    {
        Ok(updated) => updated,
        Err(nazo_identity::ports::RepositoryError::Conflict) => {
            return oauth_error(
                StatusCode::CONFLICT,
                "invalid_request",
                "用户状态发生并发冲突，请重试.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to update user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户更新失败.",
            );
        }
    };
    match updated {
        nazo_identity::AdminUserUpdateOutcome::Updated(user) => {
            json_response(admin_user_json(&user))
        }
        nazo_identity::AdminUserUpdateOutcome::TargetNotFound => {
            oauth_error(StatusCode::NOT_FOUND, "invalid_request", "未找到该用户.")
        }
        nazo_identity::AdminUserUpdateOutcome::Denied(
            nazo_identity::AdminPolicyError::InvalidRoleLevel,
        ) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "role 与 admin_level 组合无效.",
        ),
        nazo_identity::AdminUserUpdateOutcome::Denied(_) => {
            oauth_error(StatusCode::FORBIDDEN, "access_denied", "不允许修改该用户.")
        }
    }
}

pub fn patch_user_validation_error(payload: &PatchUserRequest) -> Option<HttpResponse> {
    if payload.admin_level.is_some_and(|level| level < 0) {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "admin_level 不能为负数.",
        ));
    }
    if let Some(role) = payload.role.as_deref() {
        match role {
            "admin" | "user" => {}
            _ => {
                return Some(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "用户角色无效.",
                ));
            }
        }
    }
    None
}
