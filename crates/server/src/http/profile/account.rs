//! 当前用户资料接口。
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
#[cfg(test)]
use crate::settings::Settings;
use crate::support::sessions::SessionProfileHandles;
use crate::support::views::auth_me_json_with_count;
#[cfg(test)]
use crate::support::{
    sessions::SessionPayload, tenancy::DEFAULT_ORGANIZATION_ID, tenancy::DEFAULT_REALM_ID,
    tenancy::DEFAULT_TENANT_ID, valkey::valkey_set_ex,
};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
use nazo_http_actix::{cookie_value, csrf_error};
use nazo_http_actix::{json_response, oauth_error};
use serde::Deserialize;
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;
// 只处理 /auth/me 的读取和基础资料更新。

pub(crate) async fn me(
    sessions: Data<SessionProfileHandles>,
    profiles: Data<crate::bootstrap::AccountProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let session = match sessions.current_session(&req).await {
        Ok(Some(session)) => session,
        Ok(None) => match sessions.current_pending_mfa_session(&req).await {
            Ok(Some(session)) => {
                return json_response(json!({
                    "mfa_required": true,
                    "id": session.user.id(),
                    "email": session.user.account.email,
                    "csrf_token": cookie_value(&req, sessions.http_config().csrf_cookie_name())
                }));
            }
            Ok(None) => return sessions.login_required_response(),
            Err(error) => {
                tracing::warn!(%error, "failed to resolve pending MFA session");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "会话查询失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to resolve current session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };
    match profiles.overview(session.user).await {
        Ok(overview) => {
            let mut body =
                auth_me_json_with_count(&overview.account, overview.authorized_application_count);
            if let Some(object) = body.as_object_mut() {
                object.insert("mfa_required".to_owned(), json!(false));
            }
            json_response(body)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to build auth me response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "当前用户资料查询失败.",
            )
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct UpdateProfileRequest {
    display_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    middle_name: Option<String>,
    nickname: Option<String>,
    profile_url: Option<String>,
    website_url: Option<String>,
    gender: Option<String>,
    birthdate: Option<String>,
    zoneinfo: Option<String>,
    locale: Option<String>,
    address_formatted: Option<String>,
    address_street_address: Option<String>,
    address_locality: Option<String>,
    address_region: Option<String>,
    address_postal_code: Option<String>,
    address_country: Option<String>,
    phone_number: Option<String>,
}

impl From<UpdateProfileRequest> for nazo_identity::ProfilePatch {
    fn from(payload: UpdateProfileRequest) -> Self {
        Self {
            display_name: payload.display_name,
            given_name: payload.given_name,
            family_name: payload.family_name,
            middle_name: payload.middle_name,
            nickname: payload.nickname,
            profile_url: payload.profile_url,
            website_url: payload.website_url,
            gender: payload.gender,
            birthdate: payload.birthdate,
            zoneinfo: payload.zoneinfo,
            locale: payload.locale,
            address_formatted: payload.address_formatted,
            address_street_address: payload.address_street_address,
            address_locality: payload.address_locality,
            address_region: payload.address_region,
            address_postal_code: payload.address_postal_code,
            address_country: payload.address_country,
            phone_number: payload.phone_number,
        }
    }
}

pub(crate) async fn update_me(
    sessions: Data<SessionProfileHandles>,
    profiles: Data<crate::bootstrap::AccountProfileService>,
    req: HttpRequest,
    Json(payload): Json<UpdateProfileRequest>,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match profiles.update(&user, payload.into()).await {
        Ok(overview) => json_response(auth_me_json_with_count(
            &overview.account,
            overview.authorized_application_count,
        )),
        Err(nazo_identity::UpdateProfileError::Validation(error)) => {
            profile_validation_response(error)
        }
        Err(nazo_identity::UpdateProfileError::UpdateRepository(error)) => {
            tracing::warn!(%error, "failed to update profile");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "资料更新失败.",
            )
        }
        Err(nazo_identity::UpdateProfileError::OverviewRepository(error)) => {
            tracing::warn!(%error, "failed to build updated auth me response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "当前用户资料查询失败.",
            )
        }
    }
}

fn profile_validation_response(error: nazo_identity::ProfileValidationError) -> HttpResponse {
    match error {
        nazo_identity::ProfileValidationError::FieldTooLong(field) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("{field} 超出长度限制."),
        ),
        nazo_identity::ProfileValidationError::InvalidAbsoluteUrl(field) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("{field} 必须是绝对 URL."),
        ),
        nazo_identity::ProfileValidationError::InvalidHttpUrl(field) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("{field} 必须是 http 或 https URL."),
        ),
    }
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/account.rs"]
mod tests;
