//! 当前用户资料接口。
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
#[cfg(test)]
use crate::schema::users;
#[cfg(test)]
use crate::settings::Settings;
use crate::support::auth_me_json_with_grants;
use crate::support::sessions::SessionProfileHandles;
#[cfg(test)]
use crate::support::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, SessionPayload, valkey_set_ex,
};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use diesel::prelude::*;
#[cfg(test)]
use diesel_async::RunQueryDsl;
use nazo_http_actix::{cookie_value, csrf_error};
use nazo_http_actix::{json_response, oauth_error};
#[cfg(test)]
use nazo_postgres::get_conn;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;
// 只处理 /auth/me 的读取和基础资料更新。

#[derive(Clone)]
pub(crate) struct AccountProfileService {
    users: nazo_postgres::UserRepository,
    grants: nazo_postgres::GrantRepository,
}

impl AccountProfileService {
    pub(crate) fn new(
        users: nazo_postgres::UserRepository,
        grants: nazo_postgres::GrantRepository,
    ) -> Self {
        Self { users, grants }
    }

    async fn profile_json(&self, user: &nazo_identity::PublicAccount) -> anyhow::Result<Value> {
        auth_me_json_with_grants(&self.grants, user).await
    }

    async fn update_profile(
        &self,
        user: &nazo_identity::PublicAccount,
        profile: nazo_identity::UserProfile,
    ) -> Result<nazo_identity::PublicAccount, nazo_identity::ports::RepositoryError> {
        self.users
            .update_profile(
                user.tenant().tenant_id,
                user.user_id(),
                nazo_identity::ports::ProfileUpdate { profile },
            )
            .await
    }
}

pub(crate) async fn me(
    sessions: Data<SessionProfileHandles>,
    profiles: Data<AccountProfileService>,
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
    match profiles.profile_json(&session.user).await {
        Ok(mut body) => {
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

pub(crate) async fn update_me(
    sessions: Data<SessionProfileHandles>,
    profiles: Data<AccountProfileService>,
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
    let display_name = match profile_text(payload.display_name, 80, "display_name") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let given_name = match profile_text(payload.given_name, 80, "given_name") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let family_name = match profile_text(payload.family_name, 80, "family_name") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let middle_name = match profile_text(payload.middle_name, 80, "middle_name") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let nickname = match profile_text(payload.nickname, 80, "nickname") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let profile_url = match normalize_profile_url(payload.profile_url, "profile_url") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let website_url = match normalize_profile_url(payload.website_url, "website_url") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let gender = match profile_text(payload.gender, 40, "gender") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let birthdate = match profile_text(payload.birthdate, 10, "birthdate") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let zoneinfo = match profile_text(payload.zoneinfo, 64, "zoneinfo") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let locale = match profile_text(payload.locale, 35, "locale") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let address_formatted = match profile_text(payload.address_formatted, 512, "address_formatted")
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let address_street_address = match profile_text(
        payload.address_street_address,
        256,
        "address_street_address",
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let address_locality = match profile_text(payload.address_locality, 128, "address_locality") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let address_region = match profile_text(payload.address_region, 128, "address_region") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let address_postal_code =
        match profile_text(payload.address_postal_code, 64, "address_postal_code") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let address_country = match profile_text(payload.address_country, 64, "address_country") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let phone_number = match profile_text(payload.phone_number, 32, "phone_number") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let phone_number_verified =
        user.profile.phone_number_verified && user.profile.phone_number == phone_number;
    let updated = profiles
        .update_profile(
            &user,
            nazo_identity::UserProfile {
                display_name,
                avatar_url: user.profile.avatar_url.clone(),
                given_name,
                family_name,
                middle_name,
                nickname,
                profile_url,
                website_url,
                gender,
                birthdate,
                zoneinfo,
                locale,
                address: nazo_identity::PostalAddress {
                    formatted: address_formatted,
                    street_address: address_street_address,
                    locality: address_locality,
                    region: address_region,
                    postal_code: address_postal_code,
                    country: address_country,
                },
                phone_number,
                phone_number_verified,
            },
        )
        .await;
    match updated {
        Ok(user) => match profiles.profile_json(&user).await {
            Ok(body) => json_response(body),
            Err(error) => {
                tracing::warn!(%error, "failed to build updated auth me response");
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "当前用户资料查询失败.",
                )
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to update profile");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "资料更新失败.",
            )
        }
    }
}

fn profile_text(
    value: Option<String>,
    max_bytes: usize,
    field: &str,
) -> Result<Option<String>, HttpResponse> {
    let Some(value) = value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if value.len() > max_bytes {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("{field} 超出长度限制."),
        ));
    }
    Ok(Some(value))
}

fn normalize_profile_url(
    value: Option<String>,
    field: &str,
) -> Result<Option<String>, HttpResponse> {
    let Some(value) = profile_text(value, 512, field)? else {
        return Ok(None);
    };
    let Ok(url) = url::Url::parse(&value) else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("{field} 必须是绝对 URL."),
        ));
    };
    if !matches!(url.scheme(), "https" | "http") || url.cannot_be_a_base() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("{field} 必须是 http 或 https URL."),
        ));
    }
    Ok(Some(value))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/account.rs"]
mod tests;
