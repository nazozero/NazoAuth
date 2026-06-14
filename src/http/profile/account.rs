//! 当前用户资料接口。
// 只处理 /auth/me 的读取和基础资料更新。
use crate::http::prelude::*;

pub(crate) async fn me(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let session = match current_session(&state, &req).await {
        Ok(Some(session)) => session,
        Ok(None) => match current_pending_mfa_session(&state, &req).await {
            Ok(Some(session)) => {
                return json_response(json!({
                    "mfa_required": true,
                    "id": session.user.id,
                    "email": session.user.email,
                    "csrf_token": cookie_value(&req, &state.settings.csrf_cookie_name)
                }));
            }
            Ok(None) => return login_required_response(&state),
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
    match auth_me_json(&state, &session.user).await {
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
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<UpdateProfileRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
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
    let phone_number_verified = user.phone_number_verified && user.phone_number == phone_number;
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "数据库连接失败.",
            );
        }
    };
    let updated = diesel::update(users::table.find(user.id))
        .set((
            users::display_name.eq(display_name),
            users::given_name.eq(given_name),
            users::family_name.eq(family_name),
            users::middle_name.eq(middle_name),
            users::nickname.eq(nickname),
            users::profile_url.eq(profile_url),
            users::website_url.eq(website_url),
            users::gender.eq(gender),
            users::birthdate.eq(birthdate),
            users::zoneinfo.eq(zoneinfo),
            users::locale.eq(locale),
            users::address_formatted.eq(address_formatted),
            users::address_street_address.eq(address_street_address),
            users::address_locality.eq(address_locality),
            users::address_region.eq(address_region),
            users::address_postal_code.eq(address_postal_code),
            users::address_country.eq(address_country),
            users::phone_number.eq(phone_number),
            users::phone_number_verified.eq(phone_number_verified),
            users::updated_at.eq(diesel_now),
        ))
        .returning(UserRow::as_returning())
        .get_result::<UserRow>(&mut conn)
        .await;
    match updated {
        Ok(user) => match auth_me_json(&state, &user).await {
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
#[path = "../../../tests/unit/src/http/profile/tests/account.rs"]
mod tests;
