//! 令牌签发响应构造。
// 统一 access_token、refresh_token 和 id_token 的响应形状。
use crate::http::prelude::*;

pub(crate) async fn issue_token_response(
    state: &AppState,
    client: &ClientRow,
    issue: TokenIssue,
) -> HttpResponse {
    let now = Utc::now();
    let access_token = match make_jwt(
        state,
        AccessTokenJwtInput {
            subject: &issue.subject,
            subject_type: if issue.user_id.is_some() {
                "user"
            } else {
                "client"
            },
            client_id: &client.client_id,
            audience: &issue.audience,
            scopes: &issue.scopes,
            ttl: state.settings.access_token_ttl_seconds,
            dpop_jkt: issue.dpop_jkt.as_deref(),
        },
    ) {
        Ok(v) => v,
        Err(_) => {
            return oauth_token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "令牌签发失败.",
                false,
            );
        }
    };
    let token_type = if issue.dpop_jkt.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut body = json!({
        "access_token": access_token,
        "token_type": token_type,
        "expires_in": state.settings.access_token_ttl_seconds,
        "scope": issue.scopes.join(" ")
    });
    if issue.include_refresh
        && issue
            .scopes
            .iter()
            .any(|s| s == "offline_access" || s == "openid" || s == "profile")
    {
        let raw_refresh = format!("{}.{}", random_urlsafe_token(), random_urlsafe_token());
        let family = issue.rotation.map(|r| r.0).unwrap_or_else(Uuid::now_v7);
        let rotated_from = issue.rotation.and_then(|r| r.1);
        let expires_at = now + Duration::seconds(state.settings.refresh_token_ttl_seconds);
        let mut conn = match get_conn(&state.diesel_db).await {
            Ok(conn) => conn,
            Err(_) => {
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "refresh token 持久化失败.",
                    false,
                );
            }
        };
        if diesel::insert_into(oauth_tokens::table)
            .values((
                oauth_tokens::refresh_token_blake3.eq(blake3_hex(&raw_refresh)),
                oauth_tokens::token_family_id.eq(family),
                oauth_tokens::rotated_from_id.eq(rotated_from),
                oauth_tokens::client_id.eq(client.id),
                oauth_tokens::user_id.eq(issue.user_id),
                oauth_tokens::scopes.eq(json!(issue.scopes)),
                oauth_tokens::issued_at.eq(now),
                oauth_tokens::expires_at.eq(expires_at),
                oauth_tokens::subject.eq(issue.subject.clone()),
                oauth_tokens::dpop_jkt.eq(issue.dpop_jkt.clone()),
            ))
            .execute(&mut conn)
            .await
            .is_err()
        {
            return oauth_token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "refresh token 持久化失败.",
                false,
            );
        }
        body["refresh_token"] = json!(raw_refresh);
    }
    if issue.scopes.iter().any(|s| s == "openid") {
        let id_token = match make_id_token(
            state,
            &issue.subject,
            &client.client_id,
            issue.nonce,
            state.settings.id_token_ttl_seconds,
        ) {
            Ok(token) => token,
            Err(_) => {
                return oauth_token_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "id_token 签发失败.",
                    false,
                );
            }
        };
        body["id_token"] = json!(id_token);
    }
    json_response_no_store(body)
}
