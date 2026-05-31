//! 令牌签发响应构造。
// 统一 access_token、refresh_token 和 id_token 的响应形状。
use crate::http::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection};

enum RefreshPersistResult {
    Inserted,
    RotationConflict,
}

struct PendingRefreshToken {
    raw: String,
    family: Uuid,
    rotated_from: Option<Uuid>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

pub(crate) fn should_issue_refresh_token(client: &ClientRow, scopes: &[String]) -> bool {
    client_supports_grant(client, "refresh_token")
        && scopes.iter().any(|scope| scope == "offline_access")
}

async fn mark_token_family_reuse(
    conn: &mut AsyncPgConnection,
    token_family_id: Uuid,
) -> diesel::QueryResult<()> {
    diesel::update(oauth_tokens::table.filter(oauth_tokens::token_family_id.eq(token_family_id)))
        .set(oauth_tokens::reuse_detected_at.eq(diesel_now))
        .execute(conn)
        .await?;
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::token_family_id.eq(token_family_id))
            .filter(oauth_tokens::revoked_at.is_null()),
    )
    .set(oauth_tokens::revoked_at.eq(diesel_now))
    .execute(conn)
    .await?;
    Ok(())
}

async fn insert_refresh_token(
    conn: &mut AsyncPgConnection,
    client_id: Uuid,
    issue: &TokenIssue,
    refresh: &PendingRefreshToken,
) -> diesel::QueryResult<usize> {
    diesel::insert_into(oauth_tokens::table)
        .values((
            oauth_tokens::refresh_token_blake3.eq(blake3_hex(&refresh.raw)),
            oauth_tokens::token_family_id.eq(refresh.family),
            oauth_tokens::rotated_from_id.eq(refresh.rotated_from),
            oauth_tokens::client_id.eq(client_id),
            oauth_tokens::user_id.eq(issue.user_id),
            oauth_tokens::scopes.eq(json!(issue.scopes)),
            oauth_tokens::issued_at.eq(refresh.issued_at),
            oauth_tokens::expires_at.eq(refresh.expires_at),
            oauth_tokens::subject.eq(issue.subject.clone()),
            oauth_tokens::dpop_jkt.eq(issue.dpop_jkt.clone()),
        ))
        .execute(conn)
        .await
}

async fn persist_refresh_token(
    state: &AppState,
    client: &ClientRow,
    issue: &TokenIssue,
    refresh: &PendingRefreshToken,
) -> anyhow::Result<RefreshPersistResult> {
    let mut conn = get_conn(&state.diesel_db).await?;
    let result = conn
        .transaction::<RefreshPersistResult, diesel::result::Error, _>(async |conn| {
            if let Some(rotated_from) = refresh.rotated_from {
                let rotated = diesel::update(
                    oauth_tokens::table
                        .filter(oauth_tokens::id.eq(rotated_from))
                        .filter(oauth_tokens::revoked_at.is_null()),
                )
                .set(oauth_tokens::revoked_at.eq(diesel_now))
                .execute(conn)
                .await?;
                if rotated == 0 {
                    mark_token_family_reuse(conn, refresh.family).await?;
                    return Ok(RefreshPersistResult::RotationConflict);
                }
            }
            insert_refresh_token(conn, client.id, issue, refresh).await?;
            Ok(RefreshPersistResult::Inserted)
        })
        .await?;
    Ok(result)
}

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
    if issue.scopes.iter().any(|s| s == "openid") {
        let user_claims = match issue.user_id {
            Some(user_id) => match find_user_by_id(&state.diesel_db, user_id).await {
                Ok(Some(user)) if user.is_active => {
                    Some(oidc_user_claims(&user, &issue.scopes, &issue.subject))
                }
                Ok(_) => {
                    return oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "授权用户不存在或已停用.",
                        false,
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to load id_token subject");
                    return oauth_token_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "id_token 用户声明加载失败.",
                        false,
                    );
                }
            },
            None => None,
        };
        let id_token = match make_id_token(
            state,
            &issue.subject,
            &client.client_id,
            issue.nonce.clone(),
            user_claims.as_ref(),
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
    if issue.include_refresh && should_issue_refresh_token(client, &issue.scopes) {
        let refresh = PendingRefreshToken {
            raw: format!("{}.{}", random_urlsafe_token(), random_urlsafe_token()),
            family: issue.rotation.map(|r| r.0).unwrap_or_else(Uuid::now_v7),
            rotated_from: issue.rotation.and_then(|r| r.1),
            issued_at: now,
            expires_at: now + Duration::seconds(state.settings.refresh_token_ttl_seconds),
        };
        match persist_refresh_token(state, client, &issue, &refresh).await {
            Ok(RefreshPersistResult::Inserted) => {
                body["refresh_token"] = json!(refresh.raw);
            }
            Ok(RefreshPersistResult::RotationConflict) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token 无效或已撤销.",
                    false,
                );
            }
            Err(error) => {
                tracing::warn!(%error, "failed to persist refresh token");
                let description = if refresh.rotated_from.is_some() {
                    "refresh_token 轮换失败."
                } else {
                    "refresh token 持久化失败."
                };
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    description,
                    false,
                );
            }
        }
    }
    json_response_no_store(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_with_grants(grant_types: &[&str]) -> ClientRow {
        ClientRow {
            id: Uuid::now_v7(),
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "public".to_owned(),
            client_secret_argon2_hash: None,
            redirect_uris: json!(["https://client.example/callback"]),
            scopes: json!(["openid", "offline_access"]),
            allowed_audiences: json!(["resource://default"]),
            grant_types: json!(grant_types),
            token_endpoint_auth_method: "none".to_owned(),
            is_active: true,
            jwks: None,
        }
    }

    #[test]
    fn refresh_token_requires_offline_access_scope_and_client_grant() {
        let client = client_with_grants(&["authorization_code", "refresh_token"]);
        let scopes = vec!["openid".to_owned(), "profile".to_owned()];
        assert!(!should_issue_refresh_token(&client, &scopes));

        let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
        assert!(should_issue_refresh_token(&client, &scopes));

        let client = client_with_grants(&["authorization_code"]);
        assert!(!should_issue_refresh_token(&client, &scopes));
    }
}
