//! 令牌签发响应构造。
// 统一 access_token、refresh_token 和 id_token 的响应形状。
use crate::http::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection};

const MARK_CONSUMED_AUTHORIZATION_CODE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status ~= 'consuming' then
  return state.status
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 'ok'
"#;

const MARK_FAILED_AUTHORIZATION_CODE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status ~= 'consuming' then
  return state.status
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 'ok'
"#;

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
            oauth_tokens::authorization_details.eq(issue.authorization_details.clone()),
            oauth_tokens::issued_at.eq(refresh.issued_at),
            oauth_tokens::expires_at.eq(refresh.expires_at),
            oauth_tokens::subject.eq(issue.subject.clone()),
            oauth_tokens::dpop_jkt.eq(issue.refresh_token_dpop_jkt.clone()),
            oauth_tokens::mtls_x5t_s256.eq(issue.refresh_token_mtls_x5t_s256.clone()),
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

async fn persist_consumed_authorization_code(
    state: &AppState,
    code_hash: &str,
    client_id: Uuid,
    access_token_jti: String,
    access_token_expires_at: i64,
    refresh_token_family_id: Option<Uuid>,
) -> anyhow::Result<()> {
    let payload = ConsumedAuthorizationCode {
        client_id,
        access_token_jti,
        access_token_expires_at,
        refresh_token_family_id,
        consumed_at: Utc::now(),
    };
    let body = serde_json::to_string(&AuthorizationCodeState::Consumed { marker: payload })?;
    let ttl_seconds = if refresh_token_family_id.is_some() {
        state.settings.refresh_token_ttl_seconds
    } else {
        state.settings.access_token_ttl_seconds
    };
    let ttl_seconds = if ttl_seconds <= 0 {
        1
    } else {
        ttl_seconds as u64
    };
    let result = valkey_eval_string(
        &state.valkey,
        MARK_CONSUMED_AUTHORIZATION_CODE_SCRIPT,
        vec![authorization_code_key_from_hash(code_hash)],
        vec![body, ttl_seconds.to_string()],
    )
    .await?;
    if result != "ok" {
        anyhow::bail!("authorization code state is {result}, expected consuming");
    }
    Ok(())
}

pub(super) async fn mark_failed_authorization_code(
    state: &AppState,
    code_hash: &str,
    error_code: &str,
) -> anyhow::Result<()> {
    let body = serde_json::to_string(&AuthorizationCodeState::Failed {
        failed_at: Utc::now(),
        error: error_code.to_owned(),
    })?;
    let result = valkey_eval_string(
        &state.valkey,
        MARK_FAILED_AUTHORIZATION_CODE_SCRIPT,
        vec![authorization_code_key_from_hash(code_hash)],
        vec![
            body,
            state.settings.auth_code_ttl_seconds.max(1).to_string(),
        ],
    )
    .await?;
    if matches!(result.as_str(), "ok" | "missing" | "failed" | "consumed") {
        Ok(())
    } else {
        anyhow::bail!("authorization code state is {result}, expected consuming");
    }
}

async fn mark_failed_authorization_code_if_needed(
    state: &AppState,
    code_hash: Option<&str>,
    error_code: &str,
) {
    if let Some(code_hash) = code_hash
        && let Err(error) = mark_failed_authorization_code(state, code_hash, error_code).await
    {
        tracing::warn!(%error, "failed to mark authorization code exchange as failed");
    }
}

pub(super) async fn revoke_issued_authorization_code_tokens(
    state: &AppState,
    client_id: Uuid,
    access_token_jti: &str,
    access_token_expires_at: i64,
    refresh_token_family_id: Option<Uuid>,
) -> anyhow::Result<()> {
    let mut conn = get_conn(&state.diesel_db).await?;
    if let Some(expires_at) = DateTime::<Utc>::from_timestamp(access_token_expires_at, 0) {
        diesel::insert_into(access_token_revocations::table)
            .values((
                access_token_revocations::access_token_jti_blake3.eq(blake3_hex(access_token_jti)),
                access_token_revocations::client_id.eq(client_id),
                access_token_revocations::revoked_at.eq(Utc::now()),
                access_token_revocations::expires_at.eq(expires_at),
            ))
            .on_conflict(access_token_revocations::access_token_jti_blake3)
            .do_nothing()
            .execute(&mut conn)
            .await?;
    }
    if let Some(family_id) = refresh_token_family_id {
        diesel::update(
            oauth_tokens::table
                .filter(oauth_tokens::client_id.eq(client_id))
                .filter(oauth_tokens::token_family_id.eq(family_id))
                .filter(oauth_tokens::revoked_at.is_null()),
        )
        .set(oauth_tokens::revoked_at.eq(diesel_now))
        .execute(&mut conn)
        .await?;
    }
    Ok(())
}

pub(crate) async fn issue_token_response(
    state: &AppState,
    client: &ClientRow,
    issue: TokenIssue,
) -> HttpResponse {
    let now = Utc::now();
    let next_dpop_nonce = if issue.dpop_jkt.is_some() {
        match issue_dpop_nonce(state).await {
            Ok(nonce) => Some(nonce),
            Err(error) => {
                mark_failed_authorization_code_if_needed(
                    state,
                    issue.authorization_code_hash.as_deref(),
                    "dpop_next_nonce_failed",
                )
                .await;
                return dpop_error_response(error, DpopErrorContext::TokenEndpoint);
            }
        }
    } else {
        None
    };
    let issued_access_token = match make_jwt(
        state,
        AccessTokenJwtInput {
            subject: &issue.subject,
            user_id: issue.user_id,
            subject_type: if issue.user_id.is_some() {
                "user"
            } else {
                "client"
            },
            client_id: &client.client_id,
            audiences: &issue.audiences,
            scopes: &issue.scopes,
            authorization_details: &issue.authorization_details,
            userinfo_claims: &issue.userinfo_claims,
            userinfo_claim_requests: &issue.userinfo_claim_requests,
            ttl: state.settings.access_token_ttl_seconds,
            dpop_jkt: issue.dpop_jkt.as_deref(),
            mtls_x5t_s256: issue.mtls_x5t_s256.as_deref(),
        },
    )
    .await
    {
        Ok(v) => v,
        Err(_) => {
            mark_failed_authorization_code_if_needed(
                state,
                issue.authorization_code_hash.as_deref(),
                "access_token_signing_failed",
            )
            .await;
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
        "access_token": issued_access_token.token,
        "token_type": token_type,
        "expires_in": state.settings.access_token_ttl_seconds,
        "scope": issue.scopes.join(" ")
    });
    let mut refresh_token_family_id = None;
    if issue.scopes.iter().any(|s| s == "openid") {
        let user_claims = match issue.user_id {
            Some(user_id) => match find_user_by_id(&state.diesel_db, user_id).await {
                Ok(Some(user)) if user.is_active => Some(oidc_id_token_user_claims(
                    &user,
                    &issue.scopes,
                    &issue.subject,
                    &issue.id_token_claims,
                    &issue.id_token_claim_requests,
                )),
                Ok(_) => {
                    mark_failed_authorization_code_if_needed(
                        state,
                        issue.authorization_code_hash.as_deref(),
                        "id_token_subject_invalid",
                    )
                    .await;
                    return oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "授权用户不存在或已停用.",
                        false,
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to load id_token subject");
                    mark_failed_authorization_code_if_needed(
                        state,
                        issue.authorization_code_hash.as_deref(),
                        "id_token_subject_load_failed",
                    )
                    .await;
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
            IdTokenInput {
                subject: &issue.subject,
                client_id: &client.client_id,
                nonce: issue.nonce.clone(),
                auth_time: issue.auth_time,
                amr: &issue.amr,
                sid: issue.oidc_sid.as_deref(),
                acr: issue.acr.as_deref(),
                extra_claims: user_claims.as_ref(),
                ttl: state.settings.id_token_ttl_seconds,
            },
        )
        .await
        {
            Ok(token) => token,
            Err(_) => {
                mark_failed_authorization_code_if_needed(
                    state,
                    issue.authorization_code_hash.as_deref(),
                    "id_token_signing_failed",
                )
                .await;
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
                refresh_token_family_id = Some(refresh.family);
            }
            Ok(RefreshPersistResult::RotationConflict) => {
                mark_failed_authorization_code_if_needed(
                    state,
                    issue.authorization_code_hash.as_deref(),
                    "refresh_rotation_conflict",
                )
                .await;
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token 无效或已撤销.",
                    false,
                );
            }
            Err(error) => {
                tracing::warn!(%error, "failed to persist refresh token");
                mark_failed_authorization_code_if_needed(
                    state,
                    issue.authorization_code_hash.as_deref(),
                    "refresh_persist_failed",
                )
                .await;
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
    if let Some(code_hash) = issue.authorization_code_hash.as_deref()
        && let Err(error) = persist_consumed_authorization_code(
            state,
            code_hash,
            client.id,
            issued_access_token.jti.clone(),
            issued_access_token.exp,
            refresh_token_family_id,
        )
        .await
    {
        tracing::warn!(%error, "failed to persist consumed authorization code marker");
        if let Err(revoke_error) = revoke_issued_authorization_code_tokens(
            state,
            client.id,
            &issued_access_token.jti,
            issued_access_token.exp,
            refresh_token_family_id,
        )
        .await
        {
            tracing::warn!(%revoke_error, "failed to revoke tokens after authorization code marker failure");
        }
        return oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权码兑换状态写入失败.",
            false,
        );
    }
    audit_event(
        "token_issued",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("user_id", json!(issue.user_id)),
            ("subject_hash", json!(blake3_hex(&issue.subject))),
            ("scope", json!(issue.scopes.join(" "))),
            ("audience", json!(issue.audiences)),
            ("access_token_jti", json!(issued_access_token.jti)),
            ("refresh_token_family_id", json!(refresh_token_family_id)),
        ]),
    );
    if let Some((family_id, rotated_from_id)) = issue.rotation {
        audit_event(
            "refresh_rotated",
            audit_fields(&[
                ("client_id", json!(client.client_id)),
                ("token_family_id", json!(family_id)),
                ("rotated_from_id", json!(rotated_from_id)),
            ]),
        );
    }
    let mut response = json_response_no_store(body);
    if let Some(nonce) = next_dpop_nonce
        && let Ok(value) = HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response
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
            require_dpop_bound_tokens: false,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: json!([]),
            tls_client_auth_san_uri: json!([]),
            tls_client_auth_san_ip: json!([]),
            tls_client_auth_san_email: json!([]),
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            is_active: true,
            jwks: None,
            post_logout_redirect_uris: json!([]),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
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
