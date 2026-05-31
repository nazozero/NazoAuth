//! token revoke 端点。
// 只处理 refresh token 撤销和 access token jti 黑名单写入。
use super::TokenOnlyForm;
use crate::http::prelude::*;

pub(crate) async fn revoke(
    state: Data<AppState>,
    req: HttpRequest,
    Form(form): Form<TokenOnlyForm>,
) -> HttpResponse {
    let (client_id, client_secret, method) = extract_client_credentials(
        req.headers(),
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    );
    let Some(client_id) = client_id else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    let Some(client) = find_client(&state.diesel_db, &client_id)
        .await
        .ok()
        .flatten()
    else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    if client.client_type == "confidential"
        && (method != client.token_endpoint_auth_method
            || !verify_password(
                client_secret.as_deref().unwrap_or(""),
                client.client_secret_argon2_hash.as_deref().unwrap_or(""),
            ))
    {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    }
    let refresh_hash = blake3_hex(&form.token);
    let updated = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => diesel::update(
            oauth_tokens::table
                .filter(oauth_tokens::refresh_token_blake3.eq(&refresh_hash))
                .filter(oauth_tokens::client_id.eq(client.id)),
        )
        .set(oauth_tokens::revoked_at.eq(diesel_now))
        .execute(&mut conn)
        .await
        .unwrap_or(0),
        Err(_) => 0,
    };
    if updated == 0
        && let Some(claims) = decode_access_claims(&state, &form.token)
        && claims.client_id == client.client_id
        && let (Some(expires_at), Ok(mut conn)) = (
            DateTime::<Utc>::from_timestamp(claims.exp, 0),
            get_conn(&state.diesel_db).await,
        )
    {
        let _ = diesel::insert_into(access_token_revocations::table)
            .values((
                access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)),
                access_token_revocations::client_id.eq(client.id),
                access_token_revocations::revoked_at.eq(Utc::now()),
                access_token_revocations::expires_at.eq(expires_at),
            ))
            .on_conflict(access_token_revocations::access_token_jti_blake3)
            .do_nothing()
            .execute(&mut conn)
            .await;
    }
    json_response(json!({"result": "已处理"}))
}
