//! 基础行查询函数。
// 只放被多个 handler 复用的简单 Diesel 查询。

use super::prelude::*;

pub(crate) async fn find_user_by_email(
    db: &DbPool,
    email: &str,
) -> anyhow::Result<Option<UserRow>> {
    let mut conn = db.get().await?;
    Ok(users::table
        .filter(users::email.eq(email))
        .select(UserRow::as_select())
        .first::<UserRow>(&mut conn)
        .await
        .optional()?)
}

pub(crate) async fn find_user_by_id(db: &DbPool, id: Uuid) -> anyhow::Result<Option<UserRow>> {
    let mut conn = db.get().await?;
    Ok(users::table
        .find(id)
        .select(UserRow::as_select())
        .first::<UserRow>(&mut conn)
        .await
        .optional()?)
}

pub(crate) async fn find_client(db: &DbPool, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
    let mut conn = db.get().await?;
    Ok(oauth_clients::table
        .filter(oauth_clients::client_id.eq(client_id))
        .select(ClientRow::as_select())
        .first::<ClientRow>(&mut conn)
        .await
        .optional()?)
}

pub(crate) async fn find_active_mtls_client_by_thumbprint(
    db: &DbPool,
    thumbprint: &str,
) -> anyhow::Result<Option<ClientRow>> {
    let mut conn = db.get().await?;
    let clients = oauth_clients::table
        .filter(oauth_clients::tls_client_auth_cert_sha256.eq(thumbprint))
        .filter(
            oauth_clients::token_endpoint_auth_method
                .eq_any(["tls_client_auth", "self_signed_tls_client_auth"]),
        )
        .filter(oauth_clients::client_type.eq("confidential"))
        .filter(oauth_clients::is_active.eq(true))
        .select(ClientRow::as_select())
        .limit(2)
        .load::<ClientRow>(&mut conn)
        .await?;
    Ok(match clients.as_slice() {
        [client] => Some(client.clone()),
        _ => None,
    })
}
