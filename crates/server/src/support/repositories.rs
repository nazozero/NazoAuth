//! 基础行查询函数。
// 只放被多个 handler 复用的简单 Diesel 查询。

use super::mtls::{MtlsClientCertificate, client_mtls_certificate_matches};
use super::prelude::*;
use super::tenancy::DEFAULT_TENANT_ID;

pub(crate) async fn find_user_by_email(
    db: &DbPool,
    email: &str,
) -> anyhow::Result<Option<UserRow>> {
    find_user_by_email_in_tenant(db, DEFAULT_TENANT_ID, email).await
}

pub(crate) async fn find_user_by_email_in_tenant(
    db: &DbPool,
    tenant_id: Uuid,
    email: &str,
) -> anyhow::Result<Option<UserRow>> {
    let mut conn = db.get().await?;
    Ok(users::table
        .filter(users::tenant_id.eq(tenant_id))
        .filter(users::email.eq(email.trim()))
        .select(UserRow::as_select())
        .first::<UserRow>(&mut conn)
        .await
        .optional()?)
}

pub(crate) async fn find_user_by_id(db: &DbPool, id: Uuid) -> anyhow::Result<Option<UserRow>> {
    find_user_by_id_in_tenant(db, DEFAULT_TENANT_ID, id).await
}

pub(crate) async fn find_user_by_id_in_tenant(
    db: &DbPool,
    tenant_id: Uuid,
    id: Uuid,
) -> anyhow::Result<Option<UserRow>> {
    let mut conn = db.get().await?;
    Ok(users::table
        .find(id)
        .filter(users::tenant_id.eq(tenant_id))
        .select(UserRow::as_select())
        .first::<UserRow>(&mut conn)
        .await
        .optional()?)
}

pub(crate) async fn find_client(db: &DbPool, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
    find_client_in_tenant(db, DEFAULT_TENANT_ID, client_id).await
}

pub(crate) async fn find_client_in_tenant(
    db: &DbPool,
    tenant_id: Uuid,
    client_id: &str,
) -> anyhow::Result<Option<ClientRow>> {
    let mut conn = db.get().await?;
    Ok(oauth_clients::table
        .filter(oauth_clients::tenant_id.eq(tenant_id))
        .filter(oauth_clients::client_id.eq(client_id))
        .select(ClientRow::as_select())
        .first::<ClientRow>(&mut conn)
        .await
        .optional()?)
}

pub(crate) async fn find_client_by_id(db: &DbPool, id: Uuid) -> anyhow::Result<Option<ClientRow>> {
    let mut conn = db.get().await?;
    Ok(oauth_clients::table
        .find(id)
        .select(ClientRow::as_select())
        .first::<ClientRow>(&mut conn)
        .await
        .optional()?)
}

pub(crate) async fn find_active_mtls_client_by_certificate(
    db: &DbPool,
    certificate: &MtlsClientCertificate,
) -> anyhow::Result<Option<ClientRow>> {
    let mut conn = db.get().await?;
    let candidates = oauth_clients::table
        .filter(oauth_clients::tenant_id.eq(DEFAULT_TENANT_ID))
        .filter(
            oauth_clients::token_endpoint_auth_method
                .eq_any(["tls_client_auth", "self_signed_tls_client_auth"]),
        )
        .filter(oauth_clients::client_type.eq("confidential"))
        .filter(oauth_clients::is_active.eq(true))
        .select(ClientRow::as_select())
        .limit(1000)
        .load::<ClientRow>(&mut conn)
        .await?;
    let clients = candidates
        .into_iter()
        .filter(|client| client_mtls_certificate_matches(client, certificate))
        .take(2)
        .collect::<Vec<_>>();
    Ok(match clients.as_slice() {
        [client] => Some(client.clone()),
        _ => None,
    })
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/repositories.rs"]
mod tests;
