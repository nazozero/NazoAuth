use diesel_async::{AsyncConnection, AsyncPgConnection};

use super::*;

pub(super) enum RefreshPersistResult {
    Inserted,
    RotationConflict,
}

pub(super) struct PendingRefreshToken {
    pub(super) raw: String,
    pub(super) family: Uuid,
    pub(super) rotated_from: Option<Uuid>,
    pub(super) issued_at: DateTime<Utc>,
    pub(super) expires_at: DateTime<Utc>,
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
    client: &ClientRow,
    issue: &TokenIssue,
    refresh: &PendingRefreshToken,
) -> diesel::QueryResult<usize> {
    diesel::insert_into(oauth_tokens::table)
        .values((
            oauth_tokens::refresh_token_blake3.eq(blake3_hex(&refresh.raw)),
            oauth_tokens::tenant_id.eq(client.tenant_id),
            oauth_tokens::token_family_id.eq(refresh.family),
            oauth_tokens::rotated_from_id.eq(refresh.rotated_from),
            oauth_tokens::client_id.eq(client.id),
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

pub(super) async fn persist_refresh_token(
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
                        .filter(oauth_tokens::tenant_id.eq(client.tenant_id))
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
            insert_refresh_token(conn, client, issue, refresh).await?;
            Ok(RefreshPersistResult::Inserted)
        })
        .await?;
    Ok(result)
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/token/tests/refresh_persistence.rs"]
mod tests;
