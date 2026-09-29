//! Principal-sized token authority: versions and reusable private-subject ownership.
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_auth::{CommitTokenIssuance, CommitTokenIssuanceResult, TokenPrincipalState};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

#[derive(QueryableByName)]
struct Snapshot {
    #[diesel(sql_type = sql_types::BigInt)]
    client_epoch: i64,
    #[diesel(sql_type = sql_types::Nullable<sql_types::BigInt>)]
    user_epoch: Option<i64>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    bound_user: Option<Uuid>,
}

pub(super) async fn snapshot(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    client_id: Uuid,
    user_id: Option<Uuid>,
    subject: &str,
) -> Result<TokenPrincipalState, RepositoryError> {
    // Only security columns are read: no profile preload for non-OIDC issuance.
    // Missing/inactive principals are still classified by the locked commit check.
    let row = sql_query(
        "SELECT COALESCE(c.access_token_epoch, 0)::bigint AS client_epoch, \
                CASE WHEN $3::uuid IS NOT NULL THEN COALESCE(u.access_token_epoch, 0) END AS user_epoch, \
                b.user_id AS bound_user \
         FROM (SELECT $1::uuid AS tenant_id) AS request \
         LEFT JOIN oauth_clients c ON c.tenant_id = request.tenant_id AND c.id = $2 \
         LEFT JOIN users u ON u.tenant_id = request.tenant_id AND u.id = $3 \
         LEFT JOIN oauth_subject_bindings b ON $3::uuid IS NOT NULL AND b.tenant_id = request.tenant_id AND b.subject = $4",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(client_id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(user_id)
    .bind::<sql_types::Text, _>(subject)
    .get_result::<Snapshot>(connection)
    .await
    .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
    if row.bound_user.is_some() && row.bound_user != user_id {
        return Err(RepositoryError::Consistency(
            "subject ownership collision".to_owned(),
        ));
    }
    Ok(TokenPrincipalState {
        client_epoch: row.client_epoch,
        user_epoch: row.user_epoch,
        subject_bound: row.bound_user.is_some(),
    })
}

#[derive(QueryableByName)]
struct LockedPrincipal {
    #[diesel(sql_type = sql_types::Bool)]
    is_active: bool,
    #[diesel(sql_type = sql_types::BigInt)]
    access_token_epoch: i64,
}

pub(super) async fn lock_and_recheck(
    connection: &mut AsyncPgConnection,
    input: &CommitTokenIssuance,
) -> diesel::QueryResult<Option<CommitTokenIssuanceResult>> {
    let client = sql_query("SELECT is_active, access_token_epoch FROM oauth_clients WHERE tenant_id = $1 AND id = $2 FOR SHARE")
        .bind::<sql_types::Uuid, _>(input.tenant_id)
        .bind::<sql_types::Uuid, _>(input.client_id)
        .get_result::<LockedPrincipal>(connection).await.optional()?;
    if !client.is_some_and(|row| {
        row.is_active && row.access_token_epoch == input.principal_state.client_epoch
    }) {
        return Ok(Some(CommitTokenIssuanceResult::ClientInactive));
    }
    if let Some(user_id) = input.user_id {
        let user = sql_query("SELECT is_active, access_token_epoch FROM users WHERE tenant_id = $1 AND id = $2 FOR SHARE")
            .bind::<sql_types::Uuid, _>(input.tenant_id)
            .bind::<sql_types::Uuid, _>(user_id)
            .get_result::<LockedPrincipal>(connection).await.optional()?;
        if !user.is_some_and(|row| {
            row.is_active && Some(row.access_token_epoch) == input.principal_state.user_epoch
        }) {
            return Ok(Some(CommitTokenIssuanceResult::SubjectInactive));
        }
    }
    Ok(None)
}

#[derive(QueryableByName)]
struct BindingOwner {
    #[diesel(sql_type = sql_types::Uuid)]
    user_id: Uuid,
}

pub(super) async fn ensure_subject_binding(
    connection: &mut AsyncPgConnection,
    input: &CommitTokenIssuance,
) -> diesel::QueryResult<()> {
    let Some(user_id) = input.user_id else {
        return Ok(());
    };
    if input.subject == user_id.to_string() || input.principal_state.subject_bound {
        return Ok(());
    }
    let inserted = sql_query(
        "INSERT INTO oauth_subject_bindings (tenant_id, subject, user_id) VALUES ($1, $2, $3) \
         ON CONFLICT (tenant_id, subject) DO NOTHING RETURNING user_id",
    )
    .bind::<sql_types::Uuid, _>(input.tenant_id)
    .bind::<sql_types::Text, _>(&input.subject)
    .bind::<sql_types::Uuid, _>(user_id)
    .get_result::<BindingOwner>(connection)
    .await
    .optional()?;
    if inserted.is_some() {
        return Ok(());
    }
    // A concurrent first issuance may have created the same binding while we
    // waited. A new READ COMMITTED statement sees that committed owner.
    let owner = sql_query(
        "SELECT user_id FROM oauth_subject_bindings WHERE tenant_id = $1 AND subject = $2",
    )
    .bind::<sql_types::Uuid, _>(input.tenant_id)
    .bind::<sql_types::Text, _>(&input.subject)
    .get_result::<BindingOwner>(connection)
    .await?;
    if owner.user_id != user_id {
        return Err(diesel::result::Error::RollbackTransaction);
    }
    Ok(())
}
