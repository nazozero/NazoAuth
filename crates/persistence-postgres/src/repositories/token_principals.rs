//! Principal-sized token authority: versions and reusable private-subject ownership.
use diesel::{
    BoolExpressionMethods, ExpressionMethods, NullableExpressionMethods, OptionalExtension,
    QueryDsl, QueryableByName, sql_query, sql_types,
};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_auth::{CommitTokenIssuance, CommitTokenIssuanceResult, TokenPrincipalState};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::schema::oauth_subject_bindings;

// Security-only projections of the existing tables. The full client projection
// already has 64 columns; these reads do not need that profile/configuration data.
diesel::table! {
    #[sql_name = "users"]
    user_principals (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        is_active -> Bool,
        access_token_epoch -> BigInt,
    }
}

diesel::allow_tables_to_appear_in_same_query!(user_principals, oauth_subject_bindings,);

pub(super) async fn snapshot(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    client_epoch: i64,
    user_id: Option<Uuid>,
    subject: &str,
) -> Result<TokenPrincipalState, RepositoryError> {
    // Keep the authenticated client version; a later read must not endorse
    // old authentication with a newer epoch. User and binding share one snapshot.
    // Only security columns are read: no profile preload for non-OIDC issuance.
    // Missing/inactive principals are still classified by the locked commit check.
    // Keep this one MVCC snapshot and a typed query so every connection can
    // reuse its prepared statement across tenants, clients and subject types.
    let user_epoch = user_principals::table
        .filter(user_principals::tenant_id.eq(tenant_id))
        .filter(user_principals::id.nullable().eq(user_id))
        .select(user_principals::access_token_epoch)
        .single_value();
    let private_subject = user_id.is_some_and(|id| subject != id.to_string());
    let bound_user = oauth_subject_bindings::table
        .filter(oauth_subject_bindings::tenant_id.eq(tenant_id))
        .filter(
            oauth_subject_bindings::subject
                .eq(subject)
                .and::<_, sql_types::Bool>(private_subject),
        )
        .select(oauth_subject_bindings::user_id)
        .single_value();
    let (user_epoch, bound_user) = diesel::select((user_epoch, bound_user))
        .get_result::<(Option<i64>, Option<Uuid>)>(connection)
        .await
        .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
    if bound_user.is_some() && bound_user != user_id {
        return Err(RepositoryError::Consistency(
            "subject ownership collision".to_owned(),
        ));
    }
    Ok(TokenPrincipalState {
        client_epoch,
        user_epoch: user_id.map(|_| user_epoch.unwrap_or(0)),
        subject_bound: bound_user.is_some(),
    })
}

pub(super) async fn lock_and_recheck(
    connection: &mut AsyncPgConnection,
    input: &CommitTokenIssuance,
) -> diesel::QueryResult<Result<String, CommitTokenIssuanceResult>> {
    #[derive(QueryableByName)]
    struct Fence {
        #[diesel(sql_type = sql_types::Text)]
        outcome: String,
        #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
        client_type: Option<String>,
    }
    let rows = PrincipalFence(input).load::<Fence>(connection).await?;
    let mut rows = rows.into_iter();
    let row = rows
        .next()
        .filter(|_| rows.next().is_none())
        .ok_or_else(|| {
            diesel::result::Error::DeserializationError(
                "invalid principal fence cardinality".into(),
            )
        })?;
    match (row.outcome.as_str(), row.client_type) {
        ("ok", Some(client_type)) => Ok(Ok(client_type)),
        ("client_inactive", None) => Ok(Err(CommitTokenIssuanceResult::ClientInactive)),
        ("subject_inactive", None) => Ok(Err(CommitTokenIssuanceResult::SubjectInactive)),
        _ => Err(diesel::result::Error::DeserializationError(
            "invalid principal fence outcome".into(),
        )),
    }
}

struct PrincipalFence<'a>(&'a CommitTokenIssuance);
impl diesel::query_builder::QueryId for PrincipalFence<'_> {
    type QueryId = PrincipalFence<'static>;
    const HAS_STATIC_QUERY_ID: bool = true;
}
impl diesel::query_builder::Query for PrincipalFence<'_> {
    type SqlType = sql_types::Untyped;
}
impl<Conn> diesel::RunQueryDsl<Conn> for PrincipalFence<'_> {}
impl diesel::query_builder::QueryFragment<diesel::pg::Pg> for PrincipalFence<'_> {
    fn walk_ast<'b>(
        &'b self,
        mut out: diesel::query_builder::AstPass<'_, 'b, diesel::pg::Pg>,
    ) -> diesel::QueryResult<()> {
        out.push_sql("SELECT outcome, client_type FROM public.nazo_lock_token_principals(");
        out.push_bind_param::<sql_types::Uuid, _>(&self.0.tenant_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Uuid, _>(&self.0.client_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::BigInt, _>(&self.0.principal_state.client_epoch)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Nullable<sql_types::Uuid>, _>(&self.0.user_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Nullable<sql_types::BigInt>, _>(
            &self.0.principal_state.user_epoch,
        )?;
        out.push_sql(")");
        Ok(())
    }
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
