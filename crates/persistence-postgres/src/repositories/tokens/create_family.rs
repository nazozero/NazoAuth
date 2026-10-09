//! One database call for the existing new-family capacity transition.
use super::*;

pub(super) async fn create(
    connection: &mut AsyncPgConnection,
    token: &nazo_auth::NewRefreshToken,
    contract: &PreparedRefreshContract,
    issuance_id: Uuid,
    native_source: Option<&nazo_auth::NativeSsoSourceFence>,
) -> diesel::QueryResult<(RefreshTokenPersistResult, Option<RetiredNativeSsoSource>)> {
    #[derive(QueryableByName)]
    struct Outcome {
        #[diesel(sql_type=sql_types::Text)]
        outcome: String,
        #[diesel(sql_type=sql_types::Nullable<sql_types::Jsonb>)]
        retired_source: Option<Value>,
    }
    // Drain the result. This call does not commit: its caller keeps ownership
    // of the transaction and confirms COMMIT before returning success.
    let rows = CreateFamily {
        token,
        contract,
        issuance_id,
        native_source: native_source.map(|source| source.family_id),
        scope_lock: refresh_grant_scope_lock_key(token.tenant_id, token.user_id, token.client_id),
        digest: blake3::hash(token.raw_token.as_bytes()),
        audiences: serde_json::json!(token.audiences),
    }
    .load::<Outcome>(connection)
    .await?;
    let mut rows = rows.into_iter();
    let row = rows
        .next()
        .filter(|_| rows.next().is_none())
        .ok_or_else(|| {
            deserialization_error(RepositoryError::Consistency(
                "invalid family creation result cardinality".to_owned(),
            ))
        })?;
    match row.outcome.as_str() {
        "conflict" if row.retired_source.is_none() => {
            Ok((RefreshTokenPersistResult::RotationConflict, None))
        }
        "inserted" => {
            let retired = row
                .retired_source
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| diesel::result::Error::DeserializationError(Box::new(error)))?;
            Ok((RefreshTokenPersistResult::Inserted, retired))
        }
        _ => Err(deserialization_error(RepositoryError::Consistency(
            "unknown family creation result".to_owned(),
        ))),
    }
}

struct CreateFamily<'a> {
    token: &'a nazo_auth::NewRefreshToken,
    contract: &'a PreparedRefreshContract,
    issuance_id: Uuid,
    native_source: Option<Uuid>,
    scope_lock: i64,
    digest: blake3::Hash,
    audiences: Value,
}
impl diesel::query_builder::QueryId for CreateFamily<'_> {
    type QueryId = CreateFamily<'static>;
    const HAS_STATIC_QUERY_ID: bool = true;
}
impl diesel::query_builder::Query for CreateFamily<'_> {
    type SqlType = sql_types::Untyped;
}
impl<Conn> diesel::RunQueryDsl<Conn> for CreateFamily<'_> {}
impl diesel::query_builder::QueryFragment<diesel::pg::Pg> for CreateFamily<'_> {
    fn walk_ast<'b>(
        &'b self,
        mut out: diesel::query_builder::AstPass<'_, 'b, diesel::pg::Pg>,
    ) -> diesel::QueryResult<()> {
        out.push_sql("SELECT outcome, retired_source FROM public.nazo_create_refresh_family(");
        out.push_bind_param::<sql_types::Uuid, _>(&self.token.tenant_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Uuid, _>(&self.token.family_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Uuid, _>(&self.token.client_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Nullable<sql_types::Uuid>, _>(&self.token.user_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Binary, _>(&self.contract.contract_blake3)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Jsonb, _>(&self.contract.contract_value)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Uuid, _>(&self.token.member_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Binary, _>(self.digest.as_bytes().as_slice())?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Jsonb, _>(&self.audiences)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Timestamptz, _>(&self.token.issued_at)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Timestamptz, _>(&self.token.expires_at)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Nullable<sql_types::Text>, _>(&self.token.id_token_sid)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Nullable<sql_types::Text>, _>(&self.token.dpop_jkt)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Nullable<sql_types::Text>, _>(&self.token.mtls_x5t_s256)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Nullable<sql_types::Text>, _>(
            &self.token.client_attestation_jkt,
        )?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::BigInt, _>(&self.scope_lock)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::BigInt, _>(&MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Uuid, _>(&self.issuance_id)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Nullable<sql_types::Uuid>, _>(&self.native_source)?;
        out.push_sql(", ");
        out.push_bind_param::<sql_types::Text, _>(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION)?;
        out.push_sql(")");
        Ok(())
    }
}
