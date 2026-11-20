use crate::{
    DbPool,
    convert::identity,
    get_conn,
    rows::identity::{PasskeyCredentialRow, PasskeyCredentialSummaryRow},
    schema::user_passkey_credentials,
};
use diesel::{
    ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper,
    dsl::now,
    result::{DatabaseErrorKind, Error},
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    TenantId, UserId,
    ports::{
        PasskeyAuthenticationUpdate, PasskeyCredential, PasskeyCredentialSummary, RepositoryError,
    },
};
use nazo_passkey::PasskeyCredential as WebauthnCredential;
use uuid::Uuid;

#[derive(Clone)]
pub struct PasskeyRepository {
    pool: DbPool,
}
impl PasskeyRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<PasskeyCredential>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        user_passkey_credentials::table
            .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid()))
            .order(user_passkey_credentials::created_at.asc())
            .select(PasskeyCredentialRow::as_select())
            .load(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(identity::passkey)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn list_summaries(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<PasskeyCredentialSummary>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        user_passkey_credentials::table
            .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid()))
            .order(user_passkey_credentials::created_at.asc())
            .select(PasskeyCredentialSummaryRow::as_select())
            .load(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(identity::passkey_summary)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn by_credential_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &str,
    ) -> Result<Option<PasskeyCredential>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        user_passkey_credentials::table
            .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid()))
            .filter(user_passkey_credentials::credential_id.eq(credential_id))
            .select(PasskeyCredentialRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(identity::passkey)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn insert(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential: WebauthnCredential,
        label: String,
    ) -> Result<PasskeyCredential, RepositoryError> {
        let credential_id = credential.id.to_b64url();
        let sign_count = i64::from(credential.counter);
        let credential = identity::encoded_passkey(&credential)
            .map_err(|error| RepositoryError::Consistency(error.0))?;
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let mut guard = crate::pool::DiscardOnDrop::new(connection);
        let result = guard
            .connection()
            .transaction::<_, Error, _>(async move |connection| {
                let row: PasskeyCredentialRow =
                    diesel::insert_into(user_passkey_credentials::table)
                        .values((
                            user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()),
                            user_passkey_credentials::user_id.eq(user_id.as_uuid()),
                            user_passkey_credentials::credential_id.eq(credential_id),
                            user_passkey_credentials::credential.eq(credential),
                            user_passkey_credentials::label.eq(label),
                            user_passkey_credentials::sign_count.eq(sign_count),
                        ))
                        .returning(PasskeyCredentialRow::as_returning())
                        .get_result(connection)
                        .await?;
                super::audit_ledger::append_fresh_security_audit_on_connection(
                    connection,
                    &nazo_persistence::SecurityAuditEvent {
                        event_id: uuid::Uuid::now_v7(),
                        event_type: "passkey_registered".into(),
                        event_category: "authentication".into(),
                        payload: serde_json::json!({
                            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                            "event_category": "authentication",
                            "tenant_id": tenant_id.as_uuid(),
                            "user_id": user_id.as_uuid(),
                            "credential_id": row.id,
                        }),
                        occurred_at: jiff::Timestamp::now(),
                    },
                )
                .await?;
                Ok(row)
            })
            .await;
        guard.return_to_pool();
        let row = result.map_err(map_error)?;
        identity::passkey(row).map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn update_authentication(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &str,
        update: PasskeyAuthenticationUpdate,
    ) -> Result<(), RepositoryError> {
        let credential = update.credential;
        let mut facts = serde_json::json!({
            "backup_eligible": credential.backup_eligible,
            "backup_state": credential.backup_state,
        });
        if update.initialize_user_verification {
            // A concurrent authentication must never revert an initialized UV.
            facts["uv_initialized"] = serde_json::Value::Bool(true);
        }
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel::update(
            user_passkey_credentials::table
                .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
                .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid()))
                .filter(user_passkey_credentials::credential_id.eq(credential_id))
                .filter(
                    user_passkey_credentials::sign_count.eq(i64::from(credential.expected_counter)),
                )
                .filter(
                    diesel::dsl::sql::<diesel::sql_types::Jsonb>(
                        "COALESCE(credential -> 'backup_eligible', 'null'::jsonb)",
                    )
                    .eq(serde_json::json!(credential.expected_backup_eligible)),
                )
                .filter(
                    diesel::dsl::sql::<diesel::sql_types::Jsonb>(
                        "COALESCE(credential -> 'backup_state', 'null'::jsonb)",
                    )
                    .eq(serde_json::json!(credential.expected_backup_state)),
                ),
        )
        .set((
            // Legacy copies are removed atomically with the authoritative CAS.
            user_passkey_credentials::credential.eq(diesel::dsl::sql::<diesel::sql_types::Jsonb>(
                "credential - 'id' - 'counter' || ",
            )
            .bind::<diesel::sql_types::Jsonb, _>(facts)),
            user_passkey_credentials::sign_count.eq(i64::from(credential.new_counter)),
            user_passkey_credentials::last_used_at.eq(now),
            user_passkey_credentials::updated_at.eq(now),
        ))
        .execute(&mut connection)
        .await
        .map_err(map_error)
        .and_then(|count| {
            if count == 1 {
                Ok(())
            } else {
                Err(RepositoryError::Conflict)
            }
        })
    }
    pub async fn delete(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let mut guard = crate::pool::DiscardOnDrop::new(connection);
        let result = guard
            .connection()
            .transaction::<_, Error, _>(async |connection| {
                let count = diesel::delete(
                    user_passkey_credentials::table
                        .find(id)
                        .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                if count == 1 {
                    super::audit_ledger::append_fresh_security_audit_on_connection(connection,
                    &nazo_persistence::SecurityAuditEvent {
                        event_id: Uuid::now_v7(), event_type: "passkey_deleted".into(),
                        event_category: "authentication".into(), occurred_at: jiff::Timestamp::now(),
                        payload: serde_json::json!({
                            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                            "event_category": "authentication", "tenant_id": tenant_id.as_uuid(),
                            "user_id": user_id.as_uuid(), "credential_id": id,
                        }),
                    }).await?;
                }
                Ok(count == 1)
            })
            .await;
        guard.return_to_pool();
        result.map_err(map_error)
    }
}

impl nazo_identity::ports::PasskeyRepositoryPort for PasskeyRepository {
    fn credential_ids(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<nazo_passkey::CredentialId>> {
        Box::pin(async move {
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            user_passkey_credentials::table
                .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
                .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid()))
                .order(user_passkey_credentials::created_at.asc())
                .select(user_passkey_credentials::credential_id)
                .load::<String>(&mut connection)
                .await
                .map_err(map_error)?
                .into_iter()
                .map(|id| {
                    nazo_passkey::CredentialId::from_b64url(&id)
                        .map_err(|error| RepositoryError::Consistency(error.to_string()))
                })
                .collect()
        })
    }

    fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<PasskeyCredential>> {
        Box::pin(async move { PasskeyRepository::list(self, tenant_id, user_id).await })
    }

    fn list_summaries(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<PasskeyCredentialSummary>> {
        Box::pin(async move { PasskeyRepository::list_summaries(self, tenant_id, user_id).await })
    }

    fn by_credential_id<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::ports::ObservedPasskey>>
    {
        Box::pin(async move {
            Ok(
                PasskeyRepository::by_credential_id(self, tenant_id, user_id, credential_id)
                    .await?
                    .map(|row| nazo_identity::ports::ObservedPasskey {
                        row,
                        revision: None,
                    }),
            )
        })
    }

    fn insert(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential: WebauthnCredential,
        label: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, PasskeyCredential> {
        Box::pin(async move {
            PasskeyRepository::insert(self, tenant_id, user_id, credential, label).await
        })
    }

    fn update_authentication<'a>(
        &'a self,
        observed: &'a nazo_identity::ports::ObservedPasskey,
        update: PasskeyAuthenticationUpdate,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            PasskeyRepository::update_authentication(
                self,
                observed.row.tenant_id,
                observed.row.user_id,
                &observed.row.credential.id.to_b64url(),
                update,
            )
            .await
        })
    }

    fn delete(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        id: Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, bool> {
        Box::pin(async move { PasskeyRepository::delete(self, tenant_id, user_id, id).await })
    }
}
fn map_error(error: Error) -> RepositoryError {
    match error {
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
