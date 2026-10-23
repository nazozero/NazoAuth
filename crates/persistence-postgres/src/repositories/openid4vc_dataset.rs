use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_openid4vci::CredentialStoreError;
use rand::Rng;
use uuid::Uuid;

use crate::pool::DiscardOnDrop;
use crate::{DbPool, get_conn};
#[derive(Clone)]
pub struct Openid4vciDatasetRepository {
    pool: DbPool,
    data_key: [u8; 32],
}

pub use nazo_persistence::ManagedCredentialDataset;

pub struct ManagedCredentialDatasetWrite<'a> {
    pub tenant_id: Uuid,
    pub actor_user_id: Uuid,
    pub subject_id: Uuid,
    pub credential_configuration_id: &'a str,
    pub claims: &'a serde_json::Value,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
}

struct DatasetWrite<'a> {
    tenant_id: Uuid,
    subject_id: Uuid,
    credential_configuration_id: &'a str,
    claims_ciphertext: Vec<u8>,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    source: &'static str,
    actor_user_id: Option<Uuid>,
    replace_existing: bool,
}

/// Upserts an issuer-authoritative dataset for ordinary operator management
/// on a caller-owned transaction connection.  The caller supplies ciphertext
/// produced by [`protect_dataset_claims`]; this function binds the durable
/// source and append-only audit event without inventing an admin actor.
pub async fn upsert_operator_managed_dataset_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    subject_id: Uuid,
    credential_configuration_id: &str,
    claims_ciphertext: Vec<u8>,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
) -> Result<usize, diesel::result::Error> {
    write_dataset_on_connection(
        connection,
        DatasetWrite {
            tenant_id,
            subject_id,
            credential_configuration_id,
            claims_ciphertext,
            valid_from,
            valid_until,
            source: "operator-managed",
            actor_user_id: None,
            replace_existing: true,
        },
    )
    .await
}

/// Deletes an operator-managed dataset and records a non-user actor audit
/// event on the same caller-owned transaction connection.  Returning `false`
/// is an idempotent no-op when the tenant/subject/configuration tuple is not
/// present.
pub async fn delete_operator_managed_dataset_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    subject_id: Uuid,
    credential_configuration_id: &str,
) -> Result<bool, diesel::result::Error> {
    let affected = sql_query(
        "WITH deleted AS (
            DELETE FROM openid4vci_credential_datasets
            WHERE tenant_id = $1 AND subject_id = $2
              AND credential_configuration_id = $3
              AND source = 'operator-managed'
            RETURNING tenant_id, subject_id, credential_configuration_id
         )
         INSERT INTO openid4vci_credential_dataset_events
            (tenant_id, subject_id, credential_configuration_id, action,
             actor_user_id, source)
         SELECT tenant_id, subject_id, credential_configuration_id, 2, NULL,
                'operator-managed'
         FROM deleted",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(subject_id)
    .bind::<sql_types::Text, _>(credential_configuration_id)
    .execute(connection)
    .await?;
    Ok(affected == 1)
}

async fn write_dataset_on_connection(
    connection: &mut AsyncPgConnection,
    write: DatasetWrite<'_>,
) -> Result<usize, diesel::result::Error> {
    // The two SQL forms intentionally differ only in conflict behavior: the
    // insert-only helper preserves caller-owned semantics, while operator
    // management has explicit upsert semantics.
    let statement = if write.replace_existing {
        "WITH upserted AS (
            INSERT INTO openid4vci_credential_datasets
                (tenant_id, subject_id, credential_configuration_id,
                 claims_ciphertext, source, valid_from, valid_until)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (tenant_id, subject_id, credential_configuration_id)
            DO UPDATE SET claims_ciphertext = EXCLUDED.claims_ciphertext,
                          valid_from = EXCLUDED.valid_from,
                          valid_until = EXCLUDED.valid_until,
                          updated_at = CURRENT_TIMESTAMP
            WHERE openid4vci_credential_datasets.source = EXCLUDED.source
            RETURNING tenant_id, subject_id, credential_configuration_id
         )
         INSERT INTO openid4vci_credential_dataset_events
            (tenant_id, subject_id, credential_configuration_id, action,
             actor_user_id, source)
         SELECT tenant_id, subject_id, credential_configuration_id, 1,
                $8, $5
         FROM upserted"
    } else {
        "WITH inserted AS (
            INSERT INTO openid4vci_credential_datasets
                (tenant_id, subject_id, credential_configuration_id,
                 claims_ciphertext, source, valid_from, valid_until)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING tenant_id, subject_id, credential_configuration_id
         )
         INSERT INTO openid4vci_credential_dataset_events
            (tenant_id, subject_id, credential_configuration_id, action,
             actor_user_id, source)
         SELECT tenant_id, subject_id, credential_configuration_id, 1,
                $8, $5
         FROM inserted"
    };
    sql_query(statement)
        .bind::<sql_types::Uuid, _>(write.tenant_id)
        .bind::<sql_types::Uuid, _>(write.subject_id)
        .bind::<sql_types::Text, _>(write.credential_configuration_id)
        .bind::<sql_types::Binary, _>(write.claims_ciphertext)
        .bind::<sql_types::Text, _>(write.source)
        .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(write.valid_from)
        .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(write.valid_until)
        .bind::<sql_types::Nullable<sql_types::Uuid>, _>(write.actor_user_id)
        .execute(connection)
        .await
}

impl Openid4vciDatasetRepository {
    #[must_use]
    pub fn new(pool: DbPool, data_key: [u8; 32]) -> Self {
        Self { pool, data_key }
    }

    pub async fn dataset(
        &self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &str,
    ) -> Result<Option<serde_json::Value>, CredentialStoreError> {
        #[derive(QueryableByName)]
        struct DatasetRow {
            #[diesel(sql_type = sql_types::Binary)]
            claims_ciphertext: Vec<u8>,
        }

        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let row = sql_query(
            "SELECT claims_ciphertext FROM openid4vci_credential_datasets \
             WHERE tenant_id = $1 AND subject_id = $2 \
               AND credential_configuration_id = $3 \
               AND (valid_from IS NULL OR valid_from <= CURRENT_TIMESTAMP) \
               AND (valid_until IS NULL OR valid_until > CURRENT_TIMESTAMP)",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(subject_id)
        .bind::<sql_types::Text, _>(credential_configuration_id)
        .get_result::<DatasetRow>(&mut connection)
        .await
        .optional()
        .map_err(|_| CredentialStoreError::Unavailable)?;
        drop(connection);
        row.map(|row| {
            unprotect_dataset_claims(
                &self.data_key,
                tenant_id,
                subject_id,
                credential_configuration_id,
                row.claims_ciphertext,
            )
        })
        .transpose()
    }

    pub async fn managed_dataset(
        &self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &str,
    ) -> Result<Option<ManagedCredentialDataset>, CredentialStoreError> {
        #[derive(QueryableByName)]
        struct DatasetRow {
            #[diesel(sql_type = sql_types::Binary)]
            claims_ciphertext: Vec<u8>,
            #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
            valid_from: Option<DateTime<Utc>>,
            #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
            valid_until: Option<DateTime<Utc>>,
            #[diesel(sql_type = sql_types::Timestamptz)]
            updated_at: DateTime<Utc>,
        }
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let row = sql_query(
            "SELECT claims_ciphertext, valid_from, valid_until, updated_at
             FROM openid4vci_credential_datasets
             WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = $3",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(subject_id)
        .bind::<sql_types::Text, _>(credential_configuration_id)
        .get_result::<DatasetRow>(&mut connection)
        .await
        .optional()
        .map_err(|_| CredentialStoreError::Unavailable)?;
        drop(connection);
        row.map(|row| {
            Ok(ManagedCredentialDataset {
                claims: unprotect_dataset_claims(
                    &self.data_key,
                    tenant_id,
                    subject_id,
                    credential_configuration_id,
                    row.claims_ciphertext,
                )?,
                valid_from: row.valid_from,
                valid_until: row.valid_until,
                updated_at: row.updated_at,
            })
        })
        .transpose()
    }

    pub async fn upsert_managed_dataset(
        &self,
        write: ManagedCredentialDatasetWrite<'_>,
    ) -> Result<bool, CredentialStoreError> {
        self.upsert_managed_dataset_committed(write)
            .await
            .map(|committed| committed.is_some())
    }

    async fn upsert_managed_dataset_committed(
        &self,
        write: ManagedCredentialDatasetWrite<'_>,
    ) -> Result<Option<ManagedCredentialDataset>, CredentialStoreError> {
        let ManagedCredentialDatasetWrite {
            tenant_id,
            actor_user_id,
            subject_id,
            credential_configuration_id,
            claims,
            valid_from,
            valid_until,
        } = write;
        let claims_ciphertext = protect_dataset_claims(
            &self.data_key,
            tenant_id,
            subject_id,
            credential_configuration_id,
            claims,
        )?;
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let mut guard = DiscardOnDrop(Some(connection));
        let result = guard
            .connection()
            .transaction::<Option<ManagedCredentialDataset>, diesel::result::Error, _>(
                async move |connection| {
                    let mut rows = sql_query(
                        "WITH authorized_actor AS MATERIALIZED (
                         SELECT id FROM users
                         WHERE tenant_id = $1 AND id = $2 AND is_active = TRUE
                           AND role = 'admin' AND admin_level > 0
                         FOR SHARE
                     ), active_subject AS MATERIALIZED (
                         SELECT id FROM users
                         WHERE tenant_id = $1 AND id = $3 AND is_active = TRUE
                         FOR SHARE
                     ), existing_target AS MATERIALIZED (
                         SELECT source FROM openid4vci_credential_datasets
                         WHERE tenant_id = $1 AND subject_id = $3
                           AND credential_configuration_id = $4
                         FOR UPDATE
                     ), permitted AS MATERIALIZED (
                         SELECT a.id AS actor_user_id, u.id AS subject_id
                         FROM authorized_actor a CROSS JOIN active_subject u
                         WHERE NOT EXISTS (
                             SELECT 1 FROM existing_target WHERE source <> 'admin-session'
                         )
                     ), upserted AS (
                         INSERT INTO openid4vci_credential_datasets
                             (tenant_id, subject_id, credential_configuration_id, claims_ciphertext,
                              source, valid_from, valid_until)
                         SELECT $1, subject_id, $4, $5, 'admin-session', $6, $7
                         FROM permitted WHERE TRUE
                         ON CONFLICT (tenant_id, subject_id, credential_configuration_id)
                         DO UPDATE SET claims_ciphertext = EXCLUDED.claims_ciphertext,
                             valid_from = EXCLUDED.valid_from, valid_until = EXCLUDED.valid_until,
                             updated_at = CURRENT_TIMESTAMP
                         WHERE openid4vci_credential_datasets.source = 'admin-session'
                         RETURNING tenant_id, subject_id, credential_configuration_id, source,
                             claims_ciphertext, valid_from, valid_until, updated_at
                     ), recorded AS (
                         INSERT INTO openid4vci_credential_dataset_events
                             (tenant_id, subject_id, credential_configuration_id, action,
                              actor_user_id, source)
                         SELECT tenant_id, subject_id, credential_configuration_id, 1, $2, source
                         FROM upserted
                         RETURNING 1
                     )
                     SELECT (SELECT COUNT(*) FROM permitted) AS expected_effects,
                            (SELECT COUNT(*) FROM upserted) AS effect_count,
                            (SELECT COUNT(*) FROM recorded) AS source_event_count,
                            d.claims_ciphertext, d.valid_from, d.valid_until, d.updated_at
                     FROM (SELECT 1) singleton
                     LEFT JOIN upserted d ON TRUE",
                    )
                    .bind::<sql_types::Uuid, _>(tenant_id)
                    .bind::<sql_types::Uuid, _>(actor_user_id)
                    .bind::<sql_types::Uuid, _>(subject_id)
                    .bind::<sql_types::Text, _>(credential_configuration_id)
                    .bind::<sql_types::Binary, _>(claims_ciphertext)
                    .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(valid_from)
                    .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(valid_until)
                    .load::<ManagedDatasetMutationRow>(connection)
                    .await?;
                    let row = rows.pop().expect("singleton mutation result");
                    if !row.effects.applied()? {
                        return Ok(None);
                    }
                    let ciphertext = row
                        .claims_ciphertext
                        .ok_or(diesel::result::Error::RollbackTransaction)?;
                    let view = ManagedCredentialDataset {
                        claims: unprotect_dataset_claims(
                            &self.data_key,
                            tenant_id,
                            subject_id,
                            credential_configuration_id,
                            ciphertext,
                        )
                        .map_err(|_| diesel::result::Error::RollbackTransaction)?,
                        valid_from: row.valid_from,
                        valid_until: row.valid_until,
                        updated_at: row
                            .updated_at
                            .ok_or(diesel::result::Error::RollbackTransaction)?,
                    };
                    append_managed_dataset_outcome(
                        connection,
                        tenant_id,
                        actor_user_id,
                        subject_id,
                        credential_configuration_id,
                        "openid4vci_credential_dataset_updated",
                    )
                    .await?;
                    Ok(Some(view))
                },
            )
            .await
            .map_err(|_| CredentialStoreError::Unavailable);
        guard.return_to_pool();
        result
    }

    pub async fn delete_managed_dataset(
        &self,
        tenant_id: Uuid,
        actor_user_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &str,
    ) -> Result<bool, CredentialStoreError> {
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let mut guard = DiscardOnDrop(Some(connection));
        let result = guard.connection()
            .transaction::<bool, diesel::result::Error, _>(async move |connection| {
                let mut rows = sql_query(
                    "WITH authorized_actor AS MATERIALIZED (
                         SELECT id FROM users
                         WHERE tenant_id = $1 AND id = $2 AND is_active = TRUE
                           AND role = 'admin' AND admin_level > 0
                         FOR SHARE
                     ), target AS MATERIALIZED (
                         SELECT d.tenant_id, d.subject_id, d.credential_configuration_id FROM openid4vci_credential_datasets d
                         CROSS JOIN authorized_actor a
                         WHERE d.tenant_id = $1 AND d.subject_id = $3
                           AND d.credential_configuration_id = $4 AND d.source = 'admin-session'
                         FOR UPDATE OF d
                     ), deleted AS (
                         DELETE FROM openid4vci_credential_datasets d USING target t
                         WHERE d.tenant_id = t.tenant_id AND d.subject_id = t.subject_id
                           AND d.credential_configuration_id = t.credential_configuration_id
                         RETURNING d.tenant_id, d.subject_id, d.credential_configuration_id, d.source
                     ), recorded AS (
                         INSERT INTO openid4vci_credential_dataset_events
                             (tenant_id, subject_id, credential_configuration_id, action,
                              actor_user_id, source)
                         SELECT tenant_id, subject_id, credential_configuration_id, 2, $2, source
                         FROM deleted
                         RETURNING 1
                     )
                     SELECT (SELECT COUNT(*) FROM target) AS expected_effects,
                            (SELECT COUNT(*) FROM deleted) AS effect_count,
                            (SELECT COUNT(*) FROM recorded) AS source_event_count",
                )
                .bind::<sql_types::Uuid, _>(tenant_id)
                .bind::<sql_types::Uuid, _>(actor_user_id)
                .bind::<sql_types::Uuid, _>(subject_id)
                .bind::<sql_types::Text, _>(credential_configuration_id)
                .load::<ManagedDatasetEffects>(connection).await?;
                let effects = rows.pop().expect("singleton mutation result");
                if !effects.applied()? { return Ok(false); }
                append_managed_dataset_outcome(connection, tenant_id, actor_user_id,
                    subject_id, credential_configuration_id,
                    "openid4vci_credential_dataset_deleted").await?;
                Ok(true)
            }).await.map_err(|_| CredentialStoreError::Unavailable);
        guard.return_to_pool();
        result
    }
}

#[derive(QueryableByName)]
struct ManagedDatasetEffects {
    #[diesel(sql_type = sql_types::BigInt)]
    expected_effects: i64,
    #[diesel(sql_type = sql_types::BigInt)]
    effect_count: i64,
    #[diesel(sql_type = sql_types::BigInt)]
    source_event_count: i64,
}

impl ManagedDatasetEffects {
    // SQL binds effect/event identities. Counts distinguish an ineligible target
    // from a suppressed write or source event, which must roll back.
    fn applied(&self) -> Result<bool, diesel::result::Error> {
        match (
            self.expected_effects,
            self.effect_count,
            self.source_event_count,
        ) {
            (0, 0, 0) => Ok(false),
            (1, 1, 1) => Ok(true),
            _ => Err(diesel::result::Error::RollbackTransaction),
        }
    }
}

#[derive(QueryableByName)]
struct ManagedDatasetMutationRow {
    #[diesel(embed)]
    effects: ManagedDatasetEffects,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    claims_ciphertext: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    valid_from: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    valid_until: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    updated_at: Option<DateTime<Utc>>,
}

async fn append_managed_dataset_outcome(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    actor_user_id: Uuid,
    subject_id: Uuid,
    credential_configuration_id: &str,
    event_type: &str,
) -> Result<(), diesel::result::Error> {
    crate::repositories::audit_ledger::append_fresh_security_audit_on_connection(
        connection,
        &nazo_persistence::SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: event_type.to_owned(),
            event_category: "credential_lifecycle".to_owned(),
            payload: serde_json::json!({
                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category": "credential_lifecycle", "tenant_id": tenant_id,
                "admin_user_id": actor_user_id, "subject_id": subject_id,
                "credential_configuration_id": credential_configuration_id,
                "outcome": "success",
            }),
            occurred_at: Utc::now(),
        },
    )
    .await
}

impl nazo_persistence::Openid4vciDatasetStore for Openid4vciDatasetRepository {
    fn datasets_available<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_ids: &'a [String],
    ) -> futures_util::future::BoxFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            #[derive(QueryableByName)]
            struct Availability {
                #[diesel(sql_type = sql_types::Bool)]
                available: bool,
            }
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "SELECT NOT EXISTS (
                    SELECT 1 FROM unnest($3::text[]) AS requested(configuration_id)
                    WHERE NOT EXISTS (
                        SELECT 1 FROM openid4vci_credential_datasets AS dataset
                        WHERE dataset.tenant_id = $1 AND dataset.subject_id = $2
                          AND dataset.credential_configuration_id = requested.configuration_id
                          AND (dataset.valid_from IS NULL OR dataset.valid_from <= CURRENT_TIMESTAMP)
                          AND (dataset.valid_until IS NULL OR dataset.valid_until > CURRENT_TIMESTAMP)
                    )
                 ) AS available",
            )
            .bind::<sql_types::Uuid, _>(tenant_id)
            .bind::<sql_types::Uuid, _>(subject_id)
            .bind::<sql_types::Array<sql_types::Text>, _>(credential_configuration_ids)
            .get_result::<Availability>(&mut connection)
            .await
            .map(|row| row.available)
            .map_err(|_| CredentialStoreError::Unavailable)
        })
    }

    fn dataset<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<serde_json::Value>, CredentialStoreError>>
    {
        Box::pin(async move {
            Openid4vciDatasetRepository::dataset(
                self,
                tenant_id,
                subject_id,
                credential_configuration_id,
            )
            .await
        })
    }

    fn managed_dataset<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<nazo_persistence::ManagedCredentialDataset>, CredentialStoreError>,
    > {
        Box::pin(async move {
            Openid4vciDatasetRepository::managed_dataset(
                self,
                tenant_id,
                subject_id,
                credential_configuration_id,
            )
            .await
        })
    }

    fn upsert_managed_dataset(
        &self,
        write: nazo_persistence::ManagedCredentialDatasetWrite,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Option<nazo_persistence::ManagedCredentialDataset>, CredentialStoreError>,
    > {
        Box::pin(async move {
            Openid4vciDatasetRepository::upsert_managed_dataset_committed(
                self,
                ManagedCredentialDatasetWrite {
                    tenant_id: write.tenant_id,
                    actor_user_id: write.actor_user_id,
                    subject_id: write.subject_id,
                    credential_configuration_id: &write.credential_configuration_id,
                    claims: &write.claims,
                    valid_from: write.valid_from,
                    valid_until: write.valid_until,
                },
            )
            .await
        })
    }

    fn delete_managed_dataset<'a>(
        &'a self,
        tenant_id: Uuid,
        actor_user_id: Uuid,
        subject_id: Uuid,
        credential_configuration_id: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            Openid4vciDatasetRepository::delete_managed_dataset(
                self,
                tenant_id,
                actor_user_id,
                subject_id,
                credential_configuration_id,
            )
            .await
        })
    }
}

fn dataset_aad(tenant_id: Uuid, subject_id: Uuid, credential_configuration_id: &str) -> Vec<u8> {
    let configuration = credential_configuration_id.as_bytes();
    let mut aad = Vec::with_capacity(16 + 16 + 8 + configuration.len());
    aad.extend_from_slice(tenant_id.as_bytes());
    aad.extend_from_slice(subject_id.as_bytes());
    aad.extend_from_slice(&(configuration.len() as u64).to_be_bytes());
    aad.extend_from_slice(configuration);
    aad
}

/// Encrypts issuer-authoritative claims with the same AAD and data key used by
/// the managed-dataset repository. Caller-owned transactions use this helper
/// before inserting so encryption cannot split the transaction.
pub fn protect_dataset_claims(
    key: &[u8; 32],
    tenant_id: Uuid,
    subject_id: Uuid,
    credential_configuration_id: &str,
    claims: &serde_json::Value,
) -> Result<Vec<u8>, CredentialStoreError> {
    let plaintext =
        serde_json::to_vec(claims).map_err(|_| CredentialStoreError::InvalidTransition)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    nazo_crypto::aead::encrypt_prefixed(
        key,
        &nonce,
        &dataset_aad(tenant_id, subject_id, credential_configuration_id),
        &plaintext,
        &nonce,
    )
    .map_err(|_| CredentialStoreError::Unavailable)
}

/// Decrypts a dataset read through a caller-owned connection.  Keeping this
/// primitive next to the normal dataset repository prevents onboarding replay
/// from creating a second encryption format.
/// Consumes the database buffer and parses its plaintext in place.
pub fn unprotect_dataset_claims(
    key: &[u8; 32],
    tenant_id: Uuid,
    subject_id: Uuid,
    credential_configuration_id: &str,
    mut protected: Vec<u8>,
) -> Result<serde_json::Value, CredentialStoreError> {
    let plaintext = nazo_crypto::aead::decrypt_nonce_prefixed(
        key,
        &dataset_aad(tenant_id, subject_id, credential_configuration_id),
        &mut protected,
    )
    .map_err(|_| CredentialStoreError::InvalidTransition)?;
    serde_json::from_slice(plaintext).map_err(|_| CredentialStoreError::InvalidTransition)
}
