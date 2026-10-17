use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::{ClientTrustPolicy, Openid4vcTrustPolicyRecord, Openid4vcTrustPolicyStore};
use serde_json::Value;
use uuid::Uuid;

use crate::{DbPool, get_conn};

/// Authoritative tenant-scoped resource revision and manifest digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantResourceState {
    pub tenant_id: Uuid,
    pub revision: u64,
    pub resource_manifest_sha256: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantResourceBinding {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_kind: String,
    pub resource_id: String,
    pub resource_digest: String,
    pub active: bool,
    pub locator: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Public OpenID4VC trust policy installed through the ordinary tenant
/// resource control plane. Private key material is rejected before storage
/// and by the database constraint.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredOpenid4vcTrustPolicy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_id: String,
    pub resource_digest: String,
    pub public_material: Value,
    pub wallet_origins: Vec<String>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Openid4vcTrustPolicyWrite {
    Applied(StoredOpenid4vcTrustPolicy),
    Replayed(StoredOpenid4vcTrustPolicy),
    Conflict(StoredOpenid4vcTrustPolicy),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Openid4vcTrustPolicyRevoke {
    Revoked(StoredOpenid4vcTrustPolicy),
    AlreadyAbsent,
    Conflict(StoredOpenid4vcTrustPolicy),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Openid4vcTrustPolicyForClient {
    Unbound,
    BoundInactive,
    Active(StoredOpenid4vcTrustPolicy),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Openid4vcTrustPolicyClientBind {
    Bound { binding_id: Uuid },
    Replayed { binding_id: Uuid },
    Conflict { binding_id: Uuid },
}

#[derive(Clone)]
pub struct TenantResourceRepository {
    pool: DbPool,
}

#[derive(QueryableByName)]
struct StateRow {
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::BigInt)]
    revision: i64,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_manifest_sha256: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    updated_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct BindingRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_kind: String,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_id: String,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_digest: String,
    #[diesel(sql_type = sql_types::Bool)]
    active: bool,
    #[diesel(sql_type = sql_types::Text)]
    locator: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    updated_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct OAuthClientStateRow {
    #[diesel(sql_type = sql_types::Bool)]
    is_active: bool,
}

#[derive(QueryableByName)]
struct Openid4vcTrustPolicyClientBindingRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    policy_id: Uuid,
}

#[derive(QueryableByName)]
struct Openid4vcTrustPolicyRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_id: String,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_digest: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    public_material: Value,
    #[diesel(sql_type = sql_types::Jsonb)]
    wallet_origins: Value,
    #[diesel(sql_type = sql_types::Bool)]
    active: bool,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    updated_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct Openid4vcTrustPolicyReadRow {
    #[diesel(sql_type = sql_types::Bool)]
    client_active: bool,
    #[diesel(sql_type = sql_types::Bool)]
    has_binding: bool,
    #[diesel(embed)]
    policy: Option<Openid4vcTrustPolicyRow>,
}

fn validate_openid4vc_trust_client_id(public_client_id: &str) -> Result<(), RepositoryError> {
    if public_client_id.is_empty()
        || public_client_id.len() > 255
        || public_client_id != public_client_id.trim()
    {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy client ID is invalid".to_owned(),
        ));
    }
    Ok(())
}

impl TryFrom<StateRow> for TenantResourceState {
    type Error = RepositoryError;

    fn try_from(row: StateRow) -> Result<Self, Self::Error> {
        Ok(Self {
            tenant_id: row.tenant_id,
            revision: decode_revision(row.revision)?,
            resource_manifest_sha256: row.resource_manifest_sha256,
            updated_at: row.updated_at,
        })
    }
}

impl From<BindingRow> for TenantResourceBinding {
    fn from(row: BindingRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            resource_kind: row.resource_kind,
            resource_id: row.resource_id,
            resource_digest: row.resource_digest,
            active: row.active,
            locator: row.locator,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

impl TryFrom<Openid4vcTrustPolicyRow> for StoredOpenid4vcTrustPolicy {
    type Error = RepositoryError;

    fn try_from(row: Openid4vcTrustPolicyRow) -> Result<Self, Self::Error> {
        // The table owns source, identity, size and active-state constraints.
        let wallet_origins = serde_json::from_value(row.wallet_origins).map_err(|_| {
            RepositoryError::Consistency("stored wallet origins are not a string array".to_owned())
        })?;
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            resource_id: row.resource_id,
            resource_digest: row.resource_digest,
            public_material: row.public_material,
            wallet_origins,
            active: row.active,
            created_at: row.created_at,
            updated_at: row.updated_at,
            revoked_at: row.revoked_at,
        })
    }
}

impl TenantResourceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Acquire one connection for a caller-owned transaction.  All *_on_connection
    /// methods below deliberately accept the same connection so a resource
    /// mutation, revision CAS, binding change, audit append, and receipt insert
    /// can commit or roll back together.
    pub async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }

    pub async fn state(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantResourceState>, RepositoryError> {
        let mut connection = self.connection().await?;
        Self::state_on_connection(&mut connection, tenant_id).await
    }

    pub async fn state_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
    ) -> Result<Option<TenantResourceState>, RepositoryError> {
        sql_query(
            "SELECT tenant_id, revision, resource_manifest_sha256, updated_at
             FROM tenant_resource_states
             WHERE tenant_id = $1",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .get_result::<StateRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(TenantResourceState::try_from)
        .transpose()
    }

    pub async fn compare_and_set_state_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        expected_revision: u64,
        resource_manifest_sha256: &str,
    ) -> Result<Option<u64>, RepositoryError> {
        let next_revision = expected_revision.checked_add(1).ok_or_else(|| {
            RepositoryError::Consistency(
                "tenant resource revision cannot advance past u64::MAX".to_owned(),
            )
        })?;
        let expected_revision = encode_revision(expected_revision)?;
        let next_revision = encode_revision(next_revision)?;
        #[derive(QueryableByName)]
        struct RevisionRow {
            #[diesel(sql_type = sql_types::BigInt)]
            revision: i64,
        }
        sql_query(
            "WITH updated AS (
                 UPDATE tenant_resource_states
                 SET revision = $3,
                     resource_manifest_sha256 = $4,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE tenant_id = $1 AND revision = $2
                 RETURNING revision
             ), inserted AS (
                 INSERT INTO tenant_resource_states
                     (tenant_id, revision, resource_manifest_sha256)
                 SELECT $1, $3, $4
                 WHERE $2 = 0 AND NOT EXISTS (SELECT 1 FROM updated)
                 ON CONFLICT (tenant_id) DO NOTHING
                 RETURNING revision
             )
             SELECT revision FROM updated
             UNION ALL
             SELECT revision FROM inserted",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::BigInt, _>(expected_revision)
        .bind::<sql_types::BigInt, _>(next_revision)
        .bind::<sql_types::Varchar, _>(resource_manifest_sha256)
        .get_result::<RevisionRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(|row| decode_revision(row.revision))
        .transpose()
    }

    /// Serialize one accepted operation's resource transition until the
    /// caller-owned transaction ends. The control-outcome ledger is the
    /// sole replay authority for that operation id.
    pub async fn lock_operation_identity_on_connection(
        connection: &mut AsyncPgConnection,
        deployment_id: &str,
        tenant_id: Uuid,
        jti: &str,
    ) -> Result<(), RepositoryError> {
        lock_operation_jti_on_connection(connection, deployment_id, tenant_id, jti).await
    }

    /// Lock one tenant resource identity for the duration of the caller's
    /// transaction. Callers that mutate more than one identity must acquire
    /// these locks in one deterministic `(kind, resource_id)` order before
    /// changing any resource rows.
    pub async fn lock_binding_identity_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_kind: &str,
        resource_id: &str,
    ) -> Result<(), RepositoryError> {
        lock_binding_identity_on_connection(connection, tenant_id, resource_kind, resource_id).await
    }

    /// Mutate under the identity lock already acquired by the transaction owner.
    pub async fn upsert_binding_on_connection(
        connection: &mut AsyncPgConnection,
        binding: NewTenantResourceBinding<'_>,
    ) -> Result<TenantResourceBinding, RepositoryError> {
        let id = Uuid::now_v7();
        let inserted = sql_query(
            "INSERT INTO tenant_resource_bindings
                (id, tenant_id, resource_kind, resource_id, resource_digest,
                 active, locator)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, resource_kind, resource_id)
             DO NOTHING
             RETURNING id, tenant_id, resource_kind, resource_id, resource_digest,
                       active, locator,
                       created_at, updated_at",
        )
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Uuid, _>(binding.tenant_id)
        .bind::<sql_types::Varchar, _>(binding.resource_kind)
        .bind::<sql_types::Varchar, _>(binding.resource_id)
        .bind::<sql_types::Varchar, _>(binding.resource_digest)
        .bind::<sql_types::Bool, _>(binding.active)
        .bind::<sql_types::Text, _>(binding.locator)
        .get_result::<BindingRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        if let Some(row) = inserted {
            return Ok(row.into());
        }
        let existing = sql_query(
            "SELECT id, tenant_id, resource_kind, resource_id, resource_digest,
                    active, locator,
                    created_at, updated_at
             FROM tenant_resource_bindings
             WHERE tenant_id = $1 AND resource_kind = $2
               AND resource_id = $3
             FOR UPDATE",
        )
        .bind::<sql_types::Uuid, _>(binding.tenant_id)
        .bind::<sql_types::Varchar, _>(binding.resource_kind)
        .bind::<sql_types::Varchar, _>(binding.resource_id)
        .get_result::<BindingRow>(connection)
        .await
        .map_err(map_error)?;
        let existing_binding: TenantResourceBinding = existing.into();
        if existing_binding.resource_digest == binding.resource_digest
            && existing_binding.active == binding.active
            && existing_binding.locator == binding.locator
        {
            return Ok(existing_binding);
        }
        if !existing_binding.active {
            return sql_query(
                "UPDATE tenant_resource_bindings
                 SET resource_digest = $2, active = $3, locator = $4,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = $1 AND NOT active
                 RETURNING id, tenant_id, resource_kind, resource_id, resource_digest,
                           active, locator, created_at, updated_at",
            )
            .bind::<sql_types::Uuid, _>(existing_binding.id)
            .bind::<sql_types::Varchar, _>(binding.resource_digest)
            .bind::<sql_types::Bool, _>(binding.active)
            .bind::<sql_types::Text, _>(binding.locator)
            .get_result::<BindingRow>(connection)
            .await
            .map(BindingRow::into)
            .map_err(map_error);
        }
        Err(RepositoryError::Conflict)
    }

    pub async fn active_bindings_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
    ) -> Result<Vec<TenantResourceBinding>, RepositoryError> {
        sql_query(
            "SELECT id, tenant_id, resource_kind, resource_id, resource_digest,
                    active, locator,
                    created_at, updated_at
             FROM tenant_resource_bindings
             WHERE tenant_id = $1 AND active
             ORDER BY resource_kind, resource_id, id",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .load::<BindingRow>(connection)
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(map_error)
    }

    /// Deactivate one active binding fenced by its digest. The transaction
    /// owner must already hold this binding's identity lock.
    pub async fn deactivate_binding_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_kind: &str,
        resource_id: &str,
        expected_digest: &str,
    ) -> Result<bool, RepositoryError> {
        sql_query(
            "UPDATE tenant_resource_bindings
             SET active = FALSE, updated_at = CURRENT_TIMESTAMP
             WHERE tenant_id = $1 AND resource_kind = $2
               AND resource_id = $3 AND resource_digest = $4 AND active",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(resource_kind)
        .bind::<sql_types::Varchar, _>(resource_id)
        .bind::<sql_types::Varchar, _>(expected_digest)
        .execute(connection)
        .await
        .map(|changed| changed == 1)
        .map_err(map_error)
    }

    pub async fn active_openid4vc_trust_policy_for_origin_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_id: &str,
        wallet_origin: &str,
        expected_digest: &str,
    ) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
        validate_stored_openid4vc_trust_policy_identity(resource_id, expected_digest)?;
        validate_wallet_origin(wallet_origin)?;
        sql_query(
            "SELECT id, tenant_id, resource_id, resource_digest, public_material,
                    wallet_origins, active, created_at, updated_at, revoked_at
             FROM openid4vc_trust_policies
             WHERE tenant_id = $1 AND resource_id = $2 AND resource_digest = $3
               AND active AND wallet_origins @> jsonb_build_array($4::TEXT)",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(resource_id)
        .bind::<sql_types::Varchar, _>(expected_digest)
        .bind::<sql_types::Text, _>(wallet_origin)
        .get_result::<Openid4vcTrustPolicyRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(StoredOpenid4vcTrustPolicy::try_from)
        .transpose()
    }

    pub async fn active_openid4vc_trust_policy_for_origin(
        &self,
        tenant_id: Uuid,
        resource_id: &str,
        wallet_origin: &str,
        expected_digest: &str,
    ) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
        let mut connection = self.connection().await?;
        Self::active_openid4vc_trust_policy_for_origin_on_connection(
            &mut connection,
            tenant_id,
            resource_id,
            wallet_origin,
            expected_digest,
        )
        .await
    }

    pub async fn openid4vc_trust_policy_for_client(
        &self,
        tenant_id: Uuid,
        public_client_id: &str,
    ) -> Result<Openid4vcTrustPolicyForClient, RepositoryError> {
        validate_openid4vc_trust_client_id(public_client_id)?;
        let mut connection = self.connection().await?;
        // Request-time trust resolution is a single committed snapshot. Row
        // locks belong to management writes;
        // a read lock here would end before proof verification even begins.
        let row = sql_query(
            "SELECT client.is_active AS client_active, \
                    EXISTS (SELECT 1 FROM openid4vc_trust_policy_clients AS any_binding \
                            WHERE any_binding.tenant_id = client.tenant_id \
                              AND any_binding.oauth_client_id = client.id) AS has_binding, \
                    policy.* \
             FROM oauth_clients AS client \
             LEFT JOIN LATERAL ( \
                 SELECT policy.id, policy.tenant_id, policy.resource_id, policy.resource_digest, \
                        policy.public_material, policy.wallet_origins, \
                        policy.active, policy.created_at, policy.updated_at, policy.revoked_at \
                 FROM openid4vc_trust_policy_clients AS binding \
                 JOIN openid4vc_trust_policies AS policy \
                   ON policy.tenant_id = binding.tenant_id AND policy.id = binding.policy_id \
                 WHERE binding.tenant_id = client.tenant_id AND binding.oauth_client_id = client.id \
                   AND binding.active AND policy.active \
             ) AS policy ON client.is_active \
             WHERE client.tenant_id = $1 AND client.client_id = $2",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(public_client_id)
        .get_result::<Openid4vcTrustPolicyReadRow>(&mut connection)
        .await
        .optional()
        .map_err(map_error)?;
        let Some(row) = row else {
            return Ok(Openid4vcTrustPolicyForClient::Unbound);
        };
        if !row.has_binding {
            return Ok(Openid4vcTrustPolicyForClient::Unbound);
        }
        if !row.client_active {
            return Ok(Openid4vcTrustPolicyForClient::BoundInactive);
        }
        match row.policy {
            Some(policy) => Ok(Openid4vcTrustPolicyForClient::Active(policy.try_into()?)),
            None => Ok(Openid4vcTrustPolicyForClient::BoundInactive),
        }
    }

    /// Install one validated public trust policy. The protocol/provider layer
    /// owns validation and binds the digest to the exact material. The transaction
    /// owner holds the policy identity lock; persistence owns the active digest fence.
    pub async fn apply_openid4vc_trust_policy_on_connection(
        connection: &mut AsyncPgConnection,
        policy: NewStoredOpenid4vcTrustPolicy<'_>,
    ) -> Result<Openid4vcTrustPolicyWrite, RepositoryError> {
        let wallet_origins_json = serde_json::to_value(policy.wallet_origins).map_err(|_| {
            RepositoryError::Consistency(
                "OpenID4VC trust policy wallet origins are not JSON".to_owned(),
            )
        })?;

        if let Some(current) = select_openid4vc_trust_policy_on_connection(
            connection,
            policy.tenant_id,
            policy.resource_id,
        )
        .await?
        {
            return if current.resource_digest == policy.resource_digest {
                Ok(Openid4vcTrustPolicyWrite::Replayed(current))
            } else {
                Ok(Openid4vcTrustPolicyWrite::Conflict(current))
            };
        }

        let inserted = sql_query(
            "INSERT INTO openid4vc_trust_policies
                (id, tenant_id, resource_id, resource_digest, public_material,
                 wallet_origins, source, active)
             VALUES ($1, $2, $3, $4, $5, $6, 'operator-managed', TRUE)
             RETURNING id, tenant_id, resource_id, resource_digest, public_material,
                       wallet_origins,
                       active, created_at, updated_at, revoked_at",
        )
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<sql_types::Uuid, _>(policy.tenant_id)
        .bind::<sql_types::Varchar, _>(policy.resource_id)
        .bind::<sql_types::Varchar, _>(policy.resource_digest)
        .bind::<sql_types::Jsonb, _>(policy.public_material)
        .bind::<sql_types::Jsonb, _>(&wallet_origins_json)
        .get_result::<Openid4vcTrustPolicyRow>(connection)
        .await
        .map_err(map_error)?
        .try_into()?;
        Ok(Openid4vcTrustPolicyWrite::Applied(inserted))
    }

    /// The transaction owner holds the policy identity lock. The client row lock
    /// below serializes binding changes with client deactivation.
    pub async fn bind_openid4vc_trust_policy_client_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        policy_resource_id: &str,
        expected_policy_digest: &str,
        oauth_client_id: Uuid,
    ) -> Result<Openid4vcTrustPolicyClientBind, RepositoryError> {
        sql_query(
            "SELECT is_active
             FROM oauth_clients
             WHERE tenant_id = $1 AND id = $2
             FOR UPDATE",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(oauth_client_id)
        .get_result::<OAuthClientStateRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .filter(|client| client.is_active)
        .ok_or(RepositoryError::NotFound)?;
        #[derive(QueryableByName)]
        struct PolicyIdentity {
            #[diesel(sql_type = sql_types::Uuid)]
            id: Uuid,
        }
        let policy = sql_query(
            "SELECT id FROM openid4vc_trust_policies
             WHERE tenant_id = $1 AND resource_id = $2 AND resource_digest = $3 AND active",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(policy_resource_id)
        .bind::<sql_types::Varchar, _>(expected_policy_digest)
        .get_result::<PolicyIdentity>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .ok_or(RepositoryError::Conflict)?;

        let active_binding = select_openid4vc_trust_policy_client_binding_on_connection(
            connection,
            tenant_id,
            oauth_client_id,
        )
        .await?;
        if let Some(active_binding) = active_binding {
            return if active_binding.policy_id == policy.id {
                Ok(Openid4vcTrustPolicyClientBind::Replayed {
                    binding_id: active_binding.id,
                })
            } else {
                Ok(Openid4vcTrustPolicyClientBind::Conflict {
                    binding_id: active_binding.id,
                })
            };
        }

        let binding_id = Uuid::now_v7();
        sql_query(
            "INSERT INTO openid4vc_trust_policy_clients
                (id, policy_id, tenant_id, oauth_client_id, active)
             VALUES ($1, $2, $3, $4, TRUE)",
        )
        .bind::<sql_types::Uuid, _>(binding_id)
        .bind::<sql_types::Uuid, _>(policy.id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(oauth_client_id)
        .execute(connection)
        .await
        .map_err(map_error)?;
        Ok(Openid4vcTrustPolicyClientBind::Bound { binding_id })
    }

    /// Revoke under the policy identity lock held by the transaction owner.
    pub async fn revoke_openid4vc_trust_policy_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_id: &str,
        expected_digest: &str,
    ) -> Result<Openid4vcTrustPolicyRevoke, RepositoryError> {
        let Some(current) =
            select_openid4vc_trust_policy_on_connection(connection, tenant_id, resource_id).await?
        else {
            return Ok(Openid4vcTrustPolicyRevoke::AlreadyAbsent);
        };
        if current.resource_digest != expected_digest {
            return Ok(Openid4vcTrustPolicyRevoke::Conflict(current));
        }
        sql_query(
            "UPDATE openid4vc_trust_policy_clients
             SET active = FALSE, updated_at = CURRENT_TIMESTAMP
             WHERE tenant_id = $1 AND policy_id = $2 AND active",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(current.id)
        .execute(connection)
        .await
        .map_err(map_error)?;
        let revoked = sql_query(
            "UPDATE openid4vc_trust_policies
             SET active = FALSE, revoked_at = CURRENT_TIMESTAMP,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $1 AND active AND resource_digest = $2
             RETURNING id, tenant_id, resource_id, resource_digest, public_material,
                       wallet_origins,
                       active, created_at, updated_at, revoked_at",
        )
        .bind::<sql_types::Uuid, _>(current.id)
        .bind::<sql_types::Varchar, _>(expected_digest)
        .get_result::<Openid4vcTrustPolicyRow>(connection)
        .await
        .map_err(map_error)?
        .try_into()?;
        Ok(Openid4vcTrustPolicyRevoke::Revoked(revoked))
    }
}

async fn select_openid4vc_trust_policy_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resource_id: &str,
) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
    sql_query(
        "SELECT id, tenant_id, resource_id, resource_digest, public_material,
                wallet_origins,
                active, created_at, updated_at, revoked_at
         FROM openid4vc_trust_policies
         WHERE tenant_id = $1 AND resource_id = $2 AND active
         FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(resource_id)
    .get_result::<Openid4vcTrustPolicyRow>(connection)
    .await
    .optional()
    .map_err(map_error)?
    .map(StoredOpenid4vcTrustPolicy::try_from)
    .transpose()
}

async fn select_openid4vc_trust_policy_client_binding_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    oauth_client_id: Uuid,
) -> Result<Option<Openid4vcTrustPolicyClientBindingRow>, RepositoryError> {
    sql_query(
        "SELECT id, policy_id
         FROM openid4vc_trust_policy_clients
         WHERE tenant_id = $1 AND oauth_client_id = $2 AND active
         FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(oauth_client_id)
    .get_result::<Openid4vcTrustPolicyClientBindingRow>(connection)
    .await
    .optional()
    .map_err(map_error)
}

impl Openid4vcTrustPolicyStore for TenantResourceRepository {
    fn for_client<'a>(
        &'a self,
        tenant_id: Uuid,
        public_client_id: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<ClientTrustPolicy, RepositoryError>> {
        Box::pin(async move {
            match self
                .openid4vc_trust_policy_for_client(tenant_id, public_client_id)
                .await?
            {
                Openid4vcTrustPolicyForClient::Unbound => Ok(ClientTrustPolicy::Unbound),
                Openid4vcTrustPolicyForClient::BoundInactive => {
                    Ok(ClientTrustPolicy::BoundInactive)
                }
                Openid4vcTrustPolicyForClient::Active(policy) => {
                    let material =
                        serde_json::from_value(policy.public_material).map_err(|_| {
                            RepositoryError::Consistency(
                                "stored OpenID4VC trust policy is invalid".to_owned(),
                            )
                        })?;
                    nazo_operator_protocol::validate_openid4vc_trust_policy(&material).map_err(
                        |_| {
                            RepositoryError::Consistency(
                                "stored OpenID4VC trust policy is invalid".to_owned(),
                            )
                        },
                    )?;
                    Ok(ClientTrustPolicy::Active(Box::new(
                        Openid4vcTrustPolicyRecord {
                            id: policy.id,
                            resource_id: policy.resource_id,
                            resource_digest: policy.resource_digest,
                            material,
                        },
                    )))
                }
            }
        })
    }

    fn active_for_origin<'a>(
        &'a self,
        tenant_id: Uuid,
        resource_id: &'a str,
        wallet_origin: &'a str,
        expected_digest: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<Openid4vcTrustPolicyRecord>, RepositoryError>,
    > {
        Box::pin(async move {
            self.active_openid4vc_trust_policy_for_origin(
                tenant_id,
                resource_id,
                wallet_origin,
                expected_digest,
            )
            .await?
            .map(|policy| {
                let material = serde_json::from_value(policy.public_material).map_err(|_| {
                    RepositoryError::Consistency(
                        "stored OpenID4VC trust policy is invalid".to_owned(),
                    )
                })?;
                nazo_operator_protocol::validate_openid4vc_trust_policy(&material).map_err(
                    |_| {
                        RepositoryError::Consistency(
                            "stored OpenID4VC trust policy is invalid".to_owned(),
                        )
                    },
                )?;
                Ok(Openid4vcTrustPolicyRecord {
                    id: policy.id,
                    resource_id: policy.resource_id,
                    resource_digest: policy.resource_digest,
                    material,
                })
            })
            .transpose()
        })
    }
}

async fn lock_operation_jti_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    tenant_id: Uuid,
    jti: &str,
) -> Result<(), RepositoryError> {
    let key = format!(
        "nazoauth:tenant-resource-operation:jti:{tenant_id}:{}:{deployment_id}:{}:{jti}",
        deployment_id.len(),
        jti.len(),
    );
    lock_advisory_key_on_connection(connection, key).await
}

async fn lock_advisory_key_on_connection(
    connection: &mut AsyncPgConnection,
    key: String,
) -> Result<(), RepositoryError> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 8706))")
        .bind::<sql_types::Text, _>(key)
        .execute(connection)
        .await
        .map_err(map_error)?;
    Ok(())
}

pub struct NewTenantResourceBinding<'a> {
    pub tenant_id: Uuid,
    pub resource_kind: &'a str,
    pub resource_id: &'a str,
    pub resource_digest: &'a str,
    pub active: bool,
    pub locator: &'a str,
}

pub struct NewStoredOpenid4vcTrustPolicy<'a> {
    pub tenant_id: Uuid,
    pub resource_id: &'a str,
    pub resource_digest: &'a str,
    pub public_material: &'a Value,
    /// Canonical wallet origins extracted and validated by the provider.
    pub wallet_origins: &'a [String],
}

async fn lock_binding_identity_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resource_kind: &str,
    resource_id: &str,
) -> Result<(), RepositoryError> {
    let key = format!(
        "nazoauth:tenant-resource-binding:{tenant_id}:{}:{resource_kind}:{}:{resource_id}",
        resource_kind.len(),
        resource_id.len(),
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 8707))")
        .bind::<sql_types::Text, _>(key)
        .execute(connection)
        .await
        .map_err(map_error)?;
    Ok(())
}

fn encode_revision(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| {
        RepositoryError::Consistency("tenant resource revision exceeds BIGINT".to_owned())
    })
}

fn decode_revision(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| {
        RepositoryError::Consistency("tenant resource revision is negative".to_owned())
    })
}

fn validate_stored_openid4vc_trust_policy_identity(
    resource_id: &str,
    resource_digest: &str,
) -> Result<(), RepositoryError> {
    if resource_id.is_empty()
        || resource_id.len() > 255
        || resource_id != resource_id.trim()
        || resource_id.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy resource ID is invalid".to_owned(),
        ));
    }
    if resource_digest.len() != 64
        || !resource_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy digest is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_wallet_origin(origin: &str) -> Result<(), RepositoryError> {
    if origin.len() > 2048
        || origin != origin.trim()
        || !origin.starts_with("https://")
        || origin.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy wallet origin is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        diesel::result::Error::NotFound => RepositoryError::NotFound,
        _ => RepositoryError::Unavailable,
    }
}
