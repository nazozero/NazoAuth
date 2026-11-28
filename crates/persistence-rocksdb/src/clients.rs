//! Client metadata and narrowly read authority share one transactional owner.

use jiff::Timestamp;
use nazo_auth::{
    AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort,
    ClientAuthenticationSnapshot, DynamicRegistrationClientStore,
    DynamicRegistrationDependencyError, DynamicRegistrationFuture, LogoutClientRepositoryPort,
    LogoutDependencyError, LogoutFuture, OAuthClient, PreparedClientRegistration,
    RegisteredLogoutClient, RegistrationClientSnapshot, UserinfoClient,
    ValidatedClientRegistration,
};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId, ports::RepositoryError};
use nazo_persistence::SecurityAuditEvent;
use rocksdb::{SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    RocksDb,
    audit::append_in_tx,
    db::{key, map_error, put, read_snapshot, read_tx},
    users::{admin_principal_tx, corrupt},
};
#[path = "client_record.rs"]
mod record;

pub(crate) const CLIENT_PRINCIPAL: u8 = 0x20;
pub(crate) const CLIENT_PUBLIC_ID: u8 = 0x21;
const CLIENT_REGISTRATION: u8 = 0x22;
pub(crate) const CLIENT_SECRET: u8 = 0x23;
const CLIENT_MANAGEMENT_TOKEN: u8 = 0x24;
const CLIENT_CREATED: u8 = 0x25;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ClientPrincipal {
    pub id: Uuid,
    pub public_id: String,
    pub client_type: String,
    pub active: bool,
    pub epoch: i64,
    pub tenant: TenantContext,
}
#[derive(Deserialize)]
struct ClientRecord {
    registration: record::StoredRegistration,
    require_mtls_bound_tokens: bool,
}
#[derive(Serialize)]
struct ClientWrite<'a> {
    registration: &'a ValidatedClientRegistration,
    require_mtls_bound_tokens: bool,
}

// Deserialize only response facts; protocol metadata and verifier material are
// not allocated on UserInfo or consent presentation reads.
#[derive(Deserialize)]
struct RegistrationProjection<T> {
    registration: T,
}
#[derive(Deserialize)]
struct UserinfoRegistration {
    security_policy: nazo_auth::ClientSecurityPolicy,
    userinfo_signed_response_alg: Option<String>,
    userinfo_encrypted_response_alg: Option<String>,
    userinfo_encrypted_response_enc: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<std::sync::Arc<serde_json::Value>>,
}
#[derive(Deserialize)]
struct Presentation {
    logo_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
}
#[derive(Deserialize)]
struct PresentationRegistration {
    client_name: String,
    presentation: Presentation,
}

#[derive(Deserialize)]
struct ClientName {
    client_name: String,
}

pub(crate) fn client_display(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
) -> Result<(String, String), RepositoryError> {
    let principal: ClientPrincipal =
        read_snapshot(snapshot, &key(CLIENT_PRINCIPAL, tenant, id.as_bytes()))?
            .ok_or_else(|| corrupt("client authority missing"))?;
    let record: RegistrationProjection<ClientName> =
        read_snapshot(snapshot, &key(CLIENT_REGISTRATION, tenant, id.as_bytes()))?
            .ok_or_else(|| corrupt("client registration missing"))?;
    Ok((principal.public_id, record.registration.client_name))
}

pub(crate) fn context(client: &OAuthClient) -> Result<TenantContext, RepositoryError> {
    Ok(TenantContext {
        tenant_id: TenantId::new(client.tenant_id).map_err(|_| corrupt("invalid client tenant"))?,
        realm_id: RealmId::new(client.realm_id).map_err(|_| corrupt("invalid client realm"))?,
        organization_id: OrganizationId::new(client.organization_id)
            .map_err(|_| corrupt("invalid client organization"))?,
    })
}
fn domain(
    principal: ClientPrincipal,
    record: ClientRecord,
) -> Result<OAuthClient, RepositoryError> {
    let registration = record.registration.into_domain();
    if registration.client_id != principal.public_id
        || registration.client_type != principal.client_type
    {
        return Err(corrupt("client authority and registration differ"));
    }
    registration.security_policy.validate().map_err(corrupt)?;
    Ok(OAuthClient {
        id: principal.id,
        tenant_id: principal.tenant.tenant_id.as_uuid(),
        realm_id: principal.tenant.realm_id.as_uuid(),
        organization_id: principal.tenant.organization_id.as_uuid(),
        registration,
        require_mtls_bound_tokens: record.require_mtls_bound_tokens,
        is_active: principal.active,
    })
}
pub(crate) fn read_client_snapshot(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
) -> Result<Option<OAuthClient>, RepositoryError> {
    let Some(principal) = read_snapshot(snapshot, &key(CLIENT_PRINCIPAL, tenant, id.as_bytes()))?
    else {
        return Ok(None);
    };
    let record = read_snapshot(snapshot, &key(CLIENT_REGISTRATION, tenant, id.as_bytes()))?
        .ok_or_else(|| corrupt("client registration missing"))?;
    domain(principal, record).map(Some)
}
pub(crate) fn read_client_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
    exclusive: bool,
) -> Result<Option<OAuthClient>, RepositoryError> {
    let Some(principal) = read_tx(tx, &key(CLIENT_PRINCIPAL, tenant, id.as_bytes()), exclusive)?
    else {
        return Ok(None);
    };
    let record = read_tx(tx, &key(CLIENT_REGISTRATION, tenant, id.as_bytes()), false)?
        .ok_or_else(|| corrupt("client registration missing"))?;
    domain(principal, record).map(Some)
}
pub(crate) fn client_userinfo(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
) -> Result<Option<UserinfoClient>, RepositoryError> {
    let Some(principal) =
        read_snapshot::<ClientPrincipal>(snapshot, &key(CLIENT_PRINCIPAL, tenant, id.as_bytes()))?
    else {
        return Ok(None);
    };
    let row: RegistrationProjection<UserinfoRegistration> =
        read_snapshot(snapshot, &key(CLIENT_REGISTRATION, tenant, id.as_bytes()))?
            .ok_or_else(|| corrupt("client registration missing"))?;
    row.registration
        .security_policy
        .validate()
        .map_err(corrupt)?;
    Ok(Some(UserinfoClient {
        is_active: principal.active,
        require_fapi2: row.registration.security_policy.requires_fapi2_security(),
        signed_response_alg: row.registration.userinfo_signed_response_alg,
        encrypted_response_alg: row.registration.userinfo_encrypted_response_alg,
        encrypted_response_enc: row.registration.userinfo_encrypted_response_enc,
        jwks_uri: row.registration.jwks_uri,
        jwks: row.registration.jwks,
    }))
}

pub(crate) fn client_presentation(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    public_id: &str,
) -> Result<Option<nazo_auth::ClientPresentation>, RepositoryError> {
    let Some(id) = read_snapshot::<Uuid>(
        snapshot,
        &key(CLIENT_PUBLIC_ID, tenant, public_id.as_bytes()),
    )?
    else {
        return Ok(None);
    };
    if !read_snapshot::<ClientPrincipal>(snapshot, &key(CLIENT_PRINCIPAL, tenant, id.as_bytes()))?
        .is_some_and(|p| p.active)
    {
        return Ok(None);
    }
    let row: RegistrationProjection<PresentationRegistration> =
        read_snapshot(snapshot, &key(CLIENT_REGISTRATION, tenant, id.as_bytes()))?
            .ok_or_else(|| corrupt("client registration missing"))?;
    Ok(Some(nazo_auth::ClientPresentation {
        client_name: row.registration.client_name,
        logo_uri: row.registration.presentation.logo_uri,
        policy_uri: row.registration.presentation.policy_uri,
        tos_uri: row.registration.presentation.tos_uri,
    }))
}
pub(crate) fn public_id_snapshot(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    public_id: &str,
) -> Result<Option<OAuthClient>, RepositoryError> {
    match read_snapshot::<Uuid>(
        snapshot,
        &key(CLIENT_PUBLIC_ID, tenant, public_id.as_bytes()),
    )? {
        Some(id) => read_client_snapshot(snapshot, tenant, id),
        None => Ok(None),
    }
}
pub(crate) fn client_authentication(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    public_id: &str,
) -> Result<Option<ClientAuthenticationSnapshot>, RepositoryError> {
    let Some(id) = read_snapshot::<Uuid>(
        snapshot,
        &key(CLIENT_PUBLIC_ID, tenant, public_id.as_bytes()),
    )?
    else {
        return Ok(None);
    };
    let principal: ClientPrincipal =
        read_snapshot(snapshot, &key(CLIENT_PRINCIPAL, tenant, id.as_bytes()))?
            .ok_or_else(|| corrupt("client index references missing authority"))?;
    let secret_digest = if principal.active {
        read_snapshot(snapshot, &key(CLIENT_SECRET, tenant, id.as_bytes()))?
    } else {
        None
    };
    let record = read_snapshot(snapshot, &key(CLIENT_REGISTRATION, tenant, id.as_bytes()))?
        .ok_or_else(|| corrupt("client registration missing"))?;
    Ok(Some(ClientAuthenticationSnapshot {
        client_epoch: principal.epoch,
        client: domain(principal, record)?,
        secret_digest,
    }))
}
fn optional_secret(
    tx: &Transaction<'_, TransactionDB>,
    table: u8,
    tenant: Uuid,
    id: Uuid,
    secret: Option<&str>,
) -> Result<(), RepositoryError> {
    let key = key(table, tenant, id.as_bytes());
    match secret {
        Some(secret) => put(tx, &key, &secret),
        None => tx.delete(&key).map_err(map_error),
    }
}
pub(crate) fn write_client_tx(
    tx: &Transaction<'_, TransactionDB>,
    client: &OAuthClient,
    epoch: i64,
) -> Result<(), RepositoryError> {
    client.security_policy.validate().map_err(corrupt)?;
    let principal = ClientPrincipal {
        id: client.id,
        public_id: client.client_id.clone(),
        client_type: client.client_type.clone(),
        active: client.is_active,
        epoch,
        tenant: context(client)?,
    };
    put(
        tx,
        &key(CLIENT_PRINCIPAL, client.tenant_id, client.id.as_bytes()),
        &principal,
    )?;
    put(
        tx,
        &key(CLIENT_REGISTRATION, client.tenant_id, client.id.as_bytes()),
        &ClientWrite {
            registration: &client.registration,
            require_mtls_bound_tokens: client.require_mtls_bound_tokens,
        },
    )
}
pub(crate) fn insert_client_tx(
    tx: &Transaction<'_, TransactionDB>,
    client: &OAuthClient,
    secret: Option<&str>,
    token: Option<&str>,
    epoch: i64,
) -> Result<(), RepositoryError> {
    if client.id.is_nil() || epoch < 0 {
        return Err(corrupt("invalid client authority"));
    }
    let public_key = key(
        CLIENT_PUBLIC_ID,
        client.tenant_id,
        client.client_id.as_bytes(),
    );
    if read_tx::<Uuid>(tx, &public_key, true)?.is_some()
        || read_tx::<ClientPrincipal>(
            tx,
            &key(CLIENT_PRINCIPAL, client.tenant_id, client.id.as_bytes()),
            true,
        )?
        .is_some()
    {
        return Err(RepositoryError::Conflict);
    }
    write_client_tx(tx, client, epoch)?;
    put(tx, &public_key, &client.id)?;
    let mut created = key(
        CLIENT_CREATED,
        client.tenant_id,
        &((Timestamp::now().as_microsecond() as u64) ^ (1 << 63)).to_be_bytes(),
    );
    created.extend_from_slice(client.id.as_bytes());
    put(tx, &created, &())?;
    optional_secret(tx, CLIENT_SECRET, client.tenant_id, client.id, secret)?;
    optional_secret(
        tx,
        CLIENT_MANAGEMENT_TOKEN,
        client.tenant_id,
        client.id,
        token,
    )
}
fn lifecycle_event(
    client: &OAuthClient,
    event_type: &str,
    source: Option<&str>,
    actor: Option<Uuid>,
) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::new_v4(),
        event_type: event_type.into(),
        event_category: "client_lifecycle".into(),
        occurred_at: Timestamp::now(),
        payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"client_lifecycle",
            "tenant_id":client.tenant_id,"realm_id":client.realm_id,"organization_id":client.organization_id,"admin_user_id":actor,
            "client_pk":client.id,"client_id":client.client_id,"client_type":client.client_type,"grant_types":client.grant_types,
            "token_endpoint_auth_method":client.token_endpoint_auth_method,"outcome":"success","source_ip_hash":source}),
    }
}
fn mutation_effects(
    tx: &Transaction<'_, TransactionDB>,
    old: &OAuthClient,
    new: &OAuthClient,
    epoch: i64,
) -> Result<i64, RepositoryError> {
    let deactivate = old.is_active && !new.is_active;
    let downgrade = old.client_type == "confidential" && new.client_type == "public";
    if downgrade || deactivate {
        crate::tokens::revoke_families_with_reason(
            tx,
            new.tenant_id,
            Some(new.id),
            None,
            downgrade.then_some("client_authentication_class_downgrade"),
        )?;
    }
    if deactivate {
        crate::grants::delete_for_client_tx(tx, new.tenant_id, new.id)?;
        crate::digital_credentials::issuance::revoke_for_client(tx, new.tenant_id, &new.client_id)?;
    }
    if downgrade {
        optional_secret(tx, CLIENT_SECRET, new.tenant_id, new.id, None)?;
    }
    epoch
        .checked_add(i64::from(deactivate))
        .ok_or_else(|| corrupt("client epoch exhausted"))
}
pub(crate) fn disable_client_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
) -> Result<bool, RepositoryError> {
    let Some(old) = read_client_tx(tx, tenant, id, true)?.filter(|c| c.is_active) else {
        return Ok(false);
    };
    let principal: ClientPrincipal =
        read_tx(tx, &key(CLIENT_PRINCIPAL, tenant, id.as_bytes()), true)?
            .ok_or_else(|| corrupt("client authority missing"))?;
    let mut new = old.clone();
    new.is_active = false;
    let epoch = mutation_effects(tx, &old, &new, principal.epoch)?;
    write_client_tx(tx, &new, epoch)?;
    optional_secret(tx, CLIENT_MANAGEMENT_TOKEN, tenant, id, None)?;
    Ok(true)
}
fn admin_error(error: RepositoryError) -> AdminClientPortError {
    match error {
        RepositoryError::Conflict => AdminClientPortError::Conflict,
        RepositoryError::Unavailable => AdminClientPortError::Unavailable,
        RepositoryError::Consistency(_) => AdminClientPortError::CorruptData,
        _ => AdminClientPortError::Unexpected,
    }
}
fn dynamic_error(error: RepositoryError) -> DynamicRegistrationDependencyError {
    match error {
        RepositoryError::Conflict => DynamicRegistrationDependencyError::PolicyChanged,
        RepositoryError::NotFound => DynamicRegistrationDependencyError::StaleCredentials,
        _ => DynamicRegistrationDependencyError::Unavailable,
    }
}
fn logout_error(error: RepositoryError) -> LogoutDependencyError {
    match error {
        RepositoryError::Unavailable => LogoutDependencyError::Unavailable,
        _ => LogoutDependencyError::Consistency,
    }
}

impl AdminClientRepositoryPort for RocksDb {
    fn page(
        &self,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        Box::pin(async move {
            self.run(move |db| {
                if limit < 0 || offset < 0 {
                    return Err(corrupt("negative client page bounds"));
                }
                let snapshot = db.db.snapshot();
                let prefix = key(CLIENT_CREATED, tenant_id, &[]);
                let mut upper = prefix.clone();
                upper.extend_from_slice(&[u8::MAX; 24]);
                let mut clients = Vec::new();
                let mut total = 0i64;
                let mut rows = snapshot.raw_iterator();
                rows.seek_for_prev(&upper);
                while let Some(k) = rows.key() {
                    if !k.starts_with(&prefix) {
                        break;
                    }
                    if total >= offset && clients.len() < limit as usize {
                        let id = Uuid::from_slice(&k[prefix.len() + 8..])
                            .map_err(|_| corrupt("invalid client creation index"))?;
                        clients.push(
                            read_client_snapshot(&snapshot, tenant_id, id)?
                                .ok_or_else(|| corrupt("client disappeared from snapshot"))?,
                        );
                    }
                    total += 1;
                    rows.prev();
                }
                rows.status().map_err(map_error)?;
                Ok((clients, total))
            })
            .await
            .map_err(admin_error)
        })
    }
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        let client_id = client_id.to_owned();
        Box::pin(async move {
            self.run(move |db| public_id_snapshot(&db.db.snapshot(), tenant_id, &client_id))
                .await
                .map_err(admin_error)
        })
    }
    fn insert_with_required_audit<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
        actor_id: Uuid,
        source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        let client = client.clone();
        let secret = client_secret_hash.map(str::to_owned);
        let token = registration_access_token_blake3.map(str::to_owned);
        let source = source_ip_hash.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let tx = db.transaction();
                // Client locks precede user authority everywhere, including insertion.
                insert_client_tx(&tx, &client, secret.as_deref(), token.as_deref(), 0)?;
                admin_principal_tx(&tx, context(&client)?, actor_id)?;
                append_in_tx(
                    &tx,
                    &lifecycle_event(&client, "client_created", Some(&source), Some(actor_id)),
                )?;
                tx.commit().map_err(map_error)?;
                Ok(client)
            })
            .await
            .map_err(admin_error)
        })
    }
    fn update_with_required_audit<'a>(
        &'a self,
        expected: &'a OAuthClient,
        client: &'a OAuthClient,
        actor_id: Uuid,
        source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        let expected = expected.clone();
        let client = client.clone();
        let source = source_ip_hash.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let tx = db.transaction();
                if expected.id != client.id
                    || context(&expected)? != context(&client)?
                    || expected.client_id != client.client_id
                {
                    return Err(corrupt("client placement cannot change"));
                }
                let managed =
                    crate::tenant_resources::managed_client_tx(&tx, client.tenant_id, client.id)?;
                let old = read_client_tx(&tx, client.tenant_id, client.id, true)?
                    .ok_or(RepositoryError::Conflict)?;
                if old != expected {
                    return Err(RepositoryError::Conflict);
                }
                if managed && old != client {
                    return Err(RepositoryError::Conflict);
                }
                let principal: ClientPrincipal = read_tx(
                    &tx,
                    &key(CLIENT_PRINCIPAL, client.tenant_id, client.id.as_bytes()),
                    true,
                )?
                .ok_or_else(|| corrupt("client authority missing"))?;
                admin_principal_tx(&tx, context(&client)?, actor_id)?;
                let epoch = mutation_effects(&tx, &old, &client, principal.epoch)?;
                write_client_tx(&tx, &client, epoch)?;
                append_in_tx(
                    &tx,
                    &lifecycle_event(&client, "client_updated", Some(&source), Some(actor_id)),
                )?;
                tx.commit().map_err(map_error)?;
                Ok(client)
            })
            .await
            .map_err(admin_error)
        })
    }
}
impl DynamicRegistrationClientStore for RocksDb {
    fn insert<'a>(
        &'a self,
        prepared: PreparedClientRegistration,
        source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        let source = source_ip_hash.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let tx = db.transaction();
                let write = prepared.into_write();
                insert_client_tx(
                    &tx,
                    &write.client,
                    write.client_secret_hash.as_deref(),
                    write.registration_access_token_blake3.as_deref(),
                    0,
                )?;
                append_in_tx(
                    &tx,
                    &lifecycle_event(
                        &write.client,
                        "dynamic_client_registered",
                        Some(&source),
                        None,
                    ),
                )?;
                tx.commit().map_err(map_error)?;
                Ok(write.client)
            })
            .await
            .map_err(dynamic_error)
        })
    }
    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<RegistrationClientSnapshot>> {
        let client_id = client_id.to_owned();
        let token_hash = token_hash.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let snapshot = db.db.snapshot();
                let Some(client) =
                    public_id_snapshot(&snapshot, tenant_id, &client_id)?.filter(|c| c.is_active)
                else {
                    return Ok(None);
                };
                if read_snapshot::<String>(
                    &snapshot,
                    &key(CLIENT_MANAGEMENT_TOKEN, tenant_id, client.id.as_bytes()),
                )?
                .as_deref()
                    != Some(&token_hash)
                {
                    return Ok(None);
                }
                let secret = read_snapshot::<String>(
                    &snapshot,
                    &key(CLIENT_SECRET, tenant_id, client.id.as_bytes()),
                )?;
                let secret_salt = secret
                    .as_deref()
                    .and_then(|s| s.strip_prefix("client-secret-v1:"))
                    .and_then(|s| s.split_once(':'))
                    .map(|(salt, _)| salt.to_owned());
                Ok(Some(RegistrationClientSnapshot {
                    client,
                    has_client_secret: secret.is_some(),
                    secret_salt,
                }))
            })
            .await
            .map_err(dynamic_error)
        })
    }
    fn client_secret_digest_matches<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        let candidate = candidate_digest.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let snapshot = db.db.snapshot();
                if !read_snapshot::<ClientPrincipal>(
                    &snapshot,
                    &key(CLIENT_PRINCIPAL, tenant_id, client_id.as_bytes()),
                )?
                .is_some_and(|p| p.active)
                {
                    return Ok(false);
                }
                Ok(read_snapshot::<String>(
                    &snapshot,
                    &key(CLIENT_SECRET, tenant_id, client_id.as_bytes()),
                )?
                .as_deref()
                    == Some(&candidate))
            })
            .await
            .map_err(dynamic_error)
        })
    }
    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        let secret = client_secret_hash.map(str::to_owned);
        let expected = expected_registration_access_token_hash.to_owned();
        let token = new_registration_access_token_hash.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let tx = db.transaction();
                let (client, managed) = management_client(&tx, tenant_id, client_id, &expected)?;
                if managed
                    && (token != expected
                        || read_tx::<String>(
                            &tx,
                            &key(CLIENT_SECRET, tenant_id, client_id.as_bytes()),
                            false,
                        )?
                        .as_deref()
                            != secret.as_deref())
                {
                    return Err(RepositoryError::Conflict);
                }
                optional_secret(&tx, CLIENT_SECRET, tenant_id, client_id, secret.as_deref())?;
                optional_secret(
                    &tx,
                    CLIENT_MANAGEMENT_TOKEN,
                    tenant_id,
                    client_id,
                    Some(&token),
                )?;
                tx.commit().map_err(map_error)?;
                Ok(client)
            })
            .await
            .map_err(dynamic_error)
        })
    }
    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: Option<&'a str>,
        source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        let mut client = client.clone();
        let secret = client_secret_hash.map(str::to_owned);
        let expected = expected_registration_access_token_hash.to_owned();
        let token = new_registration_access_token_hash.map(str::to_owned);
        let source = source_ip_hash.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let tx = db.transaction();
                let (old, managed) =
                    management_client(&tx, client.tenant_id, client.id, &expected)?;
                if context(&old)? != context(&client)?
                    || old.client_id != client.client_id
                    || !client.is_active
                {
                    return Err(RepositoryError::Conflict);
                }
                if old.security_policy != client.security_policy
                    || client
                        .scopes
                        .iter()
                        .any(|scope| !old.scopes.contains(scope))
                {
                    return Err(RepositoryError::Conflict);
                }
                client.registration.allowed_audiences = old.allowed_audiences.clone();
                if managed
                    && (old != client
                        || token.as_deref() != Some(expected.as_str())
                        || read_tx::<String>(
                            &tx,
                            &key(CLIENT_SECRET, client.tenant_id, client.id.as_bytes()),
                            false,
                        )?
                        .as_deref()
                            != secret.as_deref())
                {
                    return Err(RepositoryError::Conflict);
                }
                let principal: ClientPrincipal = read_tx(
                    &tx,
                    &key(CLIENT_PRINCIPAL, client.tenant_id, client.id.as_bytes()),
                    true,
                )?
                .ok_or_else(|| corrupt("client authority missing"))?;
                let epoch = mutation_effects(&tx, &old, &client, principal.epoch)?;
                write_client_tx(&tx, &client, epoch)?;
                optional_secret(
                    &tx,
                    CLIENT_SECRET,
                    client.tenant_id,
                    client.id,
                    if old.client_type == "confidential" && client.client_type == "public" {
                        None
                    } else {
                        secret.as_deref()
                    },
                )?;
                optional_secret(
                    &tx,
                    CLIENT_MANAGEMENT_TOKEN,
                    client.tenant_id,
                    client.id,
                    token.as_deref(),
                )?;
                append_in_tx(
                    &tx,
                    &lifecycle_event(
                        &client,
                        "dynamic_client_configuration_updated",
                        Some(&source),
                        None,
                    ),
                )?;
                tx.commit().map_err(map_error)?;
                Ok(client)
            })
            .await
            .map_err(dynamic_error)
        })
    }
    fn deactivate<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        expected_registration_access_token_hash: &'a str,
        source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        let expected = expected_registration_access_token_hash.to_owned();
        let source = source_ip_hash.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                let tx = db.transaction();
                let (mut client, managed) =
                    management_client(&tx, tenant_id, client_id, &expected)?;
                if managed {
                    return Err(RepositoryError::Conflict);
                }
                disable_client_tx(&tx, tenant_id, client_id)?;
                client.is_active = false;
                append_in_tx(
                    &tx,
                    &lifecycle_event(&client, "dynamic_client_deleted", Some(&source), None),
                )?;
                tx.commit().map_err(map_error)?;
                Ok(true)
            })
            .await
            .map_err(dynamic_error)
        })
    }
}
fn management_client(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
    expected: &str,
) -> Result<(OAuthClient, bool), RepositoryError> {
    let managed = crate::tenant_resources::managed_client_tx(tx, tenant, id)?;
    let client = read_client_tx(tx, tenant, id, true)?
        .filter(|c| c.is_active)
        .ok_or(RepositoryError::NotFound)?;
    if read_tx::<String>(
        tx,
        &key(CLIENT_MANAGEMENT_TOKEN, tenant, id.as_bytes()),
        true,
    )?
    .as_deref()
        != Some(expected)
    {
        return Err(RepositoryError::NotFound);
    }
    Ok((client, managed))
}
fn logout_client(client: OAuthClient) -> RegisteredLogoutClient {
    RegisteredLogoutClient {
        require_fapi2: client.security_policy.requires_fapi2_security(),
        id_token_signed_response_alg: client.registration.id_token_signed_response_alg,
        id: client.id,
        tenant_id: client.tenant_id,
        client_id: client.registration.client_id,
        active: client.is_active,
        redirect_uris: client.registration.redirect_uris,
        post_logout_redirect_uris: client.registration.post_logout_redirect_uris,
        backchannel_logout_uri: client.registration.backchannel_logout_uri,
        frontchannel_logout_uri: client.registration.frontchannel_logout_uri,
        frontchannel_logout_session_required: client
            .registration
            .frontchannel_logout_session_required,
        subject_type: client.registration.subject_type,
        sector_identifier_host: client.registration.sector_identifier_host,
    }
}
impl LogoutClientRepositoryPort for RocksDb {
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> LogoutFuture<'a, Option<RegisteredLogoutClient>> {
        let id = client_id.to_owned();
        Box::pin(async move {
            self.run(move |db| {
                public_id_snapshot(&db.db.snapshot(), tenant_id, &id).map(|c| c.map(logout_client))
            })
            .await
            .map_err(logout_error)
        })
    }
    fn by_client_ids<'a>(
        &'a self,
        tenant_id: Uuid,
        client_ids: &'a [&'a str],
    ) -> LogoutFuture<'a, Vec<RegisteredLogoutClient>> {
        let ids = client_ids.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Box::pin(async move {
            self.run(move |db| {
                let snapshot = db.db.snapshot();
                let mut clients = Vec::with_capacity(ids.len());
                for id in ids {
                    if let Some(client) = public_id_snapshot(&snapshot, tenant_id, &id)? {
                        clients.push(logout_client(client));
                    }
                }
                Ok(clients)
            })
            .await
            .map_err(logout_error)
        })
    }
}
