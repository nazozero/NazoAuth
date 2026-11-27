//! Authoritative routing and tenant boundaries. Directory writers serialize on
//! the revision; request-side authority checks lock only their tenant record.

use futures_util::future::BoxFuture;
use nazo_identity::{
    TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot, TenantId,
    TenantProvisioningRequest, ports::RepositoryError,
};
use nazo_persistence::{TenantDirectoryStore, directory_control::*};
use rocksdb::{Direction, IteratorMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    RocksDb,
    db::{decode, key, map_error, put, read, read_snapshot, read_tx},
};

const REVISION: u8 = 0x60;
const TENANT: u8 = 0x61;
const REALM_OWNER: u8 = 0x62;
const ORGANIZATION_OWNER: u8 = 0x63;
const ROUTING: u8 = 0x64;
const OUTCOME: u8 = 0x65;
const TENANT_SLUG: u8 = 0x6d;
const REALM_SLUG: u8 = 0x6e;
const ORGANIZATION_SLUG: u8 = 0x6f;

#[derive(Serialize, Deserialize)]
struct TenantRecord {
    binding: Option<TenantDirectoryBinding>,
    active: bool,
    slug: String,
    display_name: String,
}

#[derive(Serialize, Deserialize)]
struct OwnedBoundary {
    tenant_id: Uuid,
    slug: String,
    display_name: String,
}

#[derive(Serialize, Deserialize)]
struct OperationOutcome {
    deployment_id: String,
    request_hash: String,
    operation: String,
    outcome: DirectoryControlOutcome,
}

fn revision_key() -> Vec<u8> {
    key(REVISION, Uuid::nil(), &[])
}

pub(crate) fn active_context_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantId,
) -> Result<Option<TenantContext>, RepositoryError> {
    Ok(
        read_tx::<TenantRecord>(tx, &key(TENANT, tenant.as_uuid(), &[]), false)?
            .filter(|row| row.active)
            .and_then(|row| row.binding.map(|binding| binding.tenant)),
    )
}

fn validate_binding(binding: &TenantDirectoryBinding) -> Result<(), RepositoryError> {
    let issuer = nazo_auth::validate_issuer_url(&binding.issuer)
        .map_err(|error| RepositoryError::Consistency(error.to_string()))?;
    let host = nazo_identity::canonical_tenant_host(&binding.external_host)
        .map_err(|error| RepositoryError::Consistency(error.to_string()))?;
    if host != binding.external_host
        || nazo_identity::tenant_host_from_issuer(&issuer)
            .map_err(|error| RepositoryError::Consistency(error.to_string()))?
            != host
        || binding.runtime_revision == 0
    {
        return Err(RepositoryError::Consistency(
            "invalid tenant routing identity".into(),
        ));
    }
    Ok(())
}

fn validate_boundary(slug: &str, display_name: &str) -> Result<(), RepositoryError> {
    if slug.trim().is_empty() || slug.chars().count() > 120 || display_name.chars().count() > 200 {
        return Err(RepositoryError::Unexpected(
            "tenant boundary metadata violates storage limits".into(),
        ));
    }
    Ok(())
}

fn bind_slug(
    tx: &Transaction<'_, TransactionDB>,
    table: u8,
    scope: Uuid,
    slug: &str,
    id: Uuid,
) -> Result<(), RepositoryError> {
    let storage_key = key(table, scope, slug.to_lowercase().as_bytes());
    if read_tx::<Uuid>(tx, &storage_key, true)?.is_some_and(|owner| owner != id) {
        return Err(RepositoryError::Unexpected(
            "tenant boundary slug already exists".into(),
        ));
    }
    put(tx, &storage_key, &id)
}

fn ensure_tenant(
    tx: &Transaction<'_, TransactionDB>,
    id: Uuid,
    slug: &str,
    display_name: &str,
) -> Result<(), RepositoryError> {
    validate_boundary(slug, display_name)?;
    let storage_key = key(TENANT, id, &[]);
    if let Some(existing) = read_tx::<TenantRecord>(tx, &storage_key, true)? {
        return if existing.active {
            Ok(())
        } else {
            Err(RepositoryError::Consistency(
                "provisioned tenant boundary is inactive".into(),
            ))
        };
    }
    bind_slug(tx, TENANT_SLUG, Uuid::nil(), slug, id)?;
    put(
        tx,
        &storage_key,
        &TenantRecord {
            binding: None,
            active: true,
            slug: slug.into(),
            display_name: display_name.into(),
        },
    )
}

fn bind_owner(
    tx: &Transaction<'_, TransactionDB>,
    table: u8,
    id: Uuid,
    tenant: Uuid,
    slug: &str,
    display_name: &str,
) -> Result<(), RepositoryError> {
    validate_boundary(slug, display_name)?;
    let storage_key = key(table, Uuid::nil(), id.as_bytes());
    if let Some(existing) = read_tx::<OwnedBoundary>(tx, &storage_key, true)? {
        return if existing.tenant_id == tenant {
            Ok(())
        } else {
            Err(RepositoryError::Consistency(
                "boundary belongs to another tenant".into(),
            ))
        };
    }
    let slug_table = match table {
        REALM_OWNER => REALM_SLUG,
        ORGANIZATION_OWNER => ORGANIZATION_SLUG,
        _ => unreachable!(),
    };
    bind_slug(tx, slug_table, tenant, slug, id)?;
    put(
        tx,
        &storage_key,
        &OwnedBoundary {
            tenant_id: tenant,
            slug: slug.into(),
            display_name: display_name.into(),
        },
    )
}

fn ensure_default_boundaries(tx: &Transaction<'_, TransactionDB>) -> Result<(), RepositoryError> {
    let context = TenantContext::default_system();
    let tenant = context.tenant_id.as_uuid();
    ensure_tenant(tx, tenant, "default", "Default tenant")?;
    bind_owner(
        tx,
        REALM_OWNER,
        context.realm_id.as_uuid(),
        tenant,
        "default",
        "Default realm",
    )?;
    bind_owner(
        tx,
        ORGANIZATION_OWNER,
        context.organization_id.as_uuid(),
        tenant,
        "default",
        "Default organization",
    )
}

fn bind_route(
    tx: &Transaction<'_, TransactionDB>,
    host: &str,
    tenant: Uuid,
) -> Result<(), RepositoryError> {
    let route_key = key(ROUTING, Uuid::nil(), host.as_bytes());
    match read_tx::<Uuid>(tx, &route_key, true)? {
        Some(owner) if owner != tenant => Err(RepositoryError::Conflict),
        Some(_) => Ok(()),
        None => put(tx, &route_key, &tenant),
    }
}

fn insert_binding(
    tx: &Transaction<'_, TransactionDB>,
    binding: &TenantDirectoryBinding,
    revision: u64,
) -> Result<u64, RepositoryError> {
    validate_binding(binding)?;
    let tenant = binding.tenant.tenant_id.as_uuid();
    let storage_key = key(TENANT, tenant, &[]);
    let mut existing =
        read_tx::<TenantRecord>(tx, &storage_key, true)?.ok_or(RepositoryError::NotFound)?;
    if !existing.active
        || existing
            .binding
            .as_ref()
            .is_some_and(|value| value != binding)
    {
        return Err(RepositoryError::Consistency(
            "tenant binding already exists or is inactive".into(),
        ));
    }
    if existing.binding.as_ref() == Some(binding) {
        crate::runtime::ensure_defaults_in_tx(tx, tenant)?;
        return Ok(revision);
    }
    for (table, id) in [
        (REALM_OWNER, binding.tenant.realm_id.as_uuid()),
        (ORGANIZATION_OWNER, binding.tenant.organization_id.as_uuid()),
    ] {
        if !read_tx::<OwnedBoundary>(tx, &key(table, Uuid::nil(), id.as_bytes()), false)?
            .is_some_and(|owner| owner.tenant_id == tenant)
        {
            return Err(RepositoryError::Consistency(
                "tenant boundary is missing or belongs to another tenant".into(),
            ));
        }
    }
    bind_route(tx, &binding.external_host, tenant)?;
    existing.binding = Some(binding.clone());
    put(tx, &storage_key, &existing)?;
    crate::runtime::ensure_defaults_in_tx(tx, tenant)?;
    let revision = revision
        .checked_add(1)
        .ok_or_else(|| RepositoryError::Consistency("tenant revision exhausted".into()))?;
    put(tx, &revision_key(), &revision)?;
    Ok(revision)
}

impl RocksDb {
    pub async fn initialize_tenant_directory(
        &self,
        binding: TenantDirectoryBinding,
    ) -> Result<bool, RepositoryError> {
        self.run(move |db| {
            validate_binding(&binding)?;
            let tx = db.transaction();
            let revision: u64 = read_tx(&tx, &revision_key(), true)?.unwrap_or(0);
            if revision != 0 {
                let existing: Option<TenantRecord> = read_tx(
                    &tx,
                    &key(TENANT, binding.tenant.tenant_id.as_uuid(), &[]),
                    false,
                )?;
                let matches = existing.and_then(|row| row.binding).is_some_and(|row| {
                    row.tenant == binding.tenant
                        && row.issuer == binding.issuer
                        && row.external_host == binding.external_host
                });
                if !matches {
                    return Err(RepositoryError::Consistency(
                        "tenant directory is initialized with a different binding".into(),
                    ));
                }
                crate::runtime::ensure_defaults_in_tx(&tx, binding.tenant.tenant_id.as_uuid())?;
                tx.commit().map_err(map_error)?;
                return Ok(false);
            }
            ensure_default_boundaries(&tx)?;
            insert_binding(&tx, &binding, revision)?;
            tx.commit().map_err(map_error)?;
            Ok(true)
        })
        .await
    }
}

impl TenantDirectoryStore for RocksDb {
    fn current_revision(&self) -> BoxFuture<'_, Result<u64, RepositoryError>> {
        Box::pin(self.run(|db| Ok(read(&db.db, &revision_key())?.unwrap_or(0))))
    }

    fn load_active(&self) -> BoxFuture<'_, Result<TenantDirectorySnapshot, RepositoryError>> {
        Box::pin(self.run(|db| {
            let snapshot = db.db.snapshot();
            let revision = read_snapshot(&snapshot, &revision_key())?.unwrap_or(0);
            let mut tenants = Vec::new();
            for row in snapshot.iterator(IteratorMode::From(&[TENANT], Direction::Forward)) {
                let (storage_key, value) = row.map_err(map_error)?;
                if storage_key.first() != Some(&TENANT) {
                    break;
                }
                let record: TenantRecord = decode(&value)?;
                if record.active
                    && let Some(binding) = record.binding
                {
                    validate_binding(&binding)?;
                    tenants.push(binding);
                }
            }
            tenants.sort_by(|a, b| {
                (&a.external_host, a.tenant.tenant_id.as_uuid())
                    .cmp(&(&b.external_host, b.tenant.tenant_id.as_uuid()))
            });
            Ok(TenantDirectorySnapshot { revision, tenants })
        }))
    }

    fn find_active_binding(
        &self,
        tenant: TenantId,
    ) -> BoxFuture<'_, Result<Option<TenantDirectoryBinding>, RepositoryError>> {
        Box::pin(self.run(move |db| {
            let row: Option<TenantRecord> = read(&db.db, &key(TENANT, tenant.as_uuid(), &[]))?;
            let binding = row.filter(|row| row.active).and_then(|row| row.binding);
            if let Some(binding) = &binding {
                validate_binding(binding)?;
            }
            Ok(binding)
        }))
    }
}

fn operation_name(action: &DirectoryControlAction) -> &'static str {
    match action {
        DirectoryControlAction::Create { .. } => "create",
        DirectoryControlAction::Update { .. } => "update",
        DirectoryControlAction::Disable { .. } => "disable",
        DirectoryControlAction::Reload { .. } => "reload",
        DirectoryControlAction::Finalize { .. } => "finalize",
        DirectoryControlAction::Describe => "describe",
    }
}

fn apply_mutation(
    tx: &Transaction<'_, TransactionDB>,
    action: &DirectoryControlAction,
) -> Result<DirectoryControlOutcome, RepositoryError> {
    let revision: u64 = read_tx(tx, &revision_key(), true)?.unwrap_or(0);
    let (expected, tenant) = match action {
        DirectoryControlAction::Create {
            expected_revision,
            provisioning,
        } => (*expected_revision, provisioning.binding.tenant.tenant_id),
        DirectoryControlAction::Update {
            expected_revision,
            tenant_id,
            ..
        }
        | DirectoryControlAction::Disable {
            expected_revision,
            tenant_id,
        }
        | DirectoryControlAction::Reload {
            expected_revision,
            tenant_id,
        }
        | DirectoryControlAction::Finalize {
            expected_revision,
            tenant_id,
        } => (*expected_revision, *tenant_id),
        DirectoryControlAction::Describe => {
            let mut tenants = Vec::new();
            for row in tx.iterator(IteratorMode::From(&[TENANT], Direction::Forward)) {
                let (storage_key, value) = row.map_err(map_error)?;
                if storage_key.first() != Some(&TENANT) {
                    break;
                }
                let record: TenantRecord = decode(&value)?;
                if record.active
                    && let Some(binding) = record.binding
                {
                    validate_binding(&binding)?;
                    tenants.push(binding);
                }
            }
            tenants.sort_by(|a, b| {
                (&a.external_host, a.tenant.tenant_id.as_uuid())
                    .cmp(&(&b.external_host, b.tenant.tenant_id.as_uuid()))
            });
            return Ok(DirectoryControlOutcome::Describe(
                DirectoryDescribeOutcome { revision, tenants },
            ));
        }
    };
    if revision != expected {
        return Err(RepositoryError::Conflict);
    }
    let next = if let DirectoryControlAction::Create { provisioning, .. } = action {
        let TenantProvisioningRequest {
            binding,
            tenant,
            realm,
            organization,
        } = provisioning.as_ref();
        if tenant.id != binding.tenant.tenant_id
            || realm.id != binding.tenant.realm_id
            || organization.id != binding.tenant.organization_id
        {
            return Err(RepositoryError::Consistency(
                "provisioning boundaries do not match binding".into(),
            ));
        }
        if revision == 0 {
            ensure_default_boundaries(tx)?;
        }
        let tenant_id = tenant.id.as_uuid();
        ensure_tenant(tx, tenant_id, &tenant.slug, &tenant.display_name)?;
        bind_owner(
            tx,
            REALM_OWNER,
            realm.id.as_uuid(),
            tenant_id,
            &realm.slug,
            &realm.display_name,
        )?;
        bind_owner(
            tx,
            ORGANIZATION_OWNER,
            organization.id.as_uuid(),
            tenant_id,
            &organization.slug,
            &organization.display_name,
        )?;
        insert_binding(tx, binding, revision)?
    } else {
        let storage_key = key(TENANT, tenant.as_uuid(), &[]);
        let mut row: TenantRecord =
            read_tx(tx, &storage_key, true)?.ok_or(RepositoryError::NotFound)?;
        let binding = row.binding.as_mut().ok_or(RepositoryError::NotFound)?;
        let changed = match action {
            DirectoryControlAction::Update {
                issuer,
                external_host,
                ..
            } => {
                if binding.issuer == *issuer && binding.external_host == *external_host {
                    false
                } else {
                    let mut candidate = binding.clone();
                    candidate.issuer.clone_from(issuer);
                    candidate.external_host.clone_from(external_host);
                    validate_binding(&candidate)?;
                    bind_route(tx, external_host, tenant.as_uuid())?;
                    if binding.external_host != *external_host {
                        tx.delete(key(ROUTING, Uuid::nil(), binding.external_host.as_bytes()))
                            .map_err(map_error)?;
                    }
                    *binding = candidate;
                    true
                }
            }
            DirectoryControlAction::Disable { .. } => {
                let changed = row.active;
                row.active = false;
                changed
            }
            DirectoryControlAction::Reload { .. } => {
                binding.runtime_revision =
                    binding.runtime_revision.checked_add(1).ok_or_else(|| {
                        RepositoryError::Consistency("tenant runtime revision exhausted".into())
                    })?;
                true
            }
            DirectoryControlAction::Finalize { .. } => {
                tx.delete(key(ROUTING, Uuid::nil(), binding.external_host.as_bytes()))
                    .map_err(map_error)?;
                row.binding = None;
                true
            }
            _ => unreachable!(),
        };
        if changed {
            let next = revision
                .checked_add(1)
                .ok_or_else(|| RepositoryError::Consistency("tenant revision exhausted".into()))?;
            put(tx, &storage_key, &row)?;
            put(tx, &revision_key(), &next)?;
            next
        } else {
            revision
        }
    };
    Ok(DirectoryControlOutcome::Mutation(
        DirectoryMutationOutcome {
            action: operation_name(action).to_owned(),
            tenant_id: tenant.as_uuid().to_string(),
            previous_revision: revision,
            revision: next,
        },
    ))
}

impl TenantDirectoryControlPort for RocksDb {
    fn execute_control_operation<'a>(
        &'a self,
        frame: DirectoryControlFrame<'a>,
    ) -> BoxFuture<'a, Result<DirectoryControlOutcome, TenantDirectoryControlError>> {
        let deployment_id = frame.deployment_id.to_owned();
        let request_hash = frame.request_sha256.to_owned();
        let operation_id = Uuid::parse_str(frame.jti);
        let actor = frame.actor.clone();
        let action = frame.action;
        Box::pin(async move {
            let operation_id = operation_id.map_err(|_| TenantDirectoryControlError::Rejected)?;
            if request_hash.len() != 64
                || !request_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(TenantDirectoryControlError::Rejected);
            }
            self.run(move |db| {
                let tx = db.transaction();
                let storage_key = key(OUTCOME, Uuid::nil(), operation_id.as_bytes());
                let operation = operation_name(&action);
                if let Some(prior) = read_tx::<OperationOutcome>(&tx, &storage_key, true)? {
                    if prior.deployment_id != deployment_id
                        || prior.request_hash != request_hash
                        || prior.operation != operation
                    {
                        return Err(RepositoryError::Conflict);
                    }
                    return Ok(prior.outcome);
                }
                let outcome = apply_mutation(&tx, &action)?;
                let previous_revision = match &outcome {
                    DirectoryControlOutcome::Mutation(value) => value.previous_revision,
                    DirectoryControlOutcome::Describe(value) => value.revision,
                };
                let expected_revision = if matches!(action, DirectoryControlAction::Describe) {
                    0
                } else {
                    previous_revision
                };
                let mut payload = serde_json::json!({
                    "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                    "event_category": "tenant_directory",
                    "tenant_id": TenantContext::default_system().tenant_id.as_uuid(),
                    "deployment_id": deployment_id,
                    "jti": operation_id,
                    "request_sha256": request_hash,
                    "actor": actor,
                    "operation": operation,
                    "expected_revision": expected_revision,
                    "previous_revision": previous_revision,
                    "revision": outcome.revision(),
                });
                if let DirectoryControlOutcome::Mutation(value) = &outcome {
                    payload["tenant_id"] = serde_json::json!(value.tenant_id);
                }
                match &action {
                    DirectoryControlAction::Create { provisioning, .. } => {
                        payload["issuer"] = serde_json::json!(provisioning.binding.issuer);
                        payload["external_host"] =
                            serde_json::json!(provisioning.binding.external_host);
                    }
                    DirectoryControlAction::Update {
                        issuer,
                        external_host,
                        ..
                    } => {
                        payload["issuer"] = serde_json::json!(issuer);
                        payload["external_host"] = serde_json::json!(external_host);
                    }
                    _ => {}
                }
                crate::audit::append_in_tx(
                    &tx,
                    &nazo_persistence::SecurityAuditEvent {
                        event_id: Uuid::now_v7(),
                        event_type: format!("tenant_directory_{operation}"),
                        event_category: "tenant_directory".into(),
                        payload,
                        occurred_at: jiff::Timestamp::now(),
                    },
                )?;
                put(
                    &tx,
                    &storage_key,
                    &OperationOutcome {
                        deployment_id,
                        request_hash,
                        operation: operation.into(),
                        outcome: outcome.clone(),
                    },
                )?;
                tx.commit().map_err(map_error)?;
                Ok(outcome)
            })
            .await
            .map_err(|error| match error {
                RepositoryError::Conflict => TenantDirectoryControlError::Conflict,
                RepositoryError::NotFound
                | RepositoryError::Consistency(_)
                | RepositoryError::AlreadyProcessed => TenantDirectoryControlError::Rejected,
                _ => TenantDirectoryControlError::Unavailable,
            })
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/tenancy.rs"]
mod tests;
