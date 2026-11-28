//! The operator's bounded active manifest, resource changes, receipt and audit
//! share one transaction. Inactive user locators are kept separately so a
//! revoke/apply preserves the subject without growing the active manifest.

use std::{collections::BTreeSet, sync::Arc};

use futures_util::future::BoxFuture;
use jiff::Timestamp;
use nazo_identity::{TenantContext, TenantId, ports::RepositoryError};
use nazo_operator_protocol::{
    ControlResultData, Openid4vcTrustPolicy, TenantResourceIdentity, TenantResourceKind,
    TenantResourceMapping, TenantResourceSelector, canonical_tenant_resource_manifest_sha256,
    validate_control_result_data_for_wire, validate_openid4vc_trust_policy,
};
use nazo_persistence::{
    ClientTrustPolicy, Openid4vcTrustPolicyRecord, Openid4vcTrustPolicyStore,
    tenant_resources::{
        ControlTenantResourceFrame, PreparedMtlsTrustAnchor, PreparedOAuthClient,
        PreparedTenantResource, TenantResourceAction, TenantResourceExecutorError,
        TenantResourceExecutorPort, TenantResourcePayload, TenantResourcePreparation,
        TenantResourcePreparationError, UserProfileFields, empty_manifest_sha256, operation_name,
    },
};
use rocksdb::{SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    RocksDb,
    db::{key, map_error, put, read, read_snapshot, read_tx},
};

const STATE: u8 = 0xc0;
const OPERATION: u8 = 0xc6;
const TRUST_POLICY: u8 = 0xc7;
const CLIENT_POLICY: u8 = 0xc8;
const MANAGED_USER: u8 = 0xc9;
const MANAGED_CLIENT: u8 = 0xca;

type Execution<T> = Result<T, TenantResourceExecutorError>;

#[derive(Serialize, Deserialize)]
struct State {
    revision: u64,
    manifest: String,
    active: Vec<Binding>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            revision: 0,
            manifest: empty_manifest_sha256(),
            active: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Binding {
    identity: TenantResourceIdentity,
    locator: Locator,
    dependency: Option<TenantResourceSelector>,
}

#[derive(Serialize, Deserialize)]
enum Locator {
    User(Uuid),
    Client(Uuid),
    Mtls(Uuid),
    Dataset {
        subject: Uuid,
        configuration: String,
    },
    TrustPolicy(Uuid),
}

#[derive(Serialize, Deserialize)]
struct Outcome {
    deployment: String,
    tenant: Uuid,
    request_hash: String,
    operation: String,
    result: ControlResultData,
}

impl Outcome {
    fn replay(
        self,
        deployment: &str,
        tenant: Uuid,
        request_hash: &str,
        operation: TenantResourceAction,
    ) -> Execution<ControlResultData> {
        if self.deployment != deployment
            || self.tenant != tenant
            || self.request_hash != request_hash
            || self.operation != operation_name(operation)
        {
            return Err(TenantResourceExecutorError::Conflict);
        }
        validate_control_result_data_for_wire(&self.result)
            .map_err(|_| TenantResourceExecutorError::Unavailable)?;
        Ok(self.result)
    }
}

#[derive(Serialize, Deserialize)]
struct Policy {
    id: Uuid,
    resource: String,
    digest: String,
    material: Openid4vcTrustPolicy,
    active: bool,
}

#[derive(Serialize, Deserialize)]
struct PolicyBinding {
    policy_id: Uuid,
    resource: String,
    digest: String,
    active: bool,
}

impl Policy {
    fn record(self) -> Result<Openid4vcTrustPolicyRecord, RepositoryError> {
        validate_openid4vc_trust_policy(&self.material).map_err(|_| {
            RepositoryError::Consistency("invalid stored OpenID4VC trust policy".into())
        })?;
        Ok(Openid4vcTrustPolicyRecord {
            id: self.id,
            resource_id: self.resource,
            resource_digest: self.digest,
            material: self.material,
        })
    }
}

fn map_repository(error: RepositoryError) -> TenantResourceExecutorError {
    match error {
        RepositoryError::Conflict => TenantResourceExecutorError::Conflict,
        RepositoryError::AlreadyProcessed => TenantResourceExecutorError::Rejected,
        _ => TenantResourceExecutorError::Unavailable,
    }
}

fn map_preparation(error: TenantResourcePreparationError) -> TenantResourceExecutorError {
    match error {
        TenantResourcePreparationError::Rejected => TenantResourceExecutorError::Rejected,
        TenantResourcePreparationError::Unavailable => TenantResourceExecutorError::Unavailable,
    }
}

fn order(kind: TenantResourceKind) -> u8 {
    match kind {
        TenantResourceKind::User => 0,
        TenantResourceKind::OauthClient => 1,
        TenantResourceKind::MtlsTrustAnchor => 2,
        TenantResourceKind::Openid4vcDataset => 3,
        TenantResourceKind::Openid4vcTrustPolicy => 4,
    }
}

fn sorted(mut identities: Vec<TenantResourceIdentity>) -> Vec<TenantResourceIdentity> {
    identities
        .sort_by(|a, b| (order(a.kind), &a.resource_id).cmp(&(order(b.kind), &b.resource_id)));
    identities
}

fn find<'a>(state: &'a State, kind: TenantResourceKind, id: &str) -> Option<&'a Binding> {
    state
        .active
        .iter()
        .find(|binding| binding.identity.kind == kind && binding.identity.resource_id == id)
}

fn manifest(state: &State) -> Execution<String> {
    if state.active.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES {
        return Err(TenantResourceExecutorError::TooLarge);
    }
    canonical_tenant_resource_manifest_sha256(
        &state
            .active
            .iter()
            .map(|binding| binding.identity.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| TenantResourceExecutorError::Unavailable)
}

fn inactive_user_key(tenant: Uuid, resource: &str) -> Vec<u8> {
    let mut result = key(STATE, tenant, &[1]);
    result.extend_from_slice(resource.as_bytes());
    result
}

pub(crate) fn managed_user_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
) -> Result<bool, RepositoryError> {
    Ok(read_tx::<bool>(tx, &key(MANAGED_USER, tenant, id.as_bytes()), false)?.unwrap_or(false))
}

pub(crate) fn managed_client_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    id: Uuid,
) -> Result<bool, RepositoryError> {
    Ok(read_tx::<bool>(tx, &key(MANAGED_CLIENT, tenant, id.as_bytes()), false)?.unwrap_or(false))
}

pub(crate) fn trust_binding_current_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    id: Option<Uuid>,
    resource: Option<&str>,
    digest: Option<&str>,
) -> Result<bool, RepositoryError> {
    match (id, resource, digest) {
        (None, None, None) => Ok(true),
        (Some(id), Some(resource), Some(digest)) => Ok(read_tx::<Policy>(
            tx,
            &key(TRUST_POLICY, tenant, resource.as_bytes()),
            false,
        )?
        .is_some_and(|policy| policy.active && policy.id == id && policy.digest == digest)),
        _ => Ok(false),
    }
}

pub(crate) fn trust_binding_current_snapshot(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    id: Option<Uuid>,
    resource: Option<&str>,
    digest: Option<&str>,
) -> Result<bool, RepositoryError> {
    match (id, resource, digest) {
        (None, None, None) => Ok(true),
        (Some(id), Some(resource), Some(digest)) => Ok(read_snapshot::<Policy>(
            snapshot,
            &key(TRUST_POLICY, tenant, resource.as_bytes()),
        )?
        .is_some_and(|policy| policy.active && policy.id == id && policy.digest == digest)),
        _ => Ok(false),
    }
}

impl Openid4vcTrustPolicyStore for RocksDb {
    fn for_client<'a>(
        &'a self,
        tenant: Uuid,
        public_client_id: &'a str,
    ) -> BoxFuture<'a, Result<ClientTrustPolicy, RepositoryError>> {
        let public_client_id = public_client_id.to_owned();
        Box::pin(self.run(move |store| {
            let snapshot = store.db.snapshot();
            let Some(client) =
                crate::clients::public_id_snapshot(&snapshot, tenant, &public_client_id)?
            else {
                return Ok(ClientTrustPolicy::Unbound);
            };
            let Some(binding) = read_snapshot::<PolicyBinding>(
                &snapshot,
                &key(CLIENT_POLICY, tenant, client.id.as_bytes()),
            )?
            else {
                return Ok(ClientTrustPolicy::Unbound);
            };
            if !client.is_active || !binding.active {
                return Ok(ClientTrustPolicy::BoundInactive);
            }
            match read_snapshot::<Policy>(
                &snapshot,
                &key(TRUST_POLICY, tenant, binding.resource.as_bytes()),
            )?
            .filter(|policy| {
                policy.active && policy.id == binding.policy_id && policy.digest == binding.digest
            }) {
                Some(policy) => Ok(ClientTrustPolicy::Active(Box::new(policy.record()?))),
                None => Ok(ClientTrustPolicy::BoundInactive),
            }
        }))
    }

    fn active_for_origin<'a>(
        &'a self,
        tenant: Uuid,
        resource: &'a str,
        wallet_origin: &'a str,
        expected_digest: &'a str,
    ) -> BoxFuture<'a, Result<Option<Openid4vcTrustPolicyRecord>, RepositoryError>> {
        let (resource, wallet_origin, expected_digest) = (
            resource.to_owned(),
            wallet_origin.to_owned(),
            expected_digest.to_owned(),
        );
        Box::pin(self.run(move |store| {
            if wallet_origin.len() > 2048
                || wallet_origin != wallet_origin.trim()
                || !wallet_origin.starts_with("https://")
                || wallet_origin.chars().any(char::is_control)
            {
                return Err(RepositoryError::Consistency("invalid wallet origin".into()));
            }
            read::<Policy>(&store.db, &key(TRUST_POLICY, tenant, resource.as_bytes()))?
                .filter(|policy| {
                    policy.active
                        && policy.digest == expected_digest
                        && policy
                            .material
                            .wallet_authorization_origins
                            .contains(&wallet_origin)
                })
                .map(Policy::record)
                .transpose()
        }))
    }
}

/// Native operator execution over the same database transaction boundary as
/// required security evidence and durable replay receipts.
pub struct RocksDbTenantResourceExecutor {
    store: RocksDb,
    tenant: TenantContext,
    data_key: Option<[u8; 32]>,
    preparation: Option<Arc<dyn TenantResourcePreparation>>,
}

struct Prepared {
    identity: TenantResourceIdentity,
    payload: Payload,
}

enum Payload {
    User {
        username: String,
        email: String,
        password_hash: String,
        email_verified: bool,
        profile: Box<UserProfileFields>,
    },
    Client {
        material: Box<PreparedOAuthClient>,
        policy: Option<String>,
    },
    Mtls {
        client: String,
        material: PreparedMtlsTrustAnchor,
    },
    Dataset {
        user: String,
        configuration: String,
        claims: Value,
    },
    TrustPolicy(Box<Openid4vcTrustPolicy>),
}

impl Prepared {
    fn dependency(&self) -> Option<TenantResourceSelector> {
        let (kind, resource) = match &self.payload {
            Payload::Client {
                policy: Some(policy),
                ..
            } => (TenantResourceKind::Openid4vcTrustPolicy, policy),
            Payload::Mtls { client, .. } => (TenantResourceKind::OauthClient, client),
            Payload::Dataset { user, .. } => (TenantResourceKind::User, user),
            _ => return None,
        };
        Some(TenantResourceSelector {
            kind,
            resource_id: resource.clone(),
        })
    }
}

impl RocksDbTenantResourceExecutor {
    #[must_use]
    pub fn new(
        store: RocksDb,
        tenant: TenantContext,
        data_key: Option<[u8; 32]>,
        preparation: Option<Arc<dyn TenantResourcePreparation>>,
    ) -> Self {
        Self {
            store,
            tenant,
            data_key,
            preparation,
        }
    }

    async fn prepare(&self, resources: Vec<PreparedTenantResource>) -> Execution<Vec<Prepared>> {
        let preparation = self
            .preparation
            .as_ref()
            .ok_or(TenantResourceExecutorError::Rejected)?;
        let mut result = Vec::with_capacity(resources.len());
        for resource in resources {
            let payload = match resource
                .payload
                .ok_or(TenantResourceExecutorError::Rejected)?
            {
                TenantResourcePayload::User(user) => Payload::User {
                    username: user.username,
                    email: user.email,
                    password_hash: preparation
                        .hash_user_password(user.password)
                        .await
                        .map_err(map_preparation)?,
                    email_verified: user.email_verified,
                    profile: Box::new(user.profile),
                },
                TenantResourcePayload::OauthClient(client) => Payload::Client {
                    material: Box::new(
                        preparation
                            .prepare_oauth_client(
                                client.request,
                                client.supplied_secret,
                                self.tenant,
                            )
                            .await
                            .map_err(map_preparation)?,
                    ),
                    policy: client.trust_policy_resource_id,
                },
                TenantResourcePayload::MtlsTrustAnchor(anchor) => Payload::Mtls {
                    client: anchor.client_resource_id,
                    material: preparation
                        .prepare_mtls_trust_anchor(anchor.certificate_pem)
                        .await
                        .map_err(map_preparation)?,
                },
                TenantResourcePayload::Openid4vcDataset(dataset) => Payload::Dataset {
                    user: dataset.user_resource_id,
                    configuration: dataset.configuration_id,
                    claims: dataset.claims,
                },
                TenantResourcePayload::Openid4vcTrustPolicy(policy) => {
                    Payload::TrustPolicy(Box::new(policy.public_material))
                }
            };
            result.push(Prepared {
                identity: resource.identity,
                payload,
            });
        }
        result.sort_by(|a, b| {
            (order(a.identity.kind), &a.identity.resource_id)
                .cmp(&(order(b.identity.kind), &b.identity.resource_id))
        });
        Ok(result)
    }
}

impl RocksDb {
    pub async fn tenant_resource_control_outcome(
        &self,
        tenant: TenantId,
        deployment: &str,
        operation_id: Uuid,
        request_hash: &str,
        operation: TenantResourceAction,
    ) -> Execution<Option<ControlResultData>> {
        let (deployment, request_hash) = (deployment.to_owned(), request_hash.to_owned());
        self.run(move |store| {
            Ok(read::<Outcome>(
                &store.db,
                &key(OPERATION, Uuid::nil(), operation_id.as_bytes()),
            )?
            .map(|outcome| outcome.replay(&deployment, tenant.as_uuid(), &request_hash, operation))
            .transpose())
        })
        .await
        .map_err(map_repository)?
    }
}

impl TenantResourceExecutorPort for RocksDbTenantResourceExecutor {
    fn execute_control_operation<'a>(
        &'a self,
        frame: ControlTenantResourceFrame<'a>,
    ) -> BoxFuture<'a, Execution<ControlResultData>> {
        Box::pin(async move {
            if frame.tenant_id != self.tenant.tenant_id.as_uuid().to_string()
                || frame.request_sha256.len() != 64
                || !frame
                    .request_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(TenantResourceExecutorError::Rejected);
            }
            let operation_id =
                Uuid::parse_str(frame.jti).map_err(|_| TenantResourceExecutorError::Rejected)?;
            if let Some(outcome) = self
                .store
                .tenant_resource_control_outcome(
                    self.tenant.tenant_id,
                    frame.deployment_id,
                    operation_id,
                    frame.request_sha256,
                    frame.operation,
                )
                .await?
            {
                return Ok(outcome);
            }
            let identities = sorted(
                frame
                    .resources
                    .iter()
                    .map(|resource| resource.identity.clone())
                    .collect(),
            );
            let payloads = if frame.operation == TenantResourceAction::Apply {
                self.prepare(frame.resources).await?
            } else {
                Vec::new()
            };
            let (deployment, request_hash, actor, selectors) = (
                frame.deployment_id.to_owned(),
                frame.request_sha256.to_owned(),
                frame.actor.clone(),
                frame.selectors.to_owned(),
            );
            let tenant = self.tenant;
            let data_key = self.data_key;
            let operation = frame.operation;
            self.store
                .run(move |store| {
                    Ok((|| {
                        let tx = store.transaction();
                        let tenant_id = tenant.tenant_id.as_uuid();
                        let operation_key = key(OPERATION, Uuid::nil(), operation_id.as_bytes());
                        if let Some(outcome) =
                            read_tx::<Outcome>(&tx, &operation_key, true).map_err(map_repository)?
                        {
                            return outcome.replay(
                                &deployment,
                                tenant_id,
                                &request_hash,
                                operation,
                            );
                        }
                        if crate::tenancy::active_context_tx(&tx, tenant.tenant_id)
                            .map_err(map_repository)?
                            != Some(tenant)
                        {
                            return Err(TenantResourceExecutorError::Rejected);
                        }
                        let state_key = key(STATE, tenant_id, &[]);
                        let mut state = read_tx::<State>(&tx, &state_key, true)
                            .map_err(map_repository)?
                            .unwrap_or_default();
                        if manifest(&state)? != state.manifest {
                            return Err(TenantResourceExecutorError::Unavailable);
                        }
                        let previous_revision = state.revision;
                        let result = match operation {
                            TenantResourceAction::Apply => {
                                let mappings =
                                    apply(&tx, tenant, &mut state, payloads, data_key.as_ref())?;
                                state.revision = state
                                    .revision
                                    .checked_add(1)
                                    .ok_or(TenantResourceExecutorError::Unavailable)?;
                                state.manifest = manifest(&state)?;
                                ControlResultData::TenantResourceApply {
                                    revision: state.revision,
                                    resources: identities,
                                    resource_mappings: mappings,
                                    resource_manifest_sha256: state.manifest.clone(),
                                }
                            }
                            TenantResourceAction::Revoke => {
                                revoke(&tx, tenant, &mut state, &identities)?;
                                state.revision = state
                                    .revision
                                    .checked_add(1)
                                    .ok_or(TenantResourceExecutorError::Unavailable)?;
                                state.manifest = manifest(&state)?;
                                ControlResultData::TenantResourceRevoke {
                                    revision: state.revision,
                                    resources: identities,
                                    resource_manifest_sha256: state.manifest.clone(),
                                }
                            }
                            TenantResourceAction::Enumerate => {
                                let resources = sorted(
                                    state
                                        .active
                                        .iter()
                                        .filter(|binding| {
                                            selectors.is_empty()
                                                || selectors.iter().any(|selector| {
                                                    selector.kind == binding.identity.kind
                                                        && selector.resource_id
                                                            == binding.identity.resource_id
                                                })
                                        })
                                        .map(|binding| binding.identity.clone())
                                        .collect(),
                                );
                                ControlResultData::TenantResourceEnumerate {
                                    revision: state.revision,
                                    resources,
                                    resource_manifest_sha256: state.manifest.clone(),
                                }
                            }
                        };
                        validate_control_result_data_for_wire(&result).map_err(|error| {
                            if matches!(error, nazo_operator_protocol::ProtocolError::TooLarge) {
                                TenantResourceExecutorError::TooLarge
                            } else {
                                TenantResourceExecutorError::Rejected
                            }
                        })?;
                        let resources = match &result {
                            ControlResultData::TenantResourceApply { resources, .. }
                            | ControlResultData::TenantResourceRevoke { resources, .. }
                            | ControlResultData::TenantResourceEnumerate { resources, .. } => {
                                resources
                            }
                            _ => unreachable!(),
                        };
                        crate::audit::append_in_tx(
                            &tx,
                            &nazo_persistence::SecurityAuditEvent {
                                event_id: Uuid::now_v7(),
                                event_type: format!(
                                    "tenant_resource_{}",
                                    operation_name(operation)
                                ),
                                event_category: "tenant_resource".into(),
                                occurred_at: Timestamp::now(),
                                payload: serde_json::json!({
                                    "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                                    "event_category": "tenant_resource",
                                    "deployment_id": deployment,
                                    "tenant_id": tenant_id,
                                    "jti": operation_id,
                                    "request_sha256": request_hash,
                                    "actor": actor,
                                    "operation": operation_name(operation),
                                    "expected_revision": previous_revision,
                                    "resource_manifest_sha256": state.manifest,
                                    "resources": resources
                                }),
                            },
                        )
                        .map_err(map_repository)?;
                        if operation != TenantResourceAction::Enumerate {
                            put(&tx, &state_key, &state).map_err(map_repository)?;
                        }
                        let outcome = Outcome {
                            deployment,
                            tenant: tenant_id,
                            request_hash,
                            operation: operation_name(operation).into(),
                            result,
                        };
                        put(&tx, &operation_key, &outcome).map_err(map_repository)?;
                        tx.commit().map_err(map_error).map_err(map_repository)?;
                        Ok(outcome.result)
                    })())
                })
                .await
                .map_err(map_repository)?
        })
    }
}

fn apply(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantContext,
    state: &mut State,
    payloads: Vec<Prepared>,
    data_key: Option<&[u8; 32]>,
) -> Execution<Vec<TenantResourceMapping>> {
    let tenant_id = tenant.tenant_id.as_uuid();
    let mut available = state
        .active
        .iter()
        .map(|binding| (binding.identity.kind, binding.identity.resource_id.as_str()))
        .collect::<BTreeSet<_>>();
    for prepared in &payloads {
        if !available.insert((prepared.identity.kind, &prepared.identity.resource_id))
            && find(
                state,
                prepared.identity.kind,
                &prepared.identity.resource_id,
            )
            .is_none()
        {
            return Err(TenantResourceExecutorError::Rejected);
        }
        if find(
            state,
            prepared.identity.kind,
            &prepared.identity.resource_id,
        )
        .is_some_and(|binding| binding.identity.digest != prepared.identity.digest)
        {
            return Err(TenantResourceExecutorError::Conflict);
        }
    }
    for prepared in &payloads {
        if let Some(dependency) = prepared.dependency()
            && !available.contains(&(dependency.kind, dependency.resource_id.as_str()))
        {
            return Err(TenantResourceExecutorError::Rejected);
        }
    }
    if available.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES {
        return Err(TenantResourceExecutorError::TooLarge);
    }
    drop(available);
    let mut mappings = Vec::new();
    let mut client_policies = Vec::new();
    for prepared in payloads {
        let identity = prepared.identity;
        if let Some(binding) = find(state, identity.kind, &identity.resource_id) {
            if let Some(mapping) = mapping(tx, tenant_id, binding)? {
                mappings.push(mapping);
            }
            continue;
        }
        let dependency = match &prepared.payload {
            Payload::Client {
                policy: Some(policy),
                ..
            } => Some(TenantResourceSelector {
                kind: TenantResourceKind::Openid4vcTrustPolicy,
                resource_id: policy.clone(),
            }),
            Payload::Mtls { client, .. } => Some(TenantResourceSelector {
                kind: TenantResourceKind::OauthClient,
                resource_id: client.clone(),
            }),
            Payload::Dataset { user, .. } => Some(TenantResourceSelector {
                kind: TenantResourceKind::User,
                resource_id: user.clone(),
            }),
            _ => None,
        };
        let locator = match prepared.payload {
            Payload::User {
                username,
                email,
                password_hash,
                email_verified,
                profile,
            } => {
                if identity.kind != TenantResourceKind::User {
                    return Err(TenantResourceExecutorError::Rejected);
                }
                let previous = read_tx::<Uuid>(
                    tx,
                    &inactive_user_key(tenant_id, &identity.resource_id),
                    true,
                )
                .map_err(map_repository)?;
                if let Some(id) = previous {
                    read_tx::<bool>(tx, &key(MANAGED_USER, tenant_id, id.as_bytes()), true)
                        .map_err(map_repository)?;
                }
                let id = crate::users::write_managed_user_tx(
                    tx,
                    tenant,
                    previous,
                    &username,
                    &email,
                    &password_hash,
                    email_verified,
                    &profile,
                )
                .map_err(map_repository)?;
                put(tx, &key(MANAGED_USER, tenant_id, id.as_bytes()), &true)
                    .map_err(map_repository)?;
                tx.delete(inactive_user_key(tenant_id, &identity.resource_id))
                    .map_err(map_error)
                    .map_err(map_repository)?;
                Locator::User(id)
            }
            Payload::Client { material, policy } => {
                if identity.kind != TenantResourceKind::OauthClient
                    || crate::clients::context(&material.client).map_err(map_repository)? != tenant
                {
                    return Err(TenantResourceExecutorError::Rejected);
                }
                let id = material.client.id;
                read_tx::<bool>(tx, &key(MANAGED_CLIENT, tenant_id, id.as_bytes()), true)
                    .map_err(map_repository)?;
                crate::clients::insert_client_tx(
                    tx,
                    &material.client,
                    material.client_secret_hash.as_deref(),
                    None,
                    0,
                )
                .map_err(map_repository)?;
                put(tx, &key(MANAGED_CLIENT, tenant_id, id.as_bytes()), &true)
                    .map_err(map_repository)?;
                if let Some(policy) = policy {
                    client_policies.push((id, policy));
                }
                Locator::Client(id)
            }
            Payload::Mtls { client, material } => {
                if identity.kind != TenantResourceKind::MtlsTrustAnchor {
                    return Err(TenantResourceExecutorError::Rejected);
                }
                let Some(Binding {
                    locator: Locator::Client(client),
                    ..
                }) = find(state, TenantResourceKind::OauthClient, &client)
                else {
                    return Err(TenantResourceExecutorError::Rejected);
                };
                Locator::Mtls(
                    crate::mtls::insert_managed_tx(tx, tenant_id, *client, material)
                        .map_err(map_repository)?,
                )
            }
            Payload::Dataset {
                user,
                configuration,
                claims,
            } => {
                if identity.kind != TenantResourceKind::Openid4vcDataset {
                    return Err(TenantResourceExecutorError::Rejected);
                }
                let Some(Binding {
                    locator: Locator::User(subject),
                    ..
                }) = find(state, TenantResourceKind::User, &user)
                else {
                    return Err(TenantResourceExecutorError::Rejected);
                };
                let subject = *subject;
                if state.active.iter().any(|binding| {
                    matches!(&binding.locator, Locator::Dataset { subject: owner, configuration: config }
                        if *owner == subject && config == &configuration)
                }) {
                    return Err(TenantResourceExecutorError::Conflict);
                }
                crate::digital_credentials::datasets::write_managed_dataset_tx(
                    tx,
                    data_key.ok_or(TenantResourceExecutorError::Unavailable)?,
                    tenant,
                    subject,
                    &configuration,
                    &claims,
                    Timestamp::now(),
                    None,
                    "operator_control",
                )
                .map_err(map_repository)?;
                Locator::Dataset {
                    subject,
                    configuration,
                }
            }
            Payload::TrustPolicy(material) => {
                if identity.kind != TenantResourceKind::Openid4vcTrustPolicy {
                    return Err(TenantResourceExecutorError::Rejected);
                }
                validate_openid4vc_trust_policy(&material)
                    .map_err(|_| TenantResourceExecutorError::Rejected)?;
                let storage_key = key(TRUST_POLICY, tenant_id, identity.resource_id.as_bytes());
                if read_tx::<Policy>(tx, &storage_key, true)
                    .map_err(map_repository)?
                    .is_some_and(|policy| policy.active)
                {
                    return Err(TenantResourceExecutorError::Conflict);
                }
                let id = Uuid::now_v7();
                put(
                    tx,
                    &storage_key,
                    &Policy {
                        id,
                        resource: identity.resource_id.clone(),
                        digest: identity.digest.clone(),
                        material: *material,
                        active: true,
                    },
                )
                .map_err(map_repository)?;
                Locator::TrustPolicy(id)
            }
        };
        let binding = Binding {
            identity,
            locator,
            dependency,
        };
        if let Some(mapping) = mapping(tx, tenant_id, &binding)? {
            mappings.push(mapping);
        }
        state.active.push(binding);
    }
    for (client, resource) in client_policies {
        let Some(Binding {
            locator: Locator::TrustPolicy(policy_id),
            identity,
            ..
        }) = find(state, TenantResourceKind::Openid4vcTrustPolicy, &resource)
        else {
            return Err(TenantResourceExecutorError::Rejected);
        };
        put(
            tx,
            &key(CLIENT_POLICY, tenant_id, client.as_bytes()),
            &PolicyBinding {
                policy_id: *policy_id,
                resource,
                digest: identity.digest.clone(),
                active: true,
            },
        )
        .map_err(map_repository)?;
    }
    Ok(mappings)
}

fn mapping(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    binding: &Binding,
) -> Execution<Option<TenantResourceMapping>> {
    let public_id = match binding.locator {
        Locator::User(id) => id.to_string(),
        Locator::Client(id) => crate::clients::read_client_tx(tx, tenant, id, false)
            .map_err(map_repository)?
            .filter(|client| client.is_active)
            .ok_or(TenantResourceExecutorError::Rejected)?
            .client_id
            .clone(),
        _ => return Ok(None),
    };
    Ok(Some(TenantResourceMapping {
        kind: binding.identity.kind,
        resource_id: binding.identity.resource_id.clone(),
        public_id,
    }))
}

fn revoke(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantContext,
    state: &mut State,
    identities: &[TenantResourceIdentity],
) -> Execution<()> {
    let tenant_id = tenant.tenant_id.as_uuid();
    let targets = identities
        .iter()
        .map(|identity| (identity.kind, identity.resource_id.as_str()))
        .collect::<BTreeSet<_>>();
    for identity in identities {
        if !find(state, identity.kind, &identity.resource_id)
            .is_some_and(|binding| binding.identity.digest == identity.digest)
        {
            return Err(TenantResourceExecutorError::Conflict);
        }
    }
    if state.active.iter().any(|binding| {
        !targets.contains(&(binding.identity.kind, binding.identity.resource_id.as_str()))
            && binding.dependency.as_ref().is_some_and(|dependency| {
                targets.contains(&(dependency.kind, dependency.resource_id.as_str()))
            })
    }) {
        return Err(TenantResourceExecutorError::Rejected);
    }
    for identity in identities.iter().rev() {
        let binding = find(state, identity.kind, &identity.resource_id)
            .ok_or(TenantResourceExecutorError::Conflict)?;
        let changed = match &binding.locator {
            Locator::User(id) => {
                read_tx::<bool>(tx, &key(MANAGED_USER, tenant_id, id.as_bytes()), true)
                    .map_err(map_repository)?;
                let changed =
                    crate::users::disable_user_tx(tx, tenant_id, *id).map_err(map_repository)?;
                tx.delete(key(MANAGED_USER, tenant_id, id.as_bytes()))
                    .map_err(map_error)
                    .map_err(map_repository)?;
                put(tx, &inactive_user_key(tenant_id, &identity.resource_id), id)
                    .map_err(map_repository)?;
                changed
            }
            Locator::Client(id) => {
                read_tx::<bool>(tx, &key(MANAGED_CLIENT, tenant_id, id.as_bytes()), true)
                    .map_err(map_repository)?;
                let changed = crate::clients::disable_client_tx(tx, tenant_id, *id)
                    .map_err(map_repository)?;
                let policy_key = key(CLIENT_POLICY, tenant_id, id.as_bytes());
                if let Some(mut binding) =
                    read_tx::<PolicyBinding>(tx, &policy_key, true).map_err(map_repository)?
                {
                    binding.active = false;
                    put(tx, &policy_key, &binding).map_err(map_repository)?;
                }
                tx.delete(key(MANAGED_CLIENT, tenant_id, id.as_bytes()))
                    .map_err(map_error)
                    .map_err(map_repository)?;
                changed
            }
            Locator::Mtls(id) => {
                crate::mtls::revoke_managed_tx(tx, tenant_id, *id).map_err(map_repository)?
            }
            Locator::Dataset {
                subject,
                configuration,
            } => crate::digital_credentials::datasets::remove_managed_dataset_tx(
                tx,
                tenant_id,
                *subject,
                configuration,
                "operator_control",
            )
            .map_err(map_repository)?,
            Locator::TrustPolicy(id) => {
                let storage_key = key(TRUST_POLICY, tenant_id, identity.resource_id.as_bytes());
                let mut policy = read_tx::<Policy>(tx, &storage_key, true)
                    .map_err(map_repository)?
                    .filter(|policy| {
                        policy.active && policy.id == *id && policy.digest == identity.digest
                    })
                    .ok_or(TenantResourceExecutorError::Conflict)?;
                policy.active = false;
                put(tx, &storage_key, &policy).map_err(map_repository)?;
                true
            }
        };
        if !changed {
            return Err(TenantResourceExecutorError::Rejected);
        }
    }
    state.active.retain(|binding| {
        !targets.contains(&(binding.identity.kind, binding.identity.resource_id.as_str()))
    });
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/tenant_resources.rs"]
mod tests;
