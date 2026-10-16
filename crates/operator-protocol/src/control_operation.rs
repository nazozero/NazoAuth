//! The frozen cross-process control-plane contract (E01/E02).
//!
//! One [`ControlOperation`] per top-level NazoAuth application-level
//! operation, signed once with the instance Controller Key; one plain
//! [`ControlResult`] journal entry as the durable outcome record.  There are
//! deliberately no receipt chains, capability suites, or multi-envelope
//! patterns here.  Per 05 §2 the envelope carries no `iss`, `aud`, `actor`,
//! `iat`, `nbf`, or `exp`: replay protection, response-loss recovery, and
//! crash recovery are owned by `operation_id` + request hash + the server-side
//! operation journal (accept-once before any side effect, §4), and Controller
//! Key validity is evaluated exactly once, at first accept (§5).  After
//! acceptance the journal owns authorization; later key expiry never retracts
//! an accepted operation.
//!
//! # Typed result data (H07)
//!
//! [`ControlResult`] carries an optional closed [`ControlResultData`]
//! channel (05 §8 `result?`).  It is the only way operation output reaches
//! ctl: engines' richer return values have no other wire representation.  The
//! request contract itself is unchanged by this extension — every golden
//! request vector stays byte-stable.
//!
//! # Canonical bytes (E02)
//!
//! The canonical encoding of a value is: serialize to JSON, recursively
//! rewrite every object so its members are sorted by UTF-8 key order, then
//! emit compact UTF-8 JSON (no whitespace, minimal number/escape forms).
//!
//! * `request_hash` = lowercase hexadecimal SHA-256 of exactly those canonical
//!   payload bytes.  It is an equality/idempotency token only; it never carries
//!   identity.
//! * Signatures are Ed25519 over `<base64url(header)>.<base64url(canonical
//!   payload)>` with a fixed protected header (`alg`, derived `kid`, fixed
//!   `typ`).  Callers cannot choose algorithm or media type.
//! * Signature and idempotency therefore share one canonical payload
//!   definition while remaining separate responsibilities.  Verifiers reject
//!   any payload that is not canonically encoded.
//!
//! The controller key id (`kid`) is `base64url(SHA-256(raw public key
//! bytes))`, unpadded (43 characters); see [`controller_key_id`].

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_crypto::ed25519::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::verification::{
    validate_file_identifier, validate_identifier, validate_lower_hex, validate_uuid,
};
use crate::wire::{
    FixedAlgorithm, ProtectedHeader, TenantResourceIdentity, TenantResourceMapping,
    TenantResourceSelector,
};
use crate::{MAX_COMPACT_JWS_BYTES, MAX_TENANT_RESOURCE_IDENTITIES, ProtocolError};

/// Wire schema tag for [`ControlOperation`].
pub const CONTROL_OPERATION_SCHEMA: u32 = 3;
/// Wire schema tag for [`ControlResult`].
pub const CONTROL_RESULT_SCHEMA: u32 = 2;
/// Fixed JWS media type for signed control operations.  Not caller-chosen.
pub const CONTROL_OPERATION_JWS_TYPE: &str = "nazoauth-control-operation+jwt";
/// Maximum canonical [`ControlOperation`] payload size in bytes.
pub const MAX_CONTROL_OPERATION_BYTES: usize = 64 * 1024;
/// Maximum serialized [`ControlResult`] size in bytes.
pub const MAX_CONTROL_RESULT_BYTES: usize = 64 * 1024;
/// Unpadded base64url length of a 32-byte SHA-256 digest.
const CONTROLLER_KID_LENGTH: usize = 43;

/// The single signed envelope for one top-level application-level operation
/// (05 §2).  The field set is closed and exhaustive:
/// `schema`, `operation_id`, `kid`, `deployment_id`, `config_revision`,
/// `operation`.
///
/// `operation_id` is a UUIDv7 and doubles as the journal idempotency key:
/// same id + same request hash resumes or returns the recorded outcome; same
/// id + different request hash is a permanent conflict (E03).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlOperation {
    pub schema: u32,
    /// UUIDv7 (RFC 9562), canonical lowercase form; also the journal jti.
    pub operation_id: String,
    /// Issuing controller key id ([`controller_key_id`] derivation).
    pub kid: String,
    /// Audience binding: exactly one target deployment.
    pub deployment_id: String,
    /// Opaque configuration revision of the deployment state this operation
    /// was constructed against. Carried verbatim into the operation journal
    /// and compared with the deployment's current revision before admission.
    pub config_revision: String,
    /// Closed operation set with typed payloads.  Unknown operations are a
    /// protocol change and must be rejected by older consumers.
    pub operation: ControlOperationPayload,
}

/// Closed operation names seeded from E05's naming, each carrying its typed
/// payload inline.  No arbitrary command/shell passthrough exists.
///
/// Deserialization is deliberately hand-written instead of derived: serde's
/// `deny_unknown_fields` is silently ignored for internally tagged enums with
/// unit variants, so a derived implementation would accept (and drop) unknown
/// members such as `{"name":"migrate-apply","argv":[...]}`.  The manual
/// implementation below rejects every member outside the variant's closed
/// field set, keeping the wire shape exactly as strict as every other type
/// in this contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "name", rename_all = "kebab-case")]
pub enum ControlOperationPayload {
    MigrateApply,
    KeysList,
    KeysValidate,
    KeysGenerateLocal {
        alg: String,
        purposes: Vec<String>,
    },
    TenantKeysGenerateLocal {
        tenant_id: String,
        alg: String,
        purposes: Vec<String>,
    },
    KeysRegisterExternal {
        kid: String,
        alg: String,
        key_ref: String,
        public_jwk_sha256: String,
    },
    /// Apply externally described tenant resources.  Field vocabulary reuses
    /// the existing [`TenantResourceIdentity`] wire types; capability-matrix
    /// concepts stay deleted per A04 §2.
    TenantResourceApply {
        /// Canonical UUID of the tenant scope.
        tenant_id: String,
        resources: Vec<TenantResourceIdentity>,
    },
    /// Enumerate tenant resources, optionally narrowed by typed selectors.
    /// An empty selector list lists every resource in the tenant scope.
    TenantResourceEnumerate {
        tenant_id: String,
        selectors: Vec<TenantResourceSelector>,
    },
    /// Revoke previously applied tenant resources.
    TenantResourceRevoke {
        tenant_id: String,
        resources: Vec<TenantResourceIdentity>,
    },
    /// Invalidate pre-restore protocol state after a candidate has started
    /// with the signed Valkey state epoch. This never accepts arbitrary
    /// recovery commands or a second authority channel.
    RecoveryInvalidate {
        state_epoch: String,
    },
    /// Provision one tenant boundary and its canonical routing binding at the
    /// caller's expected directory revision. Identical replays are bounded
    /// no-ops; the authoritative directory rejects conflicting inputs.
    TenantDirectoryCreate {
        expected_revision: u64,
        tenant: ControlTenantBoundary,
        realm: ControlTenantBoundary,
        organization: ControlTenantBoundary,
        issuer: String,
        external_host: String,
    },
    /// Update the canonical issuer/host of one routed tenant.
    TenantDirectoryUpdate {
        expected_revision: u64,
        tenant_id: String,
        issuer: String,
        external_host: String,
    },
    /// Suspend one routed tenant: new requests stop resolving while data and
    /// audit history are preserved for recovery.
    TenantDirectoryDisable {
        expected_revision: u64,
        tenant_id: String,
    },
    /// Rebuild one tenant from its deterministic local material paths.
    TenantDirectoryReload {
        expected_revision: u64,
        tenant_id: String,
    },
    /// Remove one routed tenant's binding after dependency cleanup. Replays
    /// after the tenant row is deleted are idempotent no-ops.
    TenantDirectoryFinalize {
        expected_revision: u64,
        tenant_id: String,
    },
    /// Read the authoritative directory: the current revision and every
    /// active binding. Read-only; the outcome ledger still records the
    /// replay-safe result.
    TenantDirectoryDescribe,
}

/// One identity boundary row of a directory create operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTenantBoundary {
    pub id: String,
    pub slug: String,
    pub display_name: String,
}

/// One active binding of a directory describe result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlTenantDirectoryBinding {
    pub tenant_id: String,
    pub realm_id: String,
    pub organization_id: String,
    pub runtime_revision: u64,
    pub issuer: String,
    pub external_host: String,
}

impl<'de> Deserialize<'de> for ControlOperationPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut members = match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::Object(members) => members,
            _ => return Err(serde::de::Error::custom("operation must be a JSON object")),
        };
        let name: String = take_member(&mut members, "name").map_err(serde::de::Error::custom)?;
        let payload = match name.as_str() {
            "migrate-apply" => ControlOperationPayload::MigrateApply,
            "keys-list" => ControlOperationPayload::KeysList,
            "keys-validate" => ControlOperationPayload::KeysValidate,
            "keys-generate-local" => {
                let alg = take_member(&mut members, "alg").map_err(serde::de::Error::custom)?;
                let purposes =
                    take_member(&mut members, "purposes").map_err(serde::de::Error::custom)?;
                ControlOperationPayload::KeysGenerateLocal { alg, purposes }
            }
            "tenant-keys-generate-local" => {
                let tenant_id =
                    take_member(&mut members, "tenant_id").map_err(serde::de::Error::custom)?;
                let alg = take_member(&mut members, "alg").map_err(serde::de::Error::custom)?;
                let purposes =
                    take_member(&mut members, "purposes").map_err(serde::de::Error::custom)?;
                ControlOperationPayload::TenantKeysGenerateLocal {
                    tenant_id,
                    alg,
                    purposes,
                }
            }
            "keys-register-external" => {
                let kid = take_member(&mut members, "kid").map_err(serde::de::Error::custom)?;
                let alg = take_member(&mut members, "alg").map_err(serde::de::Error::custom)?;
                let key_ref =
                    take_member(&mut members, "key_ref").map_err(serde::de::Error::custom)?;
                let public_jwk_sha256 = take_member(&mut members, "public_jwk_sha256")
                    .map_err(serde::de::Error::custom)?;
                ControlOperationPayload::KeysRegisterExternal {
                    kid,
                    alg,
                    key_ref,
                    public_jwk_sha256,
                }
            }
            "tenant-resource-apply" | "tenant-resource-revoke" => {
                let tenant_id =
                    take_member(&mut members, "tenant_id").map_err(serde::de::Error::custom)?;
                let resources =
                    take_member(&mut members, "resources").map_err(serde::de::Error::custom)?;
                if name == "tenant-resource-apply" {
                    ControlOperationPayload::TenantResourceApply {
                        tenant_id,
                        resources,
                    }
                } else {
                    ControlOperationPayload::TenantResourceRevoke {
                        tenant_id,
                        resources,
                    }
                }
            }
            "tenant-resource-enumerate" => {
                let tenant_id =
                    take_member(&mut members, "tenant_id").map_err(serde::de::Error::custom)?;
                let selectors =
                    take_member(&mut members, "selectors").map_err(serde::de::Error::custom)?;
                ControlOperationPayload::TenantResourceEnumerate {
                    tenant_id,
                    selectors,
                }
            }
            "recovery-invalidate" => ControlOperationPayload::RecoveryInvalidate {
                state_epoch: take_member(&mut members, "state_epoch")
                    .map_err(serde::de::Error::custom)?,
            },
            "tenant-directory-create" => {
                let expected_revision = take_member(&mut members, "expected_revision")
                    .map_err(serde::de::Error::custom)?;
                let tenant =
                    take_member(&mut members, "tenant").map_err(serde::de::Error::custom)?;
                let realm = take_member(&mut members, "realm").map_err(serde::de::Error::custom)?;
                let organization =
                    take_member(&mut members, "organization").map_err(serde::de::Error::custom)?;
                let issuer =
                    take_member(&mut members, "issuer").map_err(serde::de::Error::custom)?;
                let external_host =
                    take_member(&mut members, "external_host").map_err(serde::de::Error::custom)?;
                ControlOperationPayload::TenantDirectoryCreate {
                    expected_revision,
                    tenant,
                    realm,
                    organization,
                    issuer,
                    external_host,
                }
            }
            "tenant-directory-update" => {
                let expected_revision = take_member(&mut members, "expected_revision")
                    .map_err(serde::de::Error::custom)?;
                let tenant_id =
                    take_member(&mut members, "tenant_id").map_err(serde::de::Error::custom)?;
                let issuer =
                    take_member(&mut members, "issuer").map_err(serde::de::Error::custom)?;
                let external_host =
                    take_member(&mut members, "external_host").map_err(serde::de::Error::custom)?;
                ControlOperationPayload::TenantDirectoryUpdate {
                    expected_revision,
                    tenant_id,
                    issuer,
                    external_host,
                }
            }
            "tenant-directory-disable" => ControlOperationPayload::TenantDirectoryDisable {
                expected_revision: take_member(&mut members, "expected_revision")
                    .map_err(serde::de::Error::custom)?,
                tenant_id: take_member(&mut members, "tenant_id")
                    .map_err(serde::de::Error::custom)?,
            },
            "tenant-directory-reload" => ControlOperationPayload::TenantDirectoryReload {
                expected_revision: take_member(&mut members, "expected_revision")
                    .map_err(serde::de::Error::custom)?,
                tenant_id: take_member(&mut members, "tenant_id")
                    .map_err(serde::de::Error::custom)?,
            },
            "tenant-directory-finalize" => ControlOperationPayload::TenantDirectoryFinalize {
                expected_revision: take_member(&mut members, "expected_revision")
                    .map_err(serde::de::Error::custom)?,
                tenant_id: take_member(&mut members, "tenant_id")
                    .map_err(serde::de::Error::custom)?,
            },
            "tenant-directory-describe" => ControlOperationPayload::TenantDirectoryDescribe,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown operation '{other}'"
                )));
            }
        };
        if let Some(member) = members.keys().next() {
            return Err(serde::de::Error::custom(format!(
                "unknown operation field '{member}'"
            )));
        }
        Ok(payload)
    }
}

fn take_member<T: serde::de::DeserializeOwned>(
    members: &mut serde_json::Map<String, serde_json::Value>,
    key: &'static str,
) -> Result<T, String> {
    let value = members
        .remove(key)
        .ok_or_else(|| format!("operation requires field '{key}'"))?;
    serde_json::from_value(value)
        .map_err(|error| format!("invalid operation field '{key}': {error}"))
}

/// Plain durable journal entry for one operation outcome (E01 §2 / 05 §8).
///
/// This is not a signed receipt chain: the journal is the authority, ctl
/// recovers lost responses by re-reading it through a resumed operation, and
/// no second long-term identity is introduced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResult {
    pub schema: u32,
    /// Echo of the accepted operation's id.
    pub operation_id: String,
    /// Echo of [`control_operation_request_hash`] of the accepted operation;
    /// binds the result to exactly one canonical request (D5 concept, no
    /// signing key involved).
    pub request_hash: String,
    pub outcome: ControlOutcome,
    /// Stable failure taxonomy; present if and only if `outcome` is
    /// [`ControlOutcome::Failed`].
    pub error: Option<ControlErrorCode>,
    /// Journal acceptance time (authorization snapshot anchor, E03 §5).
    pub accepted_at: i64,
    /// Terminal completion time; required exactly when the outcome is
    /// terminal, absent while in progress.
    pub completed_at: Option<i64>,
    /// Closed typed result data (05 §8 `result?`).  Present if and only if
    /// `outcome` is [`ControlOutcome::Succeeded`] *and* the operation's
    /// contract defines returned data.  Omitted from the wire form entirely
    /// when absent, so journal entries written before this extension keep
    /// their exact bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ControlResultData>,
}

/// Closed typed result-data variants (H07).  Only operations whose contract
/// defines returned data may populate the channel; adding a variant is a
/// protocol change. Every variant has named fields, so serde enforces the
/// closed field set directly.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ControlResultData {
    /// Public receipt for a freshly generated tenant-local signing key. The
    /// certificate bundle contains public material only; private key bytes
    /// never leave the managed tenant key directory.
    TenantKeyGenerated {
        tenant_id: String,
        kid: String,
        /// Canonical positive decimal revision of the tenant keyset
        /// repository generation.
        keyset_revision: String,
        certificate_chain_pem: String,
    },
    /// Authoritative outcome of an applied tenant-resource change set.
    TenantResourceApply {
        revision: u64,
        /// Identities applied by this operation, not the complete active set.
        resources: Vec<TenantResourceIdentity>,
        resource_mappings: Vec<TenantResourceMapping>,
        /// Canonical digest of the complete active set after the operation.
        resource_manifest_sha256: String,
    },
    /// Durable post-restore invalidation boundary. Ctl must keep ingress
    /// closed until strictly after `not_before`.
    RecoveryInvalidation {
        state_epoch: String,
        not_before: i64,
        revoked_refresh_tokens: u64,
    },
    /// Authoritative outcome of a revoked tenant-resource change set.
    TenantResourceRevoke {
        revision: u64,
        /// Identities revoked by this operation, not the remaining active set.
        resources: Vec<TenantResourceIdentity>,
        /// Canonical digest of the complete remaining active set.
        resource_manifest_sha256: String,
    },
    /// Authoritative tenant-resource enumeration snapshot.  `revision` is the
    /// CAS revision the read is consistent with; `resources` is the sorted,
    /// digest-bound active identity set selected by the request's selectors.
    TenantResourceEnumerate {
        revision: u64,
        resources: Vec<TenantResourceIdentity>,
        /// Canonical digest of the complete active set, including identities
        /// omitted by request selectors.
        resource_manifest_sha256: String,
    },
    /// Authoritative outcome of one tenant directory lifecycle mutation.
    /// `revision` is the directory revision after the mutation; a replay that
    /// matched an identical prior effect reports the unchanged revision.
    TenantDirectoryMutation {
        action: String,
        tenant_id: String,
        previous_revision: u64,
        revision: u64,
    },
    /// Authoritative directory snapshot at the reported revision.
    TenantDirectoryDescribe {
        revision: u64,
        tenants: Vec<ControlTenantDirectoryBinding>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlOutcome {
    Succeeded,
    Failed,
    InProgress,
}

/// Closed, stable error taxonomy spelled exactly like the CLI stable error
/// codes (09 §5).  Adding a code is a protocol change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlErrorCode {
    /// The operation was admitted and executed but the business action
    /// failed inside NazoAuth.
    ExecutionFailed,
}

/// Validate envelope structure.  There is deliberately no admission clock:
/// per 05 §2 the envelope carries no time claims, key validity is evaluated
/// once at first accept, and the operation journal owns replay defense.
pub fn validate_control_operation(operation: &ControlOperation) -> Result<(), ProtocolError> {
    if operation.schema != CONTROL_OPERATION_SCHEMA {
        return Err(ProtocolError::Policy(
            "unsupported control operation schema",
        ));
    }
    validate_uuidv7(&operation.operation_id)?;
    validate_controller_kid(&operation.kid)?;
    validate_file_identifier(&operation.deployment_id)?;
    validate_identifier(&operation.config_revision)?;
    validate_control_payload(&operation.operation)
}

fn validate_control_payload(payload: &ControlOperationPayload) -> Result<(), ProtocolError> {
    match payload {
        ControlOperationPayload::MigrateApply
        | ControlOperationPayload::KeysList
        | ControlOperationPayload::KeysValidate => {}
        ControlOperationPayload::KeysGenerateLocal { alg, purposes } => {
            validate_generate_local_fields(alg, purposes)?;
        }
        ControlOperationPayload::TenantKeysGenerateLocal {
            tenant_id,
            alg,
            purposes,
        } => {
            validate_uuid(tenant_id)?;
            validate_generate_local_fields(alg, purposes)?;
            if alg != "ES256"
                || purposes.len() != 2
                || !purposes.iter().any(|purpose| purpose == "credential")
                || !purposes
                    .iter()
                    .any(|purpose| purpose == "presentation_request")
            {
                return Err(ProtocolError::Policy(
                    "tenant key generation requires the OpenID4VC signing profile",
                ));
            }
        }
        ControlOperationPayload::KeysRegisterExternal {
            kid,
            alg,
            key_ref,
            public_jwk_sha256,
        } => {
            validate_file_identifier(kid)?;
            validate_identifier(alg)?;
            validate_lower_hex(public_jwk_sha256, 64)?;
            if key_ref.is_empty()
                || key_ref.len() > 512
                || ["//", "@", "?", "#", "="]
                    .iter()
                    .any(|forbidden| key_ref.contains(forbidden))
                || !key_ref.chars().all(|character| {
                    character.is_ascii_alphanumeric() || ".:_/-+".contains(character)
                })
            {
                return Err(ProtocolError::Policy(
                    "external key reference must be a non-secret provider locator",
                ));
            }
        }
        ControlOperationPayload::TenantResourceApply {
            tenant_id,
            resources,
        }
        | ControlOperationPayload::TenantResourceRevoke {
            tenant_id,
            resources,
        } => {
            validate_uuid(tenant_id)?;
            validate_tenant_resource_set(resources)?;
        }
        ControlOperationPayload::TenantResourceEnumerate {
            tenant_id,
            selectors,
        } => {
            validate_uuid(tenant_id)?;
            if selectors.len() > MAX_TENANT_RESOURCE_IDENTITIES {
                return Err(ProtocolError::Policy(
                    "tenant resource selectors are out of bounds",
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            for selector in selectors {
                validate_file_identifier(&selector.resource_id)?;
                if !seen.insert((selector.kind, selector.resource_id.as_str())) {
                    return Err(ProtocolError::Policy(
                        "tenant resource selectors must be unique",
                    ));
                }
            }
        }
        ControlOperationPayload::RecoveryInvalidate { state_epoch } => {
            validate_recovery_state_epoch(state_epoch)?;
        }
        ControlOperationPayload::TenantDirectoryCreate {
            expected_revision: _,
            tenant,
            realm,
            organization,
            issuer,
            external_host,
        } => {
            let mut seen = std::collections::BTreeSet::new();
            for boundary in [tenant, realm, organization] {
                validate_uuid(&boundary.id)?;
                validate_tenant_slug(&boundary.slug)?;
                validate_tenant_display_name(&boundary.display_name)?;
                if !seen.insert(boundary.id.as_str()) {
                    return Err(ProtocolError::Policy(
                        "tenant directory boundaries must reference distinct ids",
                    ));
                }
            }
            validate_tenant_issuer(issuer)?;
            validate_tenant_host(external_host)?;
        }
        ControlOperationPayload::TenantDirectoryUpdate {
            expected_revision: _,
            tenant_id,
            issuer,
            external_host,
        } => {
            validate_uuid(tenant_id)?;
            validate_tenant_issuer(issuer)?;
            validate_tenant_host(external_host)?;
        }
        ControlOperationPayload::TenantDirectoryDisable {
            expected_revision: _,
            tenant_id,
        }
        | ControlOperationPayload::TenantDirectoryReload {
            expected_revision: _,
            tenant_id,
        }
        | ControlOperationPayload::TenantDirectoryFinalize {
            expected_revision: _,
            tenant_id,
        } => validate_uuid(tenant_id)?,
        ControlOperationPayload::TenantDirectoryDescribe => {}
    }
    Ok(())
}

fn validate_generate_local_fields(alg: &str, purposes: &[String]) -> Result<(), ProtocolError> {
    validate_identifier(alg)?;
    if purposes.is_empty() || purposes.len() > 8 {
        return Err(ProtocolError::Policy("invalid signing purposes"));
    }
    for purpose in purposes {
        validate_identifier(purpose)?;
    }
    Ok(())
}

/// Routing issuer bounds shared by every directory lifecycle payload. Exact
/// URL/host consistency is enforced by the authoritative directory.
fn validate_tenant_issuer(issuer: &str) -> Result<(), ProtocolError> {
    if issuer.is_empty() || issuer.len() > 2048 || issuer != issuer.trim() {
        return Err(ProtocolError::Policy("tenant issuer is out of bounds"));
    }
    Ok(())
}

/// Canonical routing host bounds shared by every directory lifecycle payload.
fn validate_tenant_host(external_host: &str) -> Result<(), ProtocolError> {
    if external_host.is_empty()
        || external_host.len() > 255
        || external_host.bytes().any(|byte| byte.is_ascii_uppercase())
        || external_host != external_host.trim()
    {
        return Err(ProtocolError::Policy(
            "tenant external host must be a bounded lowercase host",
        ));
    }
    Ok(())
}

fn validate_tenant_slug(slug: &str) -> Result<(), ProtocolError> {
    if slug.is_empty() || slug.len() > 120 || slug != slug.trim() {
        return Err(ProtocolError::Policy("tenant slug is out of bounds"));
    }
    Ok(())
}

fn validate_tenant_display_name(display_name: &str) -> Result<(), ProtocolError> {
    if display_name.is_empty() || display_name.len() > 200 || display_name != display_name.trim() {
        return Err(ProtocolError::Policy(
            "tenant display name is out of bounds",
        ));
    }
    Ok(())
}

/// Apply/Revoke payloads must carry at least one and at most
/// [`MAX_TENANT_RESOURCE_IDENTITIES`] unique, digest-bound identities.
fn validate_tenant_resource_set(resources: &[TenantResourceIdentity]) -> Result<(), ProtocolError> {
    if resources.is_empty() || resources.len() > MAX_TENANT_RESOURCE_IDENTITIES {
        return Err(ProtocolError::Policy(
            "tenant resource identities are out of bounds",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for resource in resources {
        validate_file_identifier(&resource.resource_id)?;
        validate_lower_hex(&resource.digest, 64)?;
        if !seen.insert((resource.kind, resource.resource_id.as_str())) {
            return Err(ProtocolError::Policy(
                "tenant resource identities must be unique",
            ));
        }
    }
    Ok(())
}

/// Canonical lowercase UUIDv7 enforcement (RFC 9562 version and variant
/// nibbles included).  No UUID dependency is pulled into this crate.
fn validate_uuidv7(value: &str) -> Result<(), ProtocolError> {
    validate_uuid(value)?;
    let bytes = value.as_bytes();
    if bytes[14] != b'7' {
        return Err(ProtocolError::Policy("operation_id must be a UUIDv7"));
    }
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return Err(ProtocolError::Policy(
            "operation_id must use the RFC 9562 variant",
        ));
    }
    Ok(())
}

fn validate_recovery_state_epoch(value: &str) -> Result<(), ProtocolError> {
    validate_uuidv7(value).map_err(|_| {
        ProtocolError::Policy("recovery state epoch must be a canonical non-nil UUIDv7")
    })
}

fn validate_controller_kid(kid: &str) -> Result<(), ProtocolError> {
    if kid.len() != CONTROLLER_KID_LENGTH
        || !kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProtocolError::Policy(
            "controller kid must be unpadded base64url SHA-256 of the public key",
        ));
    }
    Ok(())
}

fn validate_keyset_revision(value: &str) -> Result<(), ProtocolError> {
    let revision = value
        .parse::<i64>()
        .map_err(|_| ProtocolError::Policy("invalid keyset revision"))?;
    if revision < 1
        || !value.starts_with(|c: char| matches!(c, '1'..='9'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProtocolError::Policy("invalid keyset revision"));
    }
    Ok(())
}

/// Derive the controller key id per E02: `base64url(SHA-256(raw public key
/// bytes))`, unpadded.
pub fn controller_key_id(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.to_bytes()))
}

/// Canonical bytes of a control operation: sorted-key compact UTF-8 JSON
/// (see the module docs for the exact algorithm), bounded by
/// [`MAX_CONTROL_OPERATION_BYTES`]. Validates the operation before encoding.
pub fn canonical_control_operation_bytes(
    operation: &ControlOperation,
) -> Result<Vec<u8>, ProtocolError> {
    validate_control_operation(operation)?;
    let mut value = serde_json::to_value(operation).map_err(|_| ProtocolError::Json)?;
    value.sort_all_objects();
    let bytes = serde_json::to_vec(&value).map_err(|_| ProtocolError::Json)?;
    if bytes.len() > MAX_CONTROL_OPERATION_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(bytes)
}

/// Lowercase hexadecimal SHA-256 of the bytes returned by
/// [`canonical_control_operation_bytes`]. Callers reuse that encoding for
/// signing or payload comparison instead of serializing the operation again.
pub fn control_operation_request_hash(canonical: &[u8]) -> String {
    lower_hex_sha256(canonical)
}

/// Sign one control operation with the instance Controller Key.
///
/// The signer's derived kid must match `operation.kid`; the compact JWS uses
/// the fixed protected header and the canonical payload bytes. Returns the
/// compact JWS and its request hash, both derived from the same encoding.
pub fn sign_control_operation(
    operation: &ControlOperation,
    key: &SigningKey,
) -> Result<(String, String), ProtocolError> {
    let canonical = canonical_control_operation_bytes(operation)?;
    let kid = controller_key_id(&key.verifying_key());
    if operation.kid != kid {
        return Err(ProtocolError::Policy(
            "controller kid does not match signer",
        ));
    }
    let protected = encode_protected_header(&operation.kid)?;
    let request_hash = control_operation_request_hash(&canonical);
    let compact = crate::signing::sign_payload(protected, &canonical, key)?;
    Ok((compact, request_hash))
}

/// Verify signature, canonical encoding, envelope policy, and header/key
/// binding without the admission clock.  Returns the decoded operation.
pub fn verify_control_operation_signature(
    compact: &str,
    expected_kid: &str,
    key: &VerifyingKey,
) -> Result<ControlOperation, ProtocolError> {
    if compact.len() > MAX_COMPACT_JWS_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    // Preserve the public entry point's header-before-payload error order.
    validate_controller_kid(expected_kid).map_err(|_| ProtocolError::Header)?;
    let (protected, payload, signature) = control_operation_segments(compact)?;
    verify_control_operation_header(protected, expected_kid)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| ProtocolError::Base64)?;
    let operation: ControlOperation =
        serde_json::from_slice(&payload_bytes).map_err(|_| ProtocolError::Json)?;
    ensure_control_operation_kid(&operation, expected_kid)?;
    let canonical = canonical_control_operation_bytes(&operation)?;
    verify_control_operation_payload(
        &compact.as_bytes()[..protected.len() + 1 + payload.len()],
        signature,
        payload_bytes == canonical,
        key,
    )?;
    Ok(operation)
}

/// Bounded presentation prepared before controller admission. Its private payload
/// and canonical bytes cannot be mutated between parsing, hashing and verification.
/// A presentation carries no signature authority; only `verify` promotes it.
pub struct PresentedControlOperation<'a> {
    signing_input: &'a [u8],
    protected: &'a str,
    signature: &'a str,
    canonical_payload: bool,
    operation: ControlOperation,
    canonical: Vec<u8>,
}

impl<'a> PresentedControlOperation<'a> {
    pub fn parse(compact: &'a str) -> Result<Self, ProtocolError> {
        if compact.len() > MAX_COMPACT_JWS_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let (protected, payload, signature) = control_operation_segments(compact)?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| ProtocolError::Base64)?;
        let operation: ControlOperation =
            serde_json::from_slice(&payload_bytes).map_err(|_| ProtocolError::Json)?;
        let canonical = canonical_control_operation_bytes(&operation)?;
        Ok(Self {
            signing_input: &compact.as_bytes()[..protected.len() + 1 + payload.len()],
            protected,
            signature,
            canonical_payload: payload_bytes == canonical,
            operation,
            canonical,
        })
    }

    /// Lookup/replay facts only. The operation remains untrusted until verification.
    pub fn operation(&self) -> &ControlOperation {
        &self.operation
    }

    pub fn request_hash(&self) -> String {
        control_operation_request_hash(&self.canonical)
    }

    pub fn verify(
        self,
        expected_kid: &str,
        key: &VerifyingKey,
    ) -> Result<ControlOperation, ProtocolError> {
        validate_controller_kid(expected_kid).map_err(|_| ProtocolError::Header)?;
        verify_control_operation_header(self.protected, expected_kid)?;
        ensure_control_operation_kid(&self.operation, expected_kid)?;
        verify_control_operation_payload(
            self.signing_input,
            self.signature,
            self.canonical_payload,
            key,
        )?;
        Ok(self.operation)
    }
}

// Each public entry checks the size before parsing; this helper owns segmentation.
fn control_operation_segments(compact: &str) -> Result<(&str, &str, &str), ProtocolError> {
    let mut segments = compact.split('.');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some(protected), Some(payload), Some(signature), None)
            if !protected.is_empty() && !payload.is_empty() && !signature.is_empty() =>
        {
            Ok((protected, payload, signature))
        }
        _ => Err(ProtocolError::SegmentCount),
    }
}

fn verify_control_operation_header(
    protected: &str,
    expected_kid: &str,
) -> Result<(), ProtocolError> {
    let header_bytes = URL_SAFE_NO_PAD
        .decode(protected)
        .map_err(|_| ProtocolError::Base64)?;
    let header: ProtectedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| ProtocolError::Header)?;
    if header.typ != CONTROL_OPERATION_JWS_TYPE || header.kid != expected_kid {
        return Err(ProtocolError::Header);
    }
    Ok(())
}

fn ensure_control_operation_kid(
    operation: &ControlOperation,
    expected_kid: &str,
) -> Result<(), ProtocolError> {
    if operation.kid != expected_kid {
        return Err(ProtocolError::Policy(
            "envelope kid does not match the controller key id claim",
        ));
    }
    Ok(())
}

fn verify_control_operation_payload(
    signing_input: &[u8],
    signature: &str,
    canonical_payload: bool,
    key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    if !canonical_payload {
        return Err(ProtocolError::Policy(
            "control operation payload is not canonically encoded",
        ));
    }
    crate::verification::verify_signature(signing_input, signature, key)
}

/// Validate and serialize a [`ControlResult`] for the journal or the
/// one-shot stdout channel.  Plain deterministic compact JSON; results are
/// never signed or hashed.
pub fn encode_control_result(result: &ControlResult) -> Result<Vec<u8>, ProtocolError> {
    validate_control_result(result)?;
    let bytes = serde_json::to_vec(result).map_err(|_| ProtocolError::Json)?;
    if bytes.len() > MAX_CONTROL_RESULT_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(bytes)
}

/// Prove that typed result data can be published in every valid
/// [`ControlResult`] envelope.  The envelope uses the longest valid signed
/// integer spellings, so a value accepted here cannot cross the wire limit
/// when the journal supplies real timestamps.
///
/// Stateful executors must call this before committing the mutation that
/// produces `data`; otherwise a structurally valid but oversized result could
/// commit its side effect and then fail permanent journal publication.
pub fn validate_control_result_data_for_wire(
    data: &ControlResultData,
) -> Result<(), ProtocolError> {
    let envelope = ControlResult {
        schema: CONTROL_RESULT_SCHEMA,
        operation_id: "00000000-0000-7000-8000-000000000000".to_owned(),
        request_hash: "0".repeat(64),
        outcome: ControlOutcome::Succeeded,
        error: None,
        accepted_at: i64::MIN,
        completed_at: Some(i64::MAX),
        result: Some(data.clone()),
    };
    encode_control_result(&envelope).map(|_| ())
}

/// Decode and validate a [`ControlResult`] received from a one-shot process
/// or read back from the journal.
pub fn decode_control_result(bytes: &[u8]) -> Result<ControlResult, ProtocolError> {
    if bytes.len() > MAX_CONTROL_RESULT_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let result: ControlResult = serde_json::from_slice(bytes).map_err(|_| ProtocolError::Json)?;
    validate_control_result(&result)?;
    Ok(result)
}

/// Validate journal-entry invariants: error presence matches the outcome and
/// timestamps are ordered.
pub fn validate_control_result(result: &ControlResult) -> Result<(), ProtocolError> {
    if result.schema != CONTROL_RESULT_SCHEMA {
        return Err(ProtocolError::Policy("unsupported control result schema"));
    }
    validate_uuidv7(&result.operation_id)?;
    validate_lower_hex(&result.request_hash, 64)?;
    match result.outcome {
        ControlOutcome::InProgress => {
            if result.error.is_some() {
                return Err(ProtocolError::Policy(
                    "in-progress results carry no error code",
                ));
            }
            if result.completed_at.is_some() {
                return Err(ProtocolError::Policy(
                    "in-progress results have no completion time",
                ));
            }
            if result.result.is_some() {
                return Err(ProtocolError::Policy(
                    "in-progress results carry no result data",
                ));
            }
        }
        ControlOutcome::Succeeded | ControlOutcome::Failed => {
            if result.completed_at.is_none() {
                return Err(ProtocolError::Policy(
                    "terminal results require a completion time",
                ));
            }
            if result
                .completed_at
                .is_some_and(|completed| completed < result.accepted_at)
            {
                return Err(ProtocolError::Policy(
                    "completion precedes journal acceptance",
                ));
            }
            if result.outcome == ControlOutcome::Failed {
                if result.error.is_none() {
                    return Err(ProtocolError::Policy(
                        "failed results require an error code",
                    ));
                }
                if result.result.is_some() {
                    return Err(ProtocolError::Policy("failed results carry no result data"));
                }
            } else if result.error.is_some() {
                return Err(ProtocolError::Policy(
                    "succeeded results carry no error code",
                ));
            }
            if let Some(data) = &result.result {
                validate_control_result_data(data)?;
            }
        }
    }
    Ok(())
}

/// Structural invariants of the typed result channel: bounded, unique,
/// digest-bound identity sets only.
fn validate_control_result_data(data: &ControlResultData) -> Result<(), ProtocolError> {
    let (resources, resource_mappings, resource_manifest_sha256, is_apply) = match data {
        ControlResultData::TenantKeyGenerated {
            tenant_id,
            kid,
            keyset_revision,
            certificate_chain_pem,
        } => {
            validate_uuid(tenant_id)?;
            validate_file_identifier(kid)?;
            validate_keyset_revision(keyset_revision)?;
            if certificate_chain_pem.is_empty()
                || certificate_chain_pem.len() > 32 * 1024
                || !certificate_chain_pem.starts_with("-----BEGIN CERTIFICATE-----\n")
                || !certificate_chain_pem.ends_with("-----END CERTIFICATE-----\n")
            {
                return Err(ProtocolError::Policy(
                    "invalid tenant key certificate chain",
                ));
            }
            return Ok(());
        }
        ControlResultData::TenantDirectoryMutation {
            action,
            tenant_id,
            previous_revision: _,
            revision: _,
        } => {
            if !matches!(
                action.as_str(),
                "create" | "update" | "disable" | "reload" | "finalize"
            ) {
                return Err(ProtocolError::Policy("invalid directory mutation action"));
            }
            validate_uuid(tenant_id)?;
            return Ok(());
        }
        ControlResultData::TenantDirectoryDescribe {
            revision: _,
            tenants,
        } => {
            if tenants.len() > MAX_TENANT_RESOURCE_IDENTITIES {
                return Err(ProtocolError::Policy(
                    "tenant directory result sets are out of bounds",
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            for binding in tenants {
                validate_uuid(&binding.tenant_id)?;
                validate_uuid(&binding.realm_id)?;
                validate_uuid(&binding.organization_id)?;
                if binding.runtime_revision == 0 {
                    return Err(ProtocolError::Policy(
                        "tenant runtime revisions must be positive",
                    ));
                }
                validate_tenant_issuer(&binding.issuer)?;
                validate_tenant_host(&binding.external_host)?;
                if !seen.insert(binding.tenant_id.as_str()) {
                    return Err(ProtocolError::Policy(
                        "tenant directory result bindings must be unique",
                    ));
                }
            }
            return Ok(());
        }
        ControlResultData::TenantResourceApply {
            resources,
            resource_mappings,
            resource_manifest_sha256,
            ..
        } => (
            resources,
            resource_mappings.as_slice(),
            resource_manifest_sha256,
            true,
        ),
        ControlResultData::TenantResourceRevoke {
            resources,
            resource_manifest_sha256,
            ..
        }
        | ControlResultData::TenantResourceEnumerate {
            resources,
            resource_manifest_sha256,
            ..
        } => (resources, &[][..], resource_manifest_sha256, false),
        ControlResultData::RecoveryInvalidation {
            state_epoch,
            not_before,
            ..
        } => {
            validate_recovery_state_epoch(state_epoch)?;
            if *not_before <= 0 {
                return Err(ProtocolError::Policy(
                    "invalid recovery invalidation result",
                ));
            }
            return Ok(());
        }
    };
    validate_lower_hex(resource_manifest_sha256, 64)?;
    if resources.len() > MAX_TENANT_RESOURCE_IDENTITIES {
        return Err(ProtocolError::Policy(
            "tenant resource result sets are out of bounds",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for resource in resources {
        validate_file_identifier(&resource.resource_id)?;
        validate_lower_hex(&resource.digest, 64)?;
        if !seen.insert((resource.kind, resource.resource_id.as_str())) {
            return Err(ProtocolError::Policy(
                "tenant resource result identities must be unique",
            ));
        }
    }
    if resource_mappings.len() > resources.len() {
        return Err(ProtocolError::Policy(
            "tenant resource result mappings are out of bounds",
        ));
    }
    let expected_mapping_count = resources
        .iter()
        .filter(|resource| {
            matches!(
                resource.kind,
                crate::wire::TenantResourceKind::User
                    | crate::wire::TenantResourceKind::OauthClient
            )
        })
        .count();
    let mut mapped = std::collections::BTreeSet::new();
    for mapping in resource_mappings {
        validate_file_identifier(&mapping.resource_id)?;
        match mapping.kind {
            crate::wire::TenantResourceKind::User => validate_uuid(&mapping.public_id)?,
            crate::wire::TenantResourceKind::OauthClient => {
                validate_identifier(&mapping.public_id)?
            }
            _ => {
                return Err(ProtocolError::Policy(
                    "invalid tenant resource result mapping",
                ));
            }
        }
        if !seen.contains(&(mapping.kind, mapping.resource_id.as_str()))
            || !mapped.insert((mapping.kind, mapping.resource_id.as_str()))
        {
            return Err(ProtocolError::Policy(
                "invalid tenant resource result mapping",
            ));
        }
    }
    if is_apply && mapped.len() != expected_mapping_count {
        return Err(ProtocolError::Policy(
            "tenant resource apply mappings must cover public resources exactly",
        ));
    }
    Ok(())
}

fn encode_protected_header(kid: &str) -> Result<String, ProtocolError> {
    let header = ProtectedHeader {
        alg: FixedAlgorithm::EdDSA,
        kid: kid.to_owned(),
        typ: CONTROL_OPERATION_JWS_TYPE.to_owned(),
    };
    let bytes = serde_json::to_vec(&header).map_err(|_| ProtocolError::Json)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn lower_hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
