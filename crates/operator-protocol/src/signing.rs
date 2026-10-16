//! Signing and compact-JWS encoding for the operator protocol.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_crypto::ed25519::{SigningKey, VerifyingKey};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::verification::{
    validate_deployment_statement, validate_discovery_statement, validate_file_identifier,
    validate_identifier, validate_lower_hex,
};
use crate::wire::{
    DeploymentStatement, DiscoveryStatement, FixedAlgorithm, Openid4vpNormalizedCreateRequest,
    ProtectedHeader, TenantResourceIdentity, TenantResourceKind,
};
use crate::{
    CONTROL_DISCOVERY_JWS_TYPE, DEPLOYMENT_STATEMENT_JWS_TYPE, MAX_COMPACT_JWS_BYTES, ProtocolError,
};

pub fn sign_discovery_statement(
    statement: &DiscoveryStatement,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_discovery_statement(statement, statement.issued_at, None)?;
    if statement.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "instance key id does not match signer",
        ));
    }
    sign_compact(statement, key_id, CONTROL_DISCOVERY_JWS_TYPE, key)
}

pub fn sign_deployment_statement(
    statement: &DeploymentStatement,
    key_id: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    validate_deployment_statement(statement)?;
    if statement.instance_key_id != key_id {
        return Err(ProtocolError::Policy(
            "instance key id does not match signer",
        ));
    }
    sign_compact(statement, key_id, DEPLOYMENT_STATEMENT_JWS_TYPE, key)
}

pub fn encode_instance_public_key(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.to_bytes())
}

pub fn decode_instance_public_key(encoded: &str) -> Result<VerifyingKey, ProtocolError> {
    let mut bytes = [0_u8; 32];
    match URL_SAFE_NO_PAD.decode_slice(encoded, &mut bytes) {
        Ok(32) => {}
        Ok(_) | Err(base64::DecodeSliceError::OutputSliceTooSmall) => {
            return Err(ProtocolError::Policy("invalid instance public key"));
        }
        Err(_) => return Err(ProtocolError::Base64),
    }
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| ProtocolError::Policy("invalid instance public key"))
}

pub fn instance_key_id(key: &VerifyingKey) -> String {
    format!("instance-{}", &hex_sha256(&key.to_bytes())[..32])
}

/// Return the exact canonical JSON and lowercase SHA-256 used to bind an
/// OpenID4VP create JTI to its complete, normalized request.
pub fn canonical_openid4vp_normalized_create_request(
    request: &Openid4vpNormalizedCreateRequest,
) -> Result<(String, String), ProtocolError> {
    let mut value = serde_json::to_value(request).map_err(|_| ProtocolError::Json)?;
    value.sort_all_objects();
    let canonical = serde_json::to_string(&value).map_err(|_| ProtocolError::Json)?;
    let sha256 = hex_sha256(canonical.as_bytes());
    Ok((canonical, sha256))
}

/// Canonical digest of a current ControlOperation tenant-resource snapshot.
///
/// Both the server and ctl use this domain-separated encoding to bind
/// `ControlResultData::resource_manifest_sha256` to the complete active
/// identity set. It is part of the current result contract.
pub fn canonical_tenant_resource_manifest_sha256(
    resources: &[TenantResourceIdentity],
) -> Result<String, ProtocolError> {
    if resources.len() > crate::MAX_TENANT_RESOURCE_IDENTITIES {
        return Err(ProtocolError::Policy(
            "tenant resource identities are out of bounds",
        ));
    }
    let mut entries = Vec::with_capacity(resources.len());
    for resource in resources {
        validate_file_identifier(&resource.resource_id)?;
        validate_lower_hex(&resource.digest, 64)?;
        entries.push((
            tenant_resource_kind_wire_label(resource.kind),
            resource.resource_id.as_str(),
            resource.digest.as_str(),
        ));
    }
    entries.sort_unstable();
    if entries
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 == pair[1].1)
    {
        return Err(ProtocolError::Policy(
            "tenant resource identities must be unique",
        ));
    }
    let mut digest = Sha256::new();
    hash_len_prefixed(&mut digest, b"nazoauth:tenant-resource-manifest:v1");
    digest.update((entries.len() as u64).to_be_bytes());
    for (kind, resource_id, resource_digest) in entries {
        hash_len_prefixed(&mut digest, kind.as_bytes());
        hash_len_prefixed(&mut digest, resource_id.as_bytes());
        hash_len_prefixed(&mut digest, resource_digest.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

fn tenant_resource_kind_wire_label(kind: TenantResourceKind) -> &'static str {
    match kind {
        TenantResourceKind::OauthClient => "oauth-client",
        TenantResourceKind::MtlsTrustAnchor => "mtls-trust-anchor",
        TenantResourceKind::Openid4vcDataset => "openid4vc-dataset",
        TenantResourceKind::Openid4vcTrustPolicy => "openid4vc-trust-policy",
        TenantResourceKind::User => "user",
    }
}

fn hash_len_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

pub fn compact_sha256(compact: &str) -> String {
    hex_sha256(compact.as_bytes())
}

pub fn protected_header(compact: &str) -> Result<ProtectedHeader, ProtocolError> {
    let (protected, _, _) = compact_segments(compact)?;
    decode_protected_header(protected)
}

pub(crate) fn sign_compact<T: Serialize>(
    claims: &T,
    key_id: &str,
    expected_type: &str,
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    // The key id becomes a key-store path component for verifiers.  Keep the
    // signing and pre-lookup parsing boundary identical so we never mint a
    // token that a safe verifier cannot look up.
    validate_file_identifier(key_id)?;
    let header = ProtectedHeader {
        alg: FixedAlgorithm::EdDSA,
        kid: key_id.to_owned(),
        typ: expected_type.to_owned(),
    };
    let protected = encode_json(&header)?;
    let payload = serde_json::to_vec(claims).map_err(|_| ProtocolError::Json)?;
    sign_payload(protected, &payload, key)
}

pub(crate) fn sign_payload(
    mut compact: String,
    payload: &[u8],
    key: &SigningKey,
) -> Result<String, ProtocolError> {
    compact.push('.');
    URL_SAFE_NO_PAD.encode_string(payload, &mut compact);
    // Ed25519 adds a dot and 86 unpadded base64url signature characters.
    if compact.len() > MAX_COMPACT_JWS_BYTES - 87 {
        return Err(ProtocolError::TooLarge);
    }
    let signature = key.sign(compact.as_bytes());
    compact.push('.');
    URL_SAFE_NO_PAD.encode_string(signature, &mut compact);
    Ok(compact)
}

pub(crate) fn compact_segments(compact: &str) -> Result<(&str, &str, &str), ProtocolError> {
    if compact.len() > MAX_COMPACT_JWS_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let mut segments = compact.split('.');
    let protected = segments.next().ok_or(ProtocolError::SegmentCount)?;
    let payload = segments.next().ok_or(ProtocolError::SegmentCount)?;
    let signature = segments.next().ok_or(ProtocolError::SegmentCount)?;
    if segments.next().is_some()
        || protected.is_empty()
        || payload.is_empty()
        || signature.is_empty()
    {
        return Err(ProtocolError::SegmentCount);
    }
    Ok((protected, payload, signature))
}

pub(crate) fn decode_protected_header(protected: &str) -> Result<ProtectedHeader, ProtocolError> {
    let header: ProtectedHeader = decode_json(protected).map_err(|_| ProtocolError::Header)?;
    if validate_file_identifier(&header.kid).is_err() || validate_identifier(&header.typ).is_err() {
        return Err(ProtocolError::Header);
    }
    Ok(header)
}

fn encode_json<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| ProtocolError::Json)
}

pub(crate) fn decode_json<T: DeserializeOwned>(encoded: &str) -> Result<T, ProtocolError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::Base64)?;
    serde_json::from_slice(&bytes).map_err(|_| ProtocolError::Json)
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
