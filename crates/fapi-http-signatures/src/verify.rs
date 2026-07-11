use std::fmt;

use sfv::{BareItem, Dictionary, FieldType, InnerList, ListEntry, Parser, Version};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{RequestInput, RequestPolicy, SignatureFields, VerifyError, prepare_request};

const REQUEST_TAG: &str = "fapi-2-request";

#[derive(Debug, Clone, Copy)]
pub struct VerificationPolicy {
    pub now: i64,
    pub max_age_seconds: i64,
    pub future_skew_seconds: i64,
}

pub struct VerifiedInput {
    signature_base: Vec<u8>,
    signature: Vec<u8>,
    keyid: String,
    algorithm: String,
    created: i64,
    replay_fingerprint: [u8; 32],
}

impl fmt::Debug for VerifiedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedInput { .. }")
    }
}

impl VerifiedInput {
    pub fn signature_base(&self) -> &[u8] {
        &self.signature_base
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn keyid(&self) -> &str {
        &self.keyid
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn created(&self) -> i64 {
        self.created
    }

    pub fn replay_fingerprint(&self) -> &[u8; 32] {
        &self.replay_fingerprint
    }
}

pub fn parse_request_for_verification(
    input: RequestInput<'_>,
    fields: SignatureFields,
    policy: VerificationPolicy,
) -> Result<VerifiedInput, VerifyError> {
    let signature_input: Dictionary = Parser::new(&fields.signature_input)
        .parse()
        .map_err(|_| VerifyError::MalformedSignature)?;
    let signatures: Dictionary = Parser::new(&fields.signature)
        .parse()
        .map_err(|_| VerifyError::MalformedSignature)?;

    if top_level_member_count(&fields.signature_input) > signature_input.len()
        || top_level_member_count(&fields.signature) > signatures.len()
    {
        return Err(VerifyError::AmbiguousSignature);
    }
    if signature_input.is_empty() || signatures.is_empty() {
        return Err(VerifyError::MissingSignature);
    }
    if signature_input.len() > 1 || signatures.len() > 1 {
        return Err(VerifyError::AmbiguousSignature);
    }
    let (label, input_entry) = signature_input
        .first()
        .ok_or(VerifyError::MissingSignature)?;
    let signature_entry = signatures
        .get(label.as_str())
        .ok_or(VerifyError::MissingSignature)?;

    let params = match input_entry {
        ListEntry::InnerList(inner) => inner,
        ListEntry::Item(_) => return Err(VerifyError::MalformedSignature),
    };
    if top_level_parameter_count(&fields.signature_input) != params.params.len() {
        return Err(VerifyError::MalformedSignature);
    }
    let signature = signature_bytes(signature_entry)?.to_vec();
    let components = component_names(params)?;
    let created = integer_parameter(params, "created").ok_or(VerifyError::InvalidCreated)?;
    let keyid = string_parameter(params, "keyid")
        .filter(|value| !value.is_empty())
        .ok_or(VerifyError::MalformedSignature)?;
    let algorithm = string_parameter(params, "alg").ok_or(VerifyError::MalformedSignature)?;
    let tag = string_parameter(params, "tag").ok_or(VerifyError::InvalidTag)?;
    if tag != REQUEST_TAG {
        return Err(VerifyError::InvalidTag);
    }
    if !matches!(
        algorithm,
        "ed25519" | "rsa-v1_5-sha256" | "ecdsa-p256-sha256"
    ) {
        return Err(VerifyError::UnsupportedAlgorithm);
    }
    validate_parameters(params)?;
    validate_time(params, created, policy)?;
    let supplied_digest = validate_digest(&input)?;

    let authorization =
        unique_header(input.headers, "authorization").ok_or(VerifyError::MissingComponent)?;
    let headers_without_digest = input
        .headers
        .iter()
        .copied()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("content-digest"))
        .collect::<Vec<_>>();
    let prepared = prepare_request(
        RequestInput {
            method: input.method,
            target_uri: input.target_uri,
            headers: &headers_without_digest,
            body: input.body,
        },
        RequestPolicy {
            created,
            keyid,
            algorithm,
        },
    )
    .map_err(|_| VerifyError::MissingComponent)?;
    let expected_input: Dictionary = Parser::new(&prepared_input(&prepared))
        .parse()
        .map_err(|_| VerifyError::MalformedSignature)?;
    let expected_components = match expected_input.first().map(|(_, value)| value) {
        Some(ListEntry::InnerList(inner)) => component_names(inner)?,
        _ => return Err(VerifyError::MalformedSignature),
    };
    if components != expected_components {
        return Err(VerifyError::MissingComponent);
    }

    let serialized = signature_input
        .serialize()
        .ok_or(VerifyError::MalformedSignature)?;
    let signature_params = serialized
        .strip_prefix(label.as_str())
        .and_then(|value| value.strip_prefix('='))
        .ok_or(VerifyError::MalformedSignature)?;
    let mut signature_base = prepared.signature_base().to_vec();
    if let Some(supplied_digest) = supplied_digest {
        replace_content_digest(&mut signature_base, supplied_digest)?;
    }
    let parameter_offset = signature_base
        .windows(b"\"@signature-params\": ".len())
        .position(|window| window == b"\"@signature-params\": ")
        .ok_or(VerifyError::MalformedSignature)?
        + b"\"@signature-params\": ".len();
    signature_base.truncate(parameter_offset);
    signature_base.extend_from_slice(signature_params.as_bytes());

    let target_uri = Url::parse(input.target_uri)
        .map_err(|_| VerifyError::MissingComponent)?
        .to_string();
    let replay_fingerprint = fingerprint(
        &signature,
        keyid.as_bytes(),
        input.method.as_bytes(),
        target_uri.as_bytes(),
        authorization.trim_matches([' ', '\t']).as_bytes(),
    );

    Ok(VerifiedInput {
        signature_base,
        signature,
        keyid: keyid.to_owned(),
        algorithm: algorithm.to_owned(),
        created,
        replay_fingerprint,
    })
}

fn prepared_input(prepared: &crate::PreparedSignature) -> String {
    let base = String::from_utf8_lossy(prepared.signature_base());
    let params = base
        .rsplit_once("\"@signature-params\": ")
        .map(|(_, params)| params)
        .expect("prepare_request always emits signature parameters");
    format!("sig1={params}")
}

fn signature_bytes(entry: &ListEntry) -> Result<&[u8], VerifyError> {
    match entry {
        ListEntry::Item(item)
            if item.params.is_empty() && matches!(item.bare_item, BareItem::ByteSequence(_)) =>
        {
            match &item.bare_item {
                BareItem::ByteSequence(bytes) => Ok(bytes),
                _ => unreachable!(),
            }
        }
        _ => Err(VerifyError::MalformedSignature),
    }
}

fn component_names(inner: &InnerList) -> Result<Vec<String>, VerifyError> {
    inner
        .items
        .iter()
        .map(|item| {
            if !item.params.is_empty() {
                return Err(VerifyError::MalformedSignature);
            }
            match &item.bare_item {
                BareItem::String(value) => Ok(value.as_str().to_owned()),
                _ => Err(VerifyError::MalformedSignature),
            }
        })
        .collect()
}

fn string_parameter<'a>(inner: &'a InnerList, name: &str) -> Option<&'a str> {
    match inner.params.get(name) {
        Some(BareItem::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn integer_parameter(inner: &InnerList, name: &str) -> Option<i64> {
    match inner.params.get(name) {
        Some(BareItem::Integer(value)) => Some((*value).into()),
        _ => None,
    }
}

fn validate_parameters(inner: &InnerList) -> Result<(), VerifyError> {
    if inner.params.keys().any(|key| {
        !matches!(
            key.as_str(),
            "created" | "expires" | "keyid" | "alg" | "tag"
        )
    }) {
        return Err(VerifyError::MalformedSignature);
    }
    Ok(())
}

fn validate_time(
    inner: &InnerList,
    created: i64,
    policy: VerificationPolicy,
) -> Result<(), VerifyError> {
    if policy.max_age_seconds < 0
        || policy.future_skew_seconds < 0
        || created < policy.now.saturating_sub(policy.max_age_seconds)
        || created > policy.now.saturating_add(policy.future_skew_seconds)
    {
        return Err(VerifyError::InvalidCreated);
    }
    if let Some(expires) = inner.params.get("expires") {
        let BareItem::Integer(expires) = expires else {
            return Err(VerifyError::InvalidCreated);
        };
        let expires: i64 = (*expires).into();
        if expires < created || expires < policy.now {
            return Err(VerifyError::InvalidCreated);
        }
    }
    Ok(())
}

fn validate_digest<'a>(input: &'a RequestInput<'_>) -> Result<Option<&'a str>, VerifyError> {
    let supplied = unique_header(input.headers, "content-digest");
    if input.body.is_empty() {
        return supplied
            .is_none()
            .then_some(None)
            .ok_or(VerifyError::DigestMismatch);
    }
    let supplied = supplied.ok_or(VerifyError::DigestMismatch)?;
    let dictionary: Dictionary = Parser::new(supplied)
        .with_version(Version::Rfc8941)
        .parse()
        .map_err(|_| VerifyError::DigestMismatch)?;
    if top_level_member_count(supplied) != dictionary.len()
        || raw_dictionary_key_count(supplied, "sha-256") != 1
    {
        return Err(VerifyError::DigestMismatch);
    }
    for entry in dictionary.values() {
        if !matches!(
            entry,
            ListEntry::Item(item)
                if item.params.is_empty()
                    && matches!(item.bare_item, BareItem::ByteSequence(_))
        ) {
            return Err(VerifyError::DigestMismatch);
        }
    }
    let digest: [u8; 32] = match dictionary.get("sha-256") {
        Some(ListEntry::Item(item)) => match &item.bare_item {
            BareItem::ByteSequence(bytes) => bytes
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::DigestMismatch)?,
            _ => return Err(VerifyError::DigestMismatch),
        },
        _ => return Err(VerifyError::DigestMismatch),
    };
    let computed: [u8; 32] = Sha256::digest(input.body).into();
    if !bool::from(digest.ct_eq(&computed)) {
        return Err(VerifyError::DigestMismatch);
    }
    Ok(Some(supplied))
}

fn unique_header<'a>(headers: &'a [(&str, &'a str)], wanted: &str) -> Option<&'a str> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| *value);
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn raw_dictionary_key_count(field: &str, wanted: &str) -> usize {
    field
        .split(',')
        .filter_map(|member| {
            member
                .trim_start()
                .split_once(['=', ';'])
                .map(|(key, _)| key)
                .or_else(|| Some(member.trim()))
        })
        .filter(|key| *key == wanted)
        .count()
}

fn replace_content_digest(
    signature_base: &mut Vec<u8>,
    supplied_digest: &str,
) -> Result<(), VerifyError> {
    let base = std::str::from_utf8(signature_base).map_err(|_| VerifyError::MalformedSignature)?;
    let prefix = "\"content-digest\": ";
    let value_start = base.find(prefix).ok_or(VerifyError::MissingComponent)? + prefix.len();
    let value_end = base[value_start..]
        .find('\n')
        .map(|offset| value_start + offset)
        .ok_or(VerifyError::MalformedSignature)?;
    signature_base.splice(
        value_start..value_end,
        supplied_digest.trim_matches([' ', '\t']).bytes(),
    );
    Ok(())
}

fn top_level_member_count(field: &str) -> usize {
    if field.trim().is_empty() {
        return 0;
    }
    let mut count = 1;
    scan_unquoted(field, |byte, depth| {
        if byte == b',' && depth == 0 {
            count += 1;
        }
    });
    count
}

fn top_level_parameter_count(field: &str) -> usize {
    let mut count = 0;
    scan_unquoted(field, |byte, depth| {
        if byte == b';' && depth == 0 {
            count += 1;
        }
    });
    count
}

fn scan_unquoted(field: &str, mut visit: impl FnMut(u8, usize)) {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_binary = false;
    for byte in field.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        if in_binary {
            if byte == b':' {
                in_binary = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b':' => in_binary = true,
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ => visit(byte, depth),
        }
    }
}

fn fingerprint(
    parts0: &[u8],
    parts1: &[u8],
    parts2: &[u8],
    parts3: &[u8],
    parts4: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [parts0, parts1, parts2, parts3, parts4] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}
