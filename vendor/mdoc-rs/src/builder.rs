//! Document builder for mdoc issuance (feature: `issue`).

use coset::{iana, CborSerializable};
use std::collections::{HashMap, HashSet};

use crate::cbor::data_item;
use crate::error::MdocError;
use crate::model::document::{IssuerSigned, IssuerSignedDocument};
use crate::model::issuer_auth::IssuerAuth;
use crate::model::issuer_signed_item::IssuerSignedItem;
use crate::model::types::{DigestAlgorithm, ValidityInfo};

/// Trait for COSE signing operations.
pub trait CoseSigner: Send + Sync {
    /// Sign the to-be-signed data and return the signature bytes.
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, MdocError>;

    /// The COSE algorithm identifier (e.g., -7 for ES256).
    fn algorithm(&self) -> i64;

    /// The issuer certificate (DER-encoded X.509).
    fn certificate_der(&self) -> &[u8];
}

/// Builder for creating issuer-signed mdoc documents.
pub struct DocumentBuilder {
    doc_type: String,
    name_spaces: HashMap<String, Vec<(String, ciborium::Value)>>,
    device_key: Option<coset::CoseKey>,
    validity_info: Option<ValidityInfo>,
    digest_algorithm: DigestAlgorithm,
    status: Option<ciborium::Value>,
    auto_tag: bool,
}

/// Default CBOR tag for a well-known mdoc / EUDIW PID data element.
///
/// ISO 18013-5 and the EUDIW PID rule book require certain date-valued elements
/// to be wrapped in a CBOR tag *inside* `elementValue` (so the tag is covered by
/// the issuer digest). Getting this wrong silently produces a non-interoperable
/// credential, so [`DocumentBuilder`] applies these tags automatically unless
/// the caller already tagged the value or disabled auto-tagging.
///
/// Mirrors `pyMDOC-CBOR`'s `CBORTAGS_ATTR_MAP`:
/// - `birth_date`, `expiry_date`, `issue_date`, `issuance_date` -> Tag 1004 (full-date)
/// - `effective_from_date` -> Tag 0 (tdate)
pub fn default_element_tag(element_id: &str) -> Option<u64> {
    match element_id {
        "birth_date" | "expiry_date" | "issue_date" | "issuance_date" => {
            Some(crate::cbor::date::TAG_FULL_DATE)
        }
        "effective_from_date" => Some(0),
        _ => None,
    }
}

/// Apply the default tag for `element_id` to `value`.
///
/// Only explicitly-known composite elements recurse into nested members. This
/// avoids silently rewriting arbitrary extension payloads that happen to use a
/// familiar field name like `issue_date`.
fn auto_tag_value(element_id: &str, value: ciborium::Value) -> ciborium::Value {
    if matches!(value, ciborium::Value::Tag(..)) {
        return value;
    }
    if let Some(tag) = default_element_tag(element_id) {
        return ciborium::Value::Tag(tag, Box::new(value));
    }

    if element_id != "driving_privileges" {
        return value;
    }

    match value {
        ciborium::Value::Array(items) => {
            ciborium::Value::Array(items.into_iter().map(auto_tag_driving_privilege).collect())
        }
        other => other,
    }
}

fn auto_tag_driving_privilege(value: ciborium::Value) -> ciborium::Value {
    match value {
        ciborium::Value::Map(entries) => ciborium::Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| match &k {
                    ciborium::Value::Text(key) => {
                        let key = key.clone();
                        (k, auto_tag_value(&key, v))
                    }
                    _ => (k, v),
                })
                .collect(),
        ),
        other => other,
    }
}

/// Draw a fresh random `digestID` not already in `used`, inserting it before
/// returning. ISO 18013-5 recommends random (non-sequential) digest IDs to
/// prevent cross-presentation correlation (#7).
fn next_random_digest_id(used: &mut HashSet<u32>) -> u32 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    loop {
        let candidate: u32 = rng.gen();
        if used.insert(candidate) {
            return candidate;
        }
    }
}

impl DocumentBuilder {
    /// Create a new document builder for the given document type.
    pub fn new(doc_type: &str) -> Self {
        Self {
            doc_type: doc_type.to_string(),
            name_spaces: HashMap::new(),
            device_key: None,
            validity_info: None,
            digest_algorithm: DigestAlgorithm::Sha256,
            status: None,
            auto_tag: true,
        }
    }

    /// Add attributes to a namespace.
    pub fn add_namespace(
        mut self,
        namespace: &str,
        attributes: Vec<(&str, ciborium::Value)>,
    ) -> Self {
        let entries: Vec<(String, ciborium::Value)> = attributes
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        self.name_spaces
            .entry(namespace.to_string())
            .or_default()
            .extend(entries);
        self
    }

    /// Set the device public key.
    pub fn device_key(mut self, key: coset::CoseKey) -> Self {
        self.device_key = Some(key);
        self
    }

    /// Set the validity information.
    pub fn validity(mut self, info: ValidityInfo) -> Self {
        self.validity_info = Some(info);
        self
    }

    /// Set the digest algorithm.
    pub fn digest_algorithm(mut self, alg: DigestAlgorithm) -> Self {
        self.digest_algorithm = alg;
        self
    }

    /// Enable or disable automatic CBOR tagging of well-known data elements
    /// (see [`default_element_tag`]). Enabled by default. Disable it when the
    /// caller takes full responsibility for wrapping values in the correct tags.
    pub fn auto_tag(mut self, enabled: bool) -> Self {
        self.auto_tag = enabled;
        self
    }

    /// Set the MSO `status` element to an IETF Token Status List reference
    /// (`status_list: { idx, uri }`). Embedded into the signed MSO so verifiers
    /// can look up revocation state.
    pub fn status_list(mut self, idx: u64, uri: &str) -> Self {
        let status_list = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("idx".to_string()),
                ciborium::Value::Integer(ciborium::value::Integer::from(idx)),
            ),
            (
                ciborium::Value::Text("uri".to_string()),
                ciborium::Value::Text(uri.to_string()),
            ),
        ]);
        self.status = Some(ciborium::Value::Map(vec![(
            ciborium::Value::Text("status_list".to_string()),
            status_list,
        )]));
        self
    }

    /// Set the MSO `status` element to an arbitrary CBOR value (for status
    /// mechanisms other than the Token Status List).
    pub fn status_raw(mut self, status: ciborium::Value) -> Self {
        self.status = Some(status);
        self
    }

    /// Build and sign the document.
    ///
    /// 1. Generate IssuerSignedItems with random salts for each attribute
    /// 2. Compute digests for each item
    /// 3. Build the MSO with valueDigests
    /// 4. Wrap MSO in COSE_Sign1 using the provided signer
    /// 5. Return the IssuerSignedDocument
    pub fn sign(self, signer: &dyn CoseSigner) -> Result<IssuerSignedDocument, MdocError> {
        let validity = self
            .validity_info
            .ok_or_else(|| MdocError::Issuance("missing validity info".to_string()))?;

        let mut name_spaces: HashMap<String, Vec<IssuerSignedItem>> = HashMap::new();
        let mut value_digests: HashMap<String, HashMap<u32, Vec<u8>>> = HashMap::new();
        let mut used_digest_ids = HashSet::new();

        for (namespace, attributes) in &self.name_spaces {
            let mut items = Vec::new();
            let mut ns_digests = HashMap::new();

            for (elem_id, elem_value) in attributes {
                let digest_id = next_random_digest_id(&mut used_digest_ids);

                let elem_value = if self.auto_tag {
                    auto_tag_value(elem_id, elem_value.clone())
                } else {
                    elem_value.clone()
                };

                let mut random = vec![0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random);

                let item_map = ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("digestID".to_string()),
                        ciborium::Value::Integer(ciborium::value::Integer::from(digest_id)),
                    ),
                    (
                        ciborium::Value::Text("random".to_string()),
                        ciborium::Value::Bytes(random.clone()),
                    ),
                    (
                        ciborium::Value::Text("elementIdentifier".to_string()),
                        ciborium::Value::Text(elem_id.clone()),
                    ),
                    (
                        ciborium::Value::Text("elementValue".to_string()),
                        elem_value.clone(),
                    ),
                ]);

                let encoded = data_item::encode_cbor_canonical(&item_map)?;

                let item = IssuerSignedItem {
                    digest_id,
                    random,
                    element_identifier: elem_id.clone(),
                    element_value: elem_value.clone(),
                    encoded,
                };

                let digest = item.compute_digest(&self.digest_algorithm);

                ns_digests.insert(digest_id, digest);
                items.push(item);
            }

            name_spaces.insert(namespace.clone(), items);
            value_digests.insert(namespace.clone(), ns_digests);
        }

        let mso_map = build_mso_cbor(
            &self.doc_type,
            &self.digest_algorithm,
            &validity,
            &value_digests,
            self.device_key.as_ref(),
            self.status.as_ref(),
        )?;

        let mso_inner = data_item::encode_cbor_canonical(&mso_map)?;
        let mso_bytes = data_item::encode_cbor_canonical(&data_item::wrap_tag24(&mso_inner))?;

        let alg = match signer.algorithm() {
            -7 => iana::Algorithm::ES256,
            -35 => iana::Algorithm::ES384,
            -36 => iana::Algorithm::ES512,
            -8 => iana::Algorithm::EdDSA,
            other => {
                return Err(MdocError::Issuance(format!(
                    "unsupported COSE algorithm: {other}"
                )))
            }
        };

        let protected = coset::HeaderBuilder::new().algorithm(alg).build();

        let cert_der = signer.certificate_der().to_vec();
        let mut unprotected = coset::Header::default();
        unprotected
            .rest
            .push((coset::Label::Int(33), ciborium::Value::Bytes(cert_der)));

        let cose_sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(mso_bytes)
            .try_create_signature(&[], |tbs| signer.sign(tbs))
            .map_err(|e| MdocError::Issuance(format!("COSE_Sign1 signing: {e}")))?
            .build();

        let issuer_auth = IssuerAuth::new(cose_sign1);

        Ok(IssuerSignedDocument {
            doc_type: self.doc_type,
            issuer_signed: IssuerSigned {
                issuer_auth,
                name_spaces,
            },
            device_signed: None,
        })
    }
}

/// Build the MSO as a CBOR Value.
fn build_mso_cbor(
    doc_type: &str,
    digest_algorithm: &DigestAlgorithm,
    validity: &ValidityInfo,
    value_digests: &HashMap<String, HashMap<u32, Vec<u8>>>,
    device_key: Option<&coset::CoseKey>,
    status: Option<&ciborium::Value>,
) -> Result<ciborium::Value, MdocError> {
    let mut vd_entries = Vec::new();
    for (ns, digests) in value_digests {
        let mut digest_entries = Vec::new();
        for (id, digest) in digests {
            digest_entries.push((
                ciborium::Value::Integer(ciborium::value::Integer::from(*id)),
                ciborium::Value::Bytes(digest.clone()),
            ));
        }
        vd_entries.push((
            ciborium::Value::Text(ns.clone()),
            ciborium::Value::Map(digest_entries),
        ));
    }

    let validity_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("signed".to_string()),
            tdate(&validity.signed),
        ),
        (
            ciborium::Value::Text("validFrom".to_string()),
            tdate(&validity.valid_from),
        ),
        (
            ciborium::Value::Text("validUntil".to_string()),
            tdate(&validity.valid_until),
        ),
    ]);

    let mut mso_entries = vec![
        (
            ciborium::Value::Text("version".to_string()),
            ciborium::Value::Text("1.0".to_string()),
        ),
        (
            ciborium::Value::Text("digestAlgorithm".to_string()),
            ciborium::Value::Text(digest_algorithm.name().to_string()),
        ),
        (
            ciborium::Value::Text("docType".to_string()),
            ciborium::Value::Text(doc_type.to_string()),
        ),
        (
            ciborium::Value::Text("valueDigests".to_string()),
            ciborium::Value::Map(vd_entries),
        ),
        (
            ciborium::Value::Text("validityInfo".to_string()),
            validity_map,
        ),
    ];

    if let Some(key) = device_key {
        let key_bytes = key
            .clone()
            .to_vec()
            .map_err(|e| MdocError::Issuance(format!("encode COSE_Key: {e}")))?;
        let key_value: ciborium::Value = ciborium::from_reader(key_bytes.as_slice())
            .map_err(|e| MdocError::Issuance(format!("re-decode COSE_Key: {e}")))?;

        let device_key_info = ciborium::Value::Map(vec![(
            ciborium::Value::Text("deviceKey".to_string()),
            key_value,
        )]);

        mso_entries.push((
            ciborium::Value::Text("deviceKeyInfo".to_string()),
            device_key_info,
        ));
    }

    if let Some(status) = status {
        mso_entries.push((ciborium::Value::Text("status".to_string()), status.clone()));
    }

    Ok(ciborium::Value::Map(mso_entries))
}

fn tdate(value: &chrono::DateTime<chrono::Utc>) -> ciborium::Value {
    ciborium::Value::Tag(
        0,
        Box::new(ciborium::Value::Text(value.to_rfc3339_opts(
            chrono::SecondsFormat::Secs,
            true,
        ))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tdate_uses_second_precision_and_utc_z() {
        let value = chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00.123+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            tdate(&value),
            ciborium::Value::Tag(
                0,
                Box::new(ciborium::Value::Text("2026-09-01T00:00:00Z".into()))
            )
        );
    }

    #[test]
    fn well_known_dates_get_default_tags() {
        assert_eq!(default_element_tag("birth_date"), Some(1004));
        assert_eq!(default_element_tag("issue_date"), Some(1004));
        assert_eq!(default_element_tag("expiry_date"), Some(1004));
        assert_eq!(default_element_tag("issuance_date"), Some(1004));
        assert_eq!(default_element_tag("effective_from_date"), Some(0));
        assert_eq!(default_element_tag("family_name"), None);
    }

    #[test]
    fn auto_tag_wraps_date_values() {
        let v = auto_tag_value("birth_date", ciborium::Value::Text("1990-01-15".into()));
        match v {
            ciborium::Value::Tag(1004, inner) => {
                assert_eq!(*inner, ciborium::Value::Text("1990-01-15".into()))
            }
            other => panic!("expected Tag 1004, got {other:?}"),
        }
    }

    #[test]
    fn auto_tag_respects_existing_tag() {
        let pre = ciborium::Value::Tag(0, Box::new(ciborium::Value::Text("x".into())));
        assert_eq!(auto_tag_value("birth_date", pre.clone()), pre);
    }

    #[test]
    fn auto_tag_leaves_plain_values_untouched() {
        let v = ciborium::Value::Text("Doe".into());
        assert_eq!(auto_tag_value("family_name", v.clone()), v);
    }

    #[test]
    fn auto_tag_recurses_into_driving_privileges() {
        let priv_entry = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("vehicle_category_code".into()),
                ciborium::Value::Text("A".into()),
            ),
            (
                ciborium::Value::Text("issue_date".into()),
                ciborium::Value::Text("2018-08-09".into()),
            ),
            (
                ciborium::Value::Text("expiry_date".into()),
                ciborium::Value::Text("2024-10-20".into()),
            ),
        ]);
        let tagged = auto_tag_value(
            "driving_privileges",
            ciborium::Value::Array(vec![priv_entry]),
        );
        let arr = tagged.as_array().unwrap();
        let map = arr[0].as_map().unwrap();
        for (k, v) in map {
            match k.as_text().unwrap() {
                "issue_date" | "expiry_date" => {
                    assert!(
                        matches!(v, ciborium::Value::Tag(1004, _)),
                        "date should be tagged"
                    );
                }
                "vehicle_category_code" => {
                    assert!(matches!(v, ciborium::Value::Text(_)), "code stays untagged");
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn auto_tag_does_not_rewrite_unknown_nested_payloads() {
        let payload = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("issue_date".into()),
                ciborium::Value::Text("2024-10-20".into()),
            ),
            (
                ciborium::Value::Text("meta".into()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Text("expiry_date".into()),
                    ciborium::Value::Text("2025-10-20".into()),
                )]),
            ),
        ]);

        assert_eq!(auto_tag_value("custom_extension", payload.clone()), payload);
    }

    #[test]
    fn random_digest_ids_are_unique() {
        let mut used = HashSet::new();
        let ids: Vec<u32> = (0..1000)
            .map(|_| next_random_digest_id(&mut used))
            .collect();
        let distinct: HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(distinct.len(), ids.len(), "all digestIDs must be unique");
    }
}
