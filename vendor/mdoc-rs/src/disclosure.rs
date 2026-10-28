//! Selective disclosure digest verification.
//!
//! For each disclosed `IssuerSignedItem`, computes the digest of its CBOR encoding
//! and matches it against `valueDigests[digestID]` in the MSO.

use crate::error::MdocError;
use crate::model::{types::Mso, IssuerSignedItem};

/// Result of verifying selective disclosure for a single namespace.
#[derive(Clone, Debug)]
pub struct NamespaceDisclosureResult {
    /// Namespace name.
    pub namespace: String,
    /// Per-attribute results.
    pub attributes: Vec<AttributeDisclosureResult>,
    /// Overall validity.
    pub is_valid: bool,
}

/// Result of verifying a single attribute's digest.
#[derive(Clone, Debug)]
pub struct AttributeDisclosureResult {
    /// Attribute name.
    pub element_identifier: String,
    /// Digest ID.
    pub digest_id: u32,
    /// Whether the digest matched.
    pub digest_matches: bool,
    /// Reason for failure, if any.
    pub reason: Option<String>,
}

/// Verify selective disclosure for all namespaces in a document against the MSO.
pub fn verify_disclosure(
    name_spaces: &std::collections::HashMap<String, Vec<IssuerSignedItem>>,
    mso: &Mso,
) -> Result<Vec<NamespaceDisclosureResult>, MdocError> {
    let mut results = Vec::new();

    for (namespace, items) in name_spaces {
        let mso_digests = mso.value_digests.get(namespace);
        let mut attr_results = Vec::new();
        let mut all_valid = true;

        // Check that the MSO has digests for this namespace
        if mso_digests.is_none() {
            attr_results.push(AttributeDisclosureResult {
                element_identifier: format!("[namespace: {namespace}]"),
                digest_id: 0,
                digest_matches: false,
                reason: Some("namespace not found in MSO valueDigests".to_string()),
            });
            all_valid = false;
        }

        for item in items {
            let result = if let Some(digests) = mso_digests {
                if let Some(expected_digest) = digests.get(&item.digest_id) {
                    let matches = item.verify_digest(expected_digest, &mso.digest_algorithm);
                    AttributeDisclosureResult {
                        element_identifier: item.element_identifier.clone(),
                        digest_id: item.digest_id,
                        digest_matches: matches,
                        reason: if matches {
                            None
                        } else {
                            Some("digest mismatch".to_string())
                        },
                    }
                } else {
                    AttributeDisclosureResult {
                        element_identifier: item.element_identifier.clone(),
                        digest_id: item.digest_id,
                        digest_matches: false,
                        reason: Some(format!(
                            "digestID {} not found in MSO for namespace {namespace}",
                            item.digest_id
                        )),
                    }
                }
            } else {
                AttributeDisclosureResult {
                    element_identifier: item.element_identifier.clone(),
                    digest_id: item.digest_id,
                    digest_matches: false,
                    reason: Some("namespace missing from MSO".to_string()),
                }
            };

            if !result.digest_matches {
                all_valid = false;
            }
            attr_results.push(result);
        }

        results.push(NamespaceDisclosureResult {
            namespace: namespace.clone(),
            attributes: attr_results,
            is_valid: all_valid,
        });
    }

    Ok(results)
}
