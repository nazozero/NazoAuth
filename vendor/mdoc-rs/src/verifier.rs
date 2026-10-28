//! Main mdoc verification pipeline.
//!
//! Runs verification checks across four categories — IssuerAuth, DeviceAuth,
//! DataIntegrity, DocumentFormat — and aggregates them into an overall
//! `is_valid` verdict.
//!
//! ## Trust model enforced
//!
//! - **Issuer authentication** — the leaf (Document Signer) certificate in the
//!   credential's `x5chain` is path-validated up to one of the caller-supplied
//!   IACA trust anchors (`tsp` feature), and the issuerAuth COSE_Sign1 is
//!   verified against that leaf's public key.
//! - **Data integrity** — every disclosed attribute hashes to the digest
//!   committed in the signed MSO (over the Tag-24-wrapped item bytes).
//! - **Device (holder) authentication** — the `deviceSignature`/`deviceMac` is
//!   cryptographically verified against the device key bound in the MSO, over
//!   the `DeviceAuthentication` structure built from the session transcript.
//!
//! ## `is_valid` is fail-closed
//!
//! `is_valid` is `true` only when **all required checks were actually run and
//! passed** — a missing or skipped security check makes the result invalid, and
//! no security-relevant condition is downgraded to a non-fatal `Warning`.

use std::collections::HashSet;

use coset::CborSerializable;

use crate::disclosure;
use crate::error::MdocError;
use crate::model::*;
use crate::session::SessionTranscript;

/// Verification check categories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationCategory {
    IssuerAuth,
    DeviceAuth,
    DataIntegrity,
    DocumentFormat,
}

/// Verification check identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CheckId {
    // ISSUER_AUTH
    IssuerCertificateValidity,
    IssuerSignatureValidity,
    MsoSignedDateWithinCertificateValidity,
    MsoValidityAtVerificationTime,
    IssuerSubjectCountryNamePresence,

    // DEVICE_AUTH
    DocumentDeviceSignaturePresence,
    DeviceAuthSignatureOrMacPresence,
    SessionTranscriptProvided,
    DeviceKeyAvailableInIssuerAuth,
    DeviceSignatureValidity,
    DeviceMacPresence,
    DeviceMacAlgorithmCorrectness,
    EphemeralKeyPresence,
    DeviceMacValidity,
    DeviceKeyAuthorizationsRespected,
    /// Synthetic requirement satisfied by either `DeviceSignatureValidity` or
    /// `DeviceMacValidity`; never emitted as an assessment, only used by the
    /// fail-closed aggregator to require that *some* device-auth validity check
    /// ran for a device-bound document.
    DeviceAuthValidity,

    // DATA_INTEGRITY
    IssuerAuthDigestAlgorithmSupported,
    IssuerAuthNamespaceDigestPresence,
    AttributeDigestMatch,
    IssuerSignedItemRandomSufficient,
    DocTypeMatch,
    IssuingCountryMatchesCertificate,
    IssuingJurisdictionMatchesCertificate,

    // DOCUMENT_FORMAT
    DeviceResponseVersionPresence,
    DeviceResponseVersionSupported,
    DeviceResponseDocumentPresence,
    MdocStatusOk,
}

/// Status of a verification check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationStatus {
    Passed,
    Failed,
    Warning,
}

/// Result of a single verification check.
#[derive(Clone, Debug)]
pub struct VerificationAssessment {
    pub status: VerificationStatus,
    pub check: String,
    pub reason: Option<String>,
    pub category: VerificationCategory,
    pub id: CheckId,
}

/// Callback for custom verification logic.
pub type OnCheckFn = Box<dyn Fn(&VerificationAssessment)>;

/// Options for verification.
#[derive(Default)]
pub struct VerifyOptions<'a> {
    /// Session transcript for device authentication.
    pub session_transcript: Option<SessionTranscript<'a>>,
    /// Ephemeral reader key for MAC verification.
    pub ephemeral_reader_key: Option<Vec<u8>>,
    /// Disable certificate chain validation.
    pub disable_certificate_chain_validation: bool,
    /// Callback for each verification check.
    pub on_check: Option<OnCheckFn>,
}

/// Verified MDoc result.
#[derive(Clone, Debug)]
pub struct VerifiedMDoc {
    /// The parsed MDoc.
    pub mdoc: MDoc,
    /// All verification assessments.
    pub assessments: Vec<VerificationAssessment>,
    /// Overall validity.
    pub is_valid: bool,
}

/// MDoc verifier.
pub struct Verifier {
    /// IACA root certificates (DER-encoded) used as trust anchors for x5chain
    /// path validation. Consumed by chain validation under the `tsp` feature.
    #[cfg_attr(not(feature = "tsp"), allow(dead_code))]
    iaca_root_certs: Vec<Vec<u8>>,
}

impl Verifier {
    /// Create a new verifier with IACA root certificates.
    pub fn new(iaca_root_certs: Vec<Vec<u8>>) -> Self {
        Self { iaca_root_certs }
    }

    /// Verify a CBOR-encoded DeviceResponse.
    pub fn verify(
        &self,
        encoded_device_response: &[u8],
        opts: &VerifyOptions,
    ) -> Result<VerifiedMDoc, MdocError> {
        let mdoc = crate::parser::parse(encoded_device_response)?;
        let mut assessments = Vec::new();

        // Required checks that MUST be present and Passed for is_valid. A check
        // that never ran (e.g. device auth silently skipped) leaves its id out
        // of this set, which makes the verdict fail closed.
        let mut required: HashSet<CheckId> = HashSet::new();
        required.insert(CheckId::DeviceResponseVersionSupported);
        required.insert(CheckId::DeviceResponseDocumentPresence);
        required.insert(CheckId::MdocStatusOk);

        // DOCUMENT_FORMAT checks
        self.check_document_format(&mdoc, &mut assessments, opts);

        // Per-document checks
        for doc in &mdoc.documents {
            // ISSUER_AUTH checks (incl. IACA chain anchoring)
            self.check_issuer_auth(doc, &mut assessments, opts);
            required.insert(CheckId::IssuerCertificateValidity);
            required.insert(CheckId::IssuerSignatureValidity);
            required.insert(CheckId::MsoValidityAtVerificationTime);

            // DATA_INTEGRITY checks
            self.check_data_integrity(doc, &mut assessments, opts);
            required.insert(CheckId::IssuerAuthDigestAlgorithmSupported);
            required.insert(CheckId::DocTypeMatch);

            // DEVICE_AUTH checks — mandatory whenever the document carries a
            // deviceSigned (a device-bound presentation must prove holder
            // binding; see CRITICAL-2 / HIGH-1).
            if doc.device_signed.is_some() {
                self.check_device_auth(doc, &mut assessments, opts);
                required.insert(CheckId::SessionTranscriptProvided);
                required.insert(CheckId::DeviceKeyAvailableInIssuerAuth);
                required.insert(CheckId::DeviceAuthValidity);
            }
        }

        let is_valid = Self::aggregate_validity(&assessments, &required, &mdoc);

        Ok(VerifiedMDoc {
            mdoc,
            assessments,
            is_valid,
        })
    }

    /// Fail-closed aggregation (HIGH-1).
    ///
    /// `is_valid` requires that:
    /// 1. no assessment is `Failed` or `Warning` (no security check may be
    ///    downgraded to a non-fatal warning), and
    /// 2. every required check actually ran and is present, and
    /// 3. for each device-bound document, a device-auth *validity* check
    ///    (`DeviceSignatureValidity` or `DeviceMacValidity`) was emitted.
    ///
    /// `DeviceAuthValidity` is a synthetic requirement satisfied by either the
    /// signature or the MAC validity check.
    fn aggregate_validity(
        assessments: &[VerificationAssessment],
        required: &HashSet<CheckId>,
        mdoc: &MDoc,
    ) -> bool {
        // (1) Any non-Passed assessment is disqualifying.
        if assessments
            .iter()
            .any(|a| a.status != VerificationStatus::Passed)
        {
            return false;
        }

        let present: HashSet<&CheckId> = assessments.iter().map(|a| &a.id).collect();

        // (3) Device-auth validity is satisfied by either sig or mac validity.
        let device_auth_validity_present = present.contains(&CheckId::DeviceSignatureValidity)
            || present.contains(&CheckId::DeviceMacValidity);

        // (2) Every required check must be present.
        for id in required {
            match id {
                CheckId::DeviceAuthValidity => {
                    if !device_auth_validity_present {
                        return false;
                    }
                }
                other => {
                    if !present.contains(other) {
                        return false;
                    }
                }
            }
        }

        // A response carrying no documents at all is never valid, even though
        // the per-document required checks would be vacuously satisfied.
        if mdoc.documents.is_empty() {
            return false;
        }

        true
    }

    fn check_document_format(
        &self,
        mdoc: &MDoc,
        assessments: &mut Vec<VerificationAssessment>,
        opts: &VerifyOptions,
    ) {
        // Version presence
        let version_check = VerificationAssessment {
            status: VerificationStatus::Passed,
            check: "Device response version present".to_string(),
            reason: None,
            category: VerificationCategory::DocumentFormat,
            id: CheckId::DeviceResponseVersionPresence,
        };
        emit(assessments, version_check, opts);

        // Version supported
        let version_supported = if mdoc.version == "1.0" {
            VerificationAssessment {
                status: VerificationStatus::Passed,
                check: "Device response version supported".to_string(),
                reason: None,
                category: VerificationCategory::DocumentFormat,
                id: CheckId::DeviceResponseVersionSupported,
            }
        } else {
            VerificationAssessment {
                status: VerificationStatus::Failed,
                check: "Device response version supported".to_string(),
                reason: Some(format!("unsupported version: {}", mdoc.version)),
                category: VerificationCategory::DocumentFormat,
                id: CheckId::DeviceResponseVersionSupported,
            }
        };
        emit(assessments, version_supported, opts);

        // Documents present
        let docs_present = if !mdoc.documents.is_empty() {
            VerificationAssessment {
                status: VerificationStatus::Passed,
                check: "Documents present in response".to_string(),
                reason: None,
                category: VerificationCategory::DocumentFormat,
                id: CheckId::DeviceResponseDocumentPresence,
            }
        } else {
            VerificationAssessment {
                status: VerificationStatus::Failed,
                check: "Documents present in response".to_string(),
                reason: Some("no documents in device response".to_string()),
                category: VerificationCategory::DocumentFormat,
                id: CheckId::DeviceResponseDocumentPresence,
            }
        };
        emit(assessments, docs_present, opts);

        // DeviceResponse status must be 0 (OK). A non-OK or undecodable status
        // (the parser maps decode failures to a general error, not OK) is
        // treated as a failure rather than being ignored (INFO-3).
        let status_check = if mdoc.status == MDocStatus::Ok {
            VerificationAssessment {
                status: VerificationStatus::Passed,
                check: "DeviceResponse status OK".to_string(),
                reason: None,
                category: VerificationCategory::DocumentFormat,
                id: CheckId::MdocStatusOk,
            }
        } else {
            VerificationAssessment {
                status: VerificationStatus::Failed,
                check: "DeviceResponse status OK".to_string(),
                reason: Some(format!("non-OK status: {:?}", mdoc.status)),
                category: VerificationCategory::DocumentFormat,
                id: CheckId::MdocStatusOk,
            }
        };
        emit(assessments, status_check, opts);
    }

    fn check_issuer_auth(
        &self,
        doc: &IssuerSignedDocument,
        assessments: &mut Vec<VerificationAssessment>,
        opts: &VerifyOptions,
    ) {
        // IssuerCertificateValidity — path-validate the credential's x5chain up
        // to a trusted IACA anchor (CRITICAL-1). The leaf-cert-parses-ok check
        // that this replaced provided no trust assurance whatsoever.
        let cert_check = self.verify_certificate_chain(doc, opts);
        emit(assessments, cert_check, opts);

        // Issuer signature validity — verify COSE_Sign1 using the leaf cert's
        // public key.
        let sig_check = self.verify_issuer_signature(doc);
        emit(assessments, sig_check, opts);

        // MSO validity dates
        let validity_check = self.verify_mso_validity(doc);
        emit(assessments, validity_check, opts);
    }

    /// Path-validate the issuer (Document Signer) certificate chain against the
    /// configured IACA trust anchors (CRITICAL-1).
    ///
    /// With the `tsp` feature this builds the chain from the credential's
    /// `x5chain` and verifies it (issuer/subject linkage, per-link signatures,
    /// CA constraints, and time validity at the MSO `signed` time) up to a
    /// caller-supplied anchor. Without `tsp` it fails closed.
    ///
    /// `disable_certificate_chain_validation` is honoured only as an explicit,
    /// loudly-logged test opt-out: it produces a `Passed` assessment whose
    /// reason states that issuer trust was NOT verified.
    fn verify_certificate_chain(
        &self,
        doc: &IssuerSignedDocument,
        opts: &VerifyOptions,
    ) -> VerificationAssessment {
        let pass = |reason: Option<String>| VerificationAssessment {
            status: VerificationStatus::Passed,
            check: "Issuer certificate chain to IACA trust anchor".to_string(),
            reason,
            category: VerificationCategory::IssuerAuth,
            id: CheckId::IssuerCertificateValidity,
        };
        let fail = |reason: String| VerificationAssessment {
            status: VerificationStatus::Failed,
            check: "Issuer certificate chain to IACA trust anchor".to_string(),
            reason: Some(reason),
            category: VerificationCategory::IssuerAuth,
            id: CheckId::IssuerCertificateValidity,
        };

        if opts.disable_certificate_chain_validation {
            log::warn!(
                "certificate chain validation DISABLED by caller — issuer trust is NOT verified"
            );
            return pass(Some(
                "certificate chain validation DISABLED by caller — issuer trust NOT verified"
                    .to_string(),
            ));
        }

        match self.validate_chain(doc) {
            Ok(()) => pass(None),
            Err(e) => fail(e),
        }
    }

    #[cfg(feature = "tsp")]
    fn validate_chain(&self, doc: &IssuerSignedDocument) -> Result<(), String> {
        use tsp_ltv::trust::{build_chain_from_pool, trust_anchor_subjects, TrustStore};

        if self.iaca_root_certs.is_empty() {
            return Err("no IACA trust anchors configured".to_string());
        }

        // Build the trust store from the caller's IACA roots.
        let mut store = TrustStore::new();
        for (i, der) in self.iaca_root_certs.iter().enumerate() {
            store
                .add_der_certificate(der)
                .map_err(|e| format!("invalid IACA root cert #{i}: {e}"))?;
        }

        // Parse the credential's x5chain into a certificate pool (leaf first).
        let chain_der = doc
            .issuer_signed
            .issuer_auth
            .certificate_chain_der()
            .map_err(|e| e.to_string())?;
        if chain_der.is_empty() {
            return Err("empty x5chain".to_string());
        }
        let mut pool: Vec<x509_cert::Certificate> = Vec::with_capacity(chain_der.len());
        for (i, der) in chain_der.iter().enumerate() {
            let cert = <x509_cert::Certificate as der::Decode>::from_der(der)
                .map_err(|e| format!("parse x5chain cert #{i}: {e}"))?;
            pool.push(cert);
        }
        let leaf = pool[0].clone();

        // Build the path from leaf to an anchor and verify it.
        let anchors = trust_anchor_subjects(&store);
        let chain = build_chain_from_pool(&leaf, &pool, &anchors, None)
            .map_err(|e| format!("chain building failed: {e}"))?;

        // Validate at the MSO signing time (ISO 18013-5: the Document Signer
        // cert must have been valid when it signed). This is also the
        // MsoSignedDateWithinCertificateValidity check.
        let validation_time = doc
            .issuer_signed
            .issuer_auth
            .mso()
            .ok()
            .and_then(|mso| chrono_to_der_datetime(mso.validity_info.signed));

        store
            .verify_chain(&chain, validation_time)
            .map(|_anchor| ())
            .map_err(|e| format!("chain not anchored to a trusted IACA root: {e}"))
    }

    #[cfg(not(feature = "tsp"))]
    fn validate_chain(&self, _doc: &IssuerSignedDocument) -> Result<(), String> {
        Err("certificate chain validation requires the `tsp` feature".to_string())
    }

    fn check_data_integrity(
        &self,
        doc: &IssuerSignedDocument,
        assessments: &mut Vec<VerificationAssessment>,
        opts: &VerifyOptions,
    ) {
        // Decode MSO
        let mso = match doc.issuer_signed.issuer_auth.mso() {
            Ok(mso) => mso,
            Err(e) => {
                let check = VerificationAssessment {
                    status: VerificationStatus::Failed,
                    check: "MSO decode".to_string(),
                    reason: Some(e.to_string()),
                    category: VerificationCategory::DataIntegrity,
                    id: CheckId::IssuerAuthDigestAlgorithmSupported,
                };
                emit(assessments, check, opts);
                return;
            }
        };

        // Digest algorithm supported
        let alg_check = VerificationAssessment {
            status: VerificationStatus::Passed,
            check: format!("Digest algorithm {} supported", mso.digest_algorithm.name()),
            reason: None,
            category: VerificationCategory::DataIntegrity,
            id: CheckId::IssuerAuthDigestAlgorithmSupported,
        };
        emit(assessments, alg_check, opts);

        // docType binding (HIGH-2): the document framing's docType must match
        // the signed MSO docType, otherwise an MSO for one document type could
        // be paired with a mismatched document.
        let doctype_check = if mso.doc_type == doc.doc_type {
            VerificationAssessment {
                status: VerificationStatus::Passed,
                check: "Document docType matches MSO".to_string(),
                reason: None,
                category: VerificationCategory::DataIntegrity,
                id: CheckId::DocTypeMatch,
            }
        } else {
            VerificationAssessment {
                status: VerificationStatus::Failed,
                check: "Document docType matches MSO".to_string(),
                reason: Some(format!(
                    "document docType {:?} != MSO docType {:?}",
                    doc.doc_type, mso.doc_type
                )),
                category: VerificationCategory::DataIntegrity,
                id: CheckId::DocTypeMatch,
            }
        };
        emit(assessments, doctype_check, opts);

        // Per-item salt entropy floor (MEDIUM-4): ISO 18013-5 requires the
        // `random` salt to be at least 16 bytes to resist value-guessing across
        // digests (notably for low-entropy attributes like age_over_NN).
        for (namespace, items) in &doc.issuer_signed.name_spaces {
            for item in items {
                if item.random.len() < 16 {
                    let check = VerificationAssessment {
                        status: VerificationStatus::Failed,
                        check: format!(
                            "IssuerSignedItem salt length: {}.{}",
                            namespace, item.element_identifier
                        ),
                        reason: Some(format!(
                            "random salt is {} bytes, minimum is 16",
                            item.random.len()
                        )),
                        category: VerificationCategory::DataIntegrity,
                        id: CheckId::IssuerSignedItemRandomSufficient,
                    };
                    emit(assessments, check, opts);
                }
            }
        }

        // Verify selective disclosure
        let disclosure_results =
            disclosure::verify_disclosure(&doc.issuer_signed.name_spaces, &mso);

        match disclosure_results {
            Ok(results) => {
                for ns_result in &results {
                    for attr in &ns_result.attributes {
                        let check = VerificationAssessment {
                            status: if attr.digest_matches {
                                VerificationStatus::Passed
                            } else {
                                VerificationStatus::Failed
                            },
                            check: format!(
                                "Attribute digest: {}.{}",
                                ns_result.namespace, attr.element_identifier
                            ),
                            reason: attr.reason.clone(),
                            category: VerificationCategory::DataIntegrity,
                            id: CheckId::AttributeDigestMatch,
                        };
                        emit(assessments, check, opts);
                    }
                }
            }
            Err(e) => {
                let check = VerificationAssessment {
                    status: VerificationStatus::Failed,
                    check: "Disclosure verification".to_string(),
                    reason: Some(e.to_string()),
                    category: VerificationCategory::DataIntegrity,
                    id: CheckId::AttributeDigestMatch,
                };
                emit(assessments, check, opts);
            }
        }
    }

    /// Cryptographically verify device (holder) authentication (CRITICAL-2).
    ///
    /// Decodes the device key bound in the MSO, reconstructs the
    /// `DeviceAuthentication` structure from the session transcript, the
    /// docType, and the preserved device-namespace bytes, then verifies the
    /// `deviceSignature` (COSE_Sign1) or `deviceMac` (COSE_Mac0). Emits a
    /// `Failed` `DeviceSignatureValidity`/`DeviceMacValidity` on any mismatch.
    /// Also enforces `keyAuthorizations` over the device-asserted namespaces
    /// (HIGH-2) and requires a session transcript (HIGH-1).
    fn check_device_auth(
        &self,
        doc: &IssuerSignedDocument,
        assessments: &mut Vec<VerificationAssessment>,
        opts: &VerifyOptions,
    ) {
        let device_signed = match &doc.device_signed {
            Some(ds) => ds,
            None => return,
        };

        // Device signature or MAC presence (the parser guarantees one exists).
        emit(
            assessments,
            VerificationAssessment {
                status: VerificationStatus::Passed,
                check: "Device auth signature or MAC present".to_string(),
                reason: None,
                category: VerificationCategory::DeviceAuth,
                id: CheckId::DeviceAuthSignatureOrMacPresence,
            },
            opts,
        );

        // Session transcript is REQUIRED for device-bound presentations
        // (HIGH-1): without it holder binding cannot be checked, so its absence
        // is a failure, not a warning.
        let session_transcript = match &opts.session_transcript {
            Some(st) => {
                emit(
                    assessments,
                    VerificationAssessment {
                        status: VerificationStatus::Passed,
                        check: "Session transcript provided".to_string(),
                        reason: None,
                        category: VerificationCategory::DeviceAuth,
                        id: CheckId::SessionTranscriptProvided,
                    },
                    opts,
                );
                st
            }
            None => {
                emit(
                    assessments,
                    VerificationAssessment {
                        status: VerificationStatus::Failed,
                        check: "Session transcript provided".to_string(),
                        reason: Some(
                            "no session transcript — device authentication cannot be verified"
                                .to_string(),
                        ),
                        category: VerificationCategory::DeviceAuth,
                        id: CheckId::SessionTranscriptProvided,
                    },
                    opts,
                );
                return;
            }
        };

        // Decode the device key from the MSO (DeviceKeyAvailableInIssuerAuth).
        let device_key = match doc
            .issuer_signed
            .issuer_auth
            .mso()
            .ok()
            .and_then(|mso| mso.device_key_info.map(|dki| dki.device_key))
        {
            Some(k) => {
                emit(
                    assessments,
                    VerificationAssessment {
                        status: VerificationStatus::Passed,
                        check: "Device key present in issuerAuth".to_string(),
                        reason: None,
                        category: VerificationCategory::DeviceAuth,
                        id: CheckId::DeviceKeyAvailableInIssuerAuth,
                    },
                    opts,
                );
                k
            }
            None => {
                emit(
                    assessments,
                    VerificationAssessment {
                        status: VerificationStatus::Failed,
                        check: "Device key present in issuerAuth".to_string(),
                        reason: Some("MSO has no deviceKeyInfo.deviceKey".to_string()),
                        category: VerificationCategory::DeviceAuth,
                        id: CheckId::DeviceKeyAvailableInIssuerAuth,
                    },
                    opts,
                );
                return;
            }
        };

        // keyAuthorizations enforcement (HIGH-2): device-asserted namespaces /
        // elements must fall within the authorizations bound to the device key.
        let auth_check = check_key_authorizations(doc, device_signed);
        emit(assessments, auth_check, opts);

        // Reconstruct DeviceAuthentication and verify the signature/MAC.
        let verify_result = (|| -> Result<crate::device_auth::DeviceAuthResult, MdocError> {
            let transcript_bytes = session_transcript.to_cbor_bytes()?;
            let device_auth_bytes = crate::session::build_device_authentication_bytes(
                &transcript_bytes,
                &doc.doc_type,
                &device_signed.name_spaces_bytes,
            )?;
            let device_key_bytes = device_key
                .clone()
                .to_vec()
                .map_err(|e| MdocError::DeviceAuth(format!("encode device COSE_Key: {e}")))?;

            // For MAC mode, derive the ephemeral MAC key from the reader's
            // ephemeral private key (opts.ephemeral_reader_key) and the device
            // public key via ECDH+HKDF (HIGH-3).
            let ephemeral_mac_key = match &device_signed.device_auth {
                DeviceAuth::Mac(_) => Some(self.derive_mac_key(
                    &device_key,
                    opts.ephemeral_reader_key.as_deref(),
                    &transcript_bytes,
                )?),
                DeviceAuth::Signature(_) => None,
            };

            crate::device_auth::verify_device_auth(
                &device_signed.device_auth,
                &device_auth_bytes,
                &device_key_bytes,
                ephemeral_mac_key.as_ref(),
            )
        })();

        let (id, label) = match &device_signed.device_auth {
            DeviceAuth::Signature(_) => (
                CheckId::DeviceSignatureValidity,
                "Device signature validity",
            ),
            DeviceAuth::Mac(_) => (CheckId::DeviceMacValidity, "Device MAC validity"),
        };

        let check = match verify_result {
            Ok(res) if res.is_valid => VerificationAssessment {
                status: VerificationStatus::Passed,
                check: label.to_string(),
                reason: None,
                category: VerificationCategory::DeviceAuth,
                id,
            },
            Ok(res) => VerificationAssessment {
                status: VerificationStatus::Failed,
                check: label.to_string(),
                reason: Some(res.reasons.join("; ")),
                category: VerificationCategory::DeviceAuth,
                id,
            },
            Err(e) => VerificationAssessment {
                status: VerificationStatus::Failed,
                check: label.to_string(),
                reason: Some(e.to_string()),
                category: VerificationCategory::DeviceAuth,
                id,
            },
        };
        emit(assessments, check, opts);
    }

    /// Derive the ephemeral MAC key for COSE_Mac0 device auth (HIGH-3).
    ///
    /// `EMacKey = HKDF(ECDH(reader_ephemeral_priv, device_pub), salt =
    /// SHA-256(SessionTranscriptBytes), info = "EMacKey")`. ECDH is symmetric
    /// with the holder's `ECDH(device_priv, reader_ephemeral_pub)`, so this
    /// reproduces the same key the holder used to compute the tag.
    fn derive_mac_key(
        &self,
        device_key: &coset::CoseKey,
        ephemeral_reader_key: Option<&[u8]>,
        transcript_bytes: &[u8],
    ) -> Result<[u8; 32], MdocError> {
        use crate::cose::key::CoseKeyExt;

        let reader_priv = ephemeral_reader_key.ok_or_else(|| {
            MdocError::DeviceAuth(
                "MAC-based device auth requires ephemeral_reader_key in VerifyOptions".to_string(),
            )
        })?;

        let device_pub_sec1 = device_key.public_key_bytes()?;
        let shared = ecdh_p256_shared_secret(reader_priv, &device_pub_sec1)?;
        crate::session::derive_ephemeral_mac_key(&shared, transcript_bytes)
    }

    /// Verify the issuer's COSE_Sign1 signature using the public key from the x5chain certificate.
    fn verify_issuer_signature(&self, doc: &IssuerSignedDocument) -> VerificationAssessment {
        let result = (|| -> Result<bool, MdocError> {
            crate::cose::validate_critical_headers(
                &doc.issuer_signed.issuer_auth.cose_sign1.protected,
                &doc.issuer_signed.issuer_auth.cose_sign1.unprotected,
            )?;

            // Extract issuer certificate
            let cert_der = doc.issuer_signed.issuer_auth.certificate_der()?;

            // Parse certificate to get SPKI and extract public key
            let cert = <x509_cert::Certificate as der::Decode>::from_der(&cert_der)
                .map_err(|e| MdocError::Certificate(format!("parse issuer cert: {e}")))?;

            // Get the algorithm from the COSE_Sign1 protected header
            let alg = doc
                .issuer_signed
                .issuer_auth
                .cose_sign1
                .protected
                .header
                .alg
                .as_ref()
                .ok_or_else(|| {
                    MdocError::Signature("missing algorithm in issuerAuth".to_string())
                })?;

            let alg_id = match alg {
                coset::Algorithm::Assigned(a) => *a as i64,
                _ => {
                    return Err(MdocError::Signature(
                        "unsupported algorithm type in issuerAuth".to_string(),
                    ))
                }
            };

            // Get the SPKI from the certificate, encode the public key as a COSE_Key
            // For simplicity, extract the raw public key and build a temporary COSE_Key
            let spki = &cert.tbs_certificate.subject_public_key_info;
            let pub_key_bits = spki.subject_public_key.as_bytes().ok_or_else(|| {
                MdocError::Certificate("SPKI public key is not byte-aligned".to_string())
            })?;

            // Build a minimal COSE_Key from the raw public key for verification
            let cose_key = build_cose_key_from_ec_point(pub_key_bits, alg_id)?;

            // Build the tbs data and verify
            let tbs = doc.issuer_signed.issuer_auth.cose_sign1.tbs_data(&[]);

            crate::cose::verify_cose_signature(
                &tbs,
                &doc.issuer_signed.issuer_auth.cose_sign1.signature,
                &cose_key,
                alg_id,
            )
        })();

        match result {
            Ok(true) => VerificationAssessment {
                status: VerificationStatus::Passed,
                check: "Issuer signature validity".to_string(),
                reason: None,
                category: VerificationCategory::IssuerAuth,
                id: CheckId::IssuerSignatureValidity,
            },
            Ok(false) => VerificationAssessment {
                status: VerificationStatus::Failed,
                check: "Issuer signature validity".to_string(),
                reason: Some("signature verification failed".to_string()),
                category: VerificationCategory::IssuerAuth,
                id: CheckId::IssuerSignatureValidity,
            },
            Err(e) => VerificationAssessment {
                status: VerificationStatus::Failed,
                check: "Issuer signature validity".to_string(),
                reason: Some(e.to_string()),
                category: VerificationCategory::IssuerAuth,
                id: CheckId::IssuerSignatureValidity,
            },
        }
    }

    /// Check MSO validity dates against current time.
    fn verify_mso_validity(&self, doc: &IssuerSignedDocument) -> VerificationAssessment {
        let result = (|| -> Result<(), String> {
            let mso = doc
                .issuer_signed
                .issuer_auth
                .mso()
                .map_err(|e| e.to_string())?;

            let vi = &mso.validity_info;

            // Interval-consistency sanity checks (MEDIUM-3): a self-contradictory
            // validity window must be rejected outright.
            if vi.valid_from > vi.valid_until {
                return Err(format!(
                    "validFrom ({}) is after validUntil ({})",
                    vi.valid_from, vi.valid_until
                ));
            }
            if vi.signed > vi.valid_until {
                return Err(format!(
                    "signed ({}) is after validUntil ({})",
                    vi.signed, vi.valid_until
                ));
            }

            let now = chrono::Utc::now();
            if now < vi.valid_from {
                return Err(format!("MSO not yet valid (validFrom: {})", vi.valid_from));
            }
            if now > vi.valid_until {
                return Err(format!("MSO expired (validUntil: {})", vi.valid_until));
            }
            Ok(())
        })();

        match result {
            Ok(()) => VerificationAssessment {
                status: VerificationStatus::Passed,
                check: "MSO validity at verification time".to_string(),
                reason: None,
                category: VerificationCategory::IssuerAuth,
                id: CheckId::MsoValidityAtVerificationTime,
            },
            Err(reason) => VerificationAssessment {
                status: VerificationStatus::Failed,
                check: "MSO validity at verification time".to_string(),
                reason: Some(reason),
                category: VerificationCategory::IssuerAuth,
                id: CheckId::MsoValidityAtVerificationTime,
            },
        }
    }
}

/// Convert a chrono UTC timestamp to a `der::DateTime` for x.509 time-validity
/// checks. Returns `None` if the value is outside the representable range
/// (pre-1970 or far future), in which case the caller skips the time check.
#[cfg(feature = "tsp")]
fn chrono_to_der_datetime(dt: chrono::DateTime<chrono::Utc>) -> Option<der::DateTime> {
    let secs = dt.timestamp();
    if secs < 0 {
        return None;
    }
    der::DateTime::from_unix_duration(core::time::Duration::from_secs(secs as u64)).ok()
}

/// Enforce the MSO's `keyAuthorizations` over the device-asserted namespaces
/// and elements (HIGH-2, ISO 18013-5 §9.1.2.4).
///
/// When `keyAuthorizations` is absent the device key is authorized for all data
/// elements (per spec) and the check passes. When present, every device-signed
/// namespace must be covered either by an authorized full namespace or by an
/// explicit per-element authorization; any element outside the authorized set
/// fails the check.
fn check_key_authorizations(
    doc: &IssuerSignedDocument,
    device_signed: &DeviceSigned,
) -> VerificationAssessment {
    let pass = || VerificationAssessment {
        status: VerificationStatus::Passed,
        check: "Device key authorizations respected".to_string(),
        reason: None,
        category: VerificationCategory::DeviceAuth,
        id: CheckId::DeviceKeyAuthorizationsRespected,
    };
    let fail = |reason: String| VerificationAssessment {
        status: VerificationStatus::Failed,
        check: "Device key authorizations respected".to_string(),
        reason: Some(reason),
        category: VerificationCategory::DeviceAuth,
        id: CheckId::DeviceKeyAuthorizationsRespected,
    };

    // If there are no device-asserted elements there is nothing to authorize.
    if device_signed.name_spaces.is_empty() {
        return pass();
    }

    let key_auth = match doc
        .issuer_signed
        .issuer_auth
        .mso()
        .ok()
        .and_then(|mso| mso.device_key_info)
        .and_then(|dki| dki.key_authorizations)
    {
        // Absent authorizations → authorized for everything.
        None => return pass(),
        Some(ka) => ka,
    };

    let authorized_namespaces = key_auth.name_spaces.unwrap_or_default();
    let authorized_elements = key_auth.data_elements.unwrap_or_default();

    for (ns, elements) in &device_signed.name_spaces {
        let whole_ns_authorized = authorized_namespaces.iter().any(|n| n == ns);
        if whole_ns_authorized {
            continue;
        }
        let allowed = authorized_elements.get(ns);
        for elem in elements.keys() {
            let elem_authorized = allowed
                .map(|list| list.iter().any(|e| e == elem))
                .unwrap_or(false);
            if !elem_authorized {
                return fail(format!(
                    "device-asserted element {ns}.{elem} is outside the device key's authorizations"
                ));
            }
        }
    }

    pass()
}

/// ECDH over P-256: shared secret from a raw 32-byte private scalar and an
/// uncompressed SEC1 public point (0x04 || x || y). Used to derive the device
/// MAC key (HIGH-3).
fn ecdh_p256_shared_secret(
    private_scalar: &[u8],
    public_sec1: &[u8],
) -> Result<Vec<u8>, MdocError> {
    use p256::{PublicKey, SecretKey};

    let sk = SecretKey::from_slice(private_scalar)
        .map_err(|e| MdocError::DeviceAuth(format!("ephemeral reader private key: {e}")))?;
    let pk = PublicKey::from_sec1_bytes(public_sec1)
        .map_err(|e| MdocError::DeviceAuth(format!("device public key: {e}")))?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}

/// Build a minimal COSE_Key from a raw EC uncompressed point for verification.
fn build_cose_key_from_ec_point(ec_point: &[u8], alg_id: i64) -> Result<coset::CoseKey, MdocError> {
    use crate::cose::key::{algorithms, curves};
    use coset::iana;

    // Determine curve from algorithm
    let (curve_id, coord_len) = match alg_id {
        algorithms::ES256 => (curves::P256, 32),
        algorithms::ES384 => (curves::P384, 48),
        algorithms::ES512 => (curves::P521, 66),
        algorithms::EDDSA => {
            // Ed25519: raw 32-byte public key (no 0x04 prefix)
            let key = coset::CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv as i64,
                    ciborium::Value::from(curves::ED25519 as i128),
                )
                .param(
                    iana::OkpKeyParameter::X as i64,
                    ciborium::Value::Bytes(ec_point.to_vec()),
                )
                .build();
            return Ok(key);
        }
        _ => {
            return Err(MdocError::UnsupportedAlgorithm(format!(
                "cannot build COSE_Key for alg {alg_id}"
            )));
        }
    };

    // EC2 key: expect 0x04 || x || y (uncompressed point)
    if ec_point.len() != 1 + 2 * coord_len || ec_point[0] != 0x04 {
        return Err(MdocError::Certificate(format!(
            "expected uncompressed EC point (0x04 + {} bytes), got {} bytes",
            2 * coord_len,
            ec_point.len()
        )));
    }

    let x = &ec_point[1..1 + coord_len];
    let y = &ec_point[1 + coord_len..];

    let key = coset::CoseKeyBuilder::new_ec2_pub_key(
        match curve_id {
            1 => iana::EllipticCurve::P_256,
            2 => iana::EllipticCurve::P_384,
            3 => iana::EllipticCurve::P_521,
            _ => unreachable!(),
        },
        x.to_vec(),
        y.to_vec(),
    )
    .build();

    Ok(key)
}

fn emit(
    assessments: &mut Vec<VerificationAssessment>,
    assessment: VerificationAssessment,
    opts: &VerifyOptions,
) {
    if let Some(ref callback) = opts.on_check {
        callback(&assessment);
    }
    assessments.push(assessment);
}
