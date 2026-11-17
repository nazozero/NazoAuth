# Frozen peer reconciliation

Peer: e0014c4a7088085b7b08288ae5f739f27f3f818c
Jiff parent: 74f22b17bab32295f0a206ef59a2a9af3a64f0ca

## Cargo.lock

2807: version = "0.3.9"
2808: dependencies = [
2809:  "base64 0.23.1",
2810:  "flate2",
2811: <<<<<<< HEAD
2812:  "jiff",
2813: =======
2814:  "iri-string",
2815: >>>>>>> e0014c4a7088085b7b08288ae5f739f27f3f818c
2816:  "nazo-crypto",
2817:  "rand 0.10.3",
2818:  "rcgen",
2819:  "serde",

## crates/authorization-server/src/domain/openid4vc/credential_crypto/mdoc.rs

73:         .map_err(|_| CredentialTrustError::InvalidEncoding)?;
74:     if !remainder.is_empty() {
75:         return Err(CredentialTrustError::InvalidEncoding);
76:     }
77: <<<<<<< HEAD
78:     validate_mdl_issuing_country(&certificate, &input.payload.credential_type, namespaces)?;
79:     let not_before =
80:         MdocTimestamp::from_unix_seconds(certificate.validity().not_before.timestamp())
81:             .map_err(|_| CredentialTrustError::InvalidEncoding)?;
82:     let not_after = MdocTimestamp::from_unix_seconds(certificate.validity().not_after.timestamp())
83: =======
84:     check_mdoc_document_signer_profile(&certificate)?;
85:     let (_, issuer) = x509_parser::parse_x509_certificate(signing_material.issuer_der())
86:         .map_err(|_| CredentialTrustError::UntrustedIssuer)?;
87:     check_mdoc_issuer_binding(&certificate, &issuer)?;
88:     validate_mdl_issuer_attributes(&certificate, &input.payload.credential_type, namespaces)?;
89:     let not_before = Timestamp::from_unix_seconds(certificate.validity().not_before.timestamp())
90:         .map_err(|_| CredentialTrustError::InvalidEncoding)?;
91:     let not_after = Timestamp::from_unix_seconds(certificate.validity().not_after.timestamp())
92: >>>>>>> e0014c4a7088085b7b08288ae5f739f27f3f818c
93:         .map_err(|_| CredentialTrustError::InvalidEncoding)?;
94:     // The public certificate cohort boundary preserves privacy rounding without
95:     // extending the credential deadline or predating the selected signing key.
96:     let signed = to_protocol_time(input.issued_at)?.max(not_before);

307:     let mut documents = verify_presentation(
308:         &bytes,
309:         &transcript,
310:         &VerificationOptions {
311: <<<<<<< HEAD
312:             now: to_protocol_time(Timestamp::now())?,
313: =======
314:             now: to_protocol_time(now)?,
315: >>>>>>> e0014c4a7088085b7b08288ae5f739f27f3f818c
316:             max_documents: 1,
317:         },
318:     )
319:     .map_err(|error| match error {

436:         .any(|candidate| candidate.as_slice() == anchor);
437:     revocation_policy.check_chain_with_scoped_trust(
438:         None,
439:         certificates,
440: <<<<<<< HEAD
441:         Timestamp::now(),
442: =======
443:         now,
444: >>>>>>> e0014c4a7088085b7b08288ae5f739f27f3f818c
445:         scoped_anchor_authenticated,
446:     )?;
447:     // Project authenticated certificates already parsed for the profile. Do not
448:     // append the loaded anchor or parse the common single-leaf path again.

## crates/authorization-server/tests/unit/domain/openid4vc_credential_crypto.rs

1818:     ));
1819: }
1820: 
1821: #[test]
1822: <<<<<<< HEAD
1823: fn mdoc_direct_scoped_trust_anchor_is_exact_self_signed_and_lease_scoped() {
1824:     let certs = certificate_fixture("issuer.example");
1825:     let now = Timestamp::now().as_second();
1826: =======
1827: fn mdoc_verification_rejects_a_scoped_iaca_used_as_document_signer() {
1828:     futures_executor::block_on(async {
1829:         let (crypto, _, _) = real_crypto_fixture().await;
1830:         let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
1831:         let mut params = CertificateParams::default();
1832:         params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
1833:         params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
1834:         params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
1835:         params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
1836:         let ca = params.self_signed(&key).unwrap();
1837:         let certs = CertificateFixture {
1838:             ca_der: ca.der().to_vec(),
1839:             ca_pem: ca.pem(),
1840:             leaf_der: ca.der().to_vec(),
1841:             leaf_pem: ca.pem(),
1842:             leaf_key: key,
1843:         };
1844:         let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
1845:         let presentation = PresentedCredential {
1846:             format: CredentialFormat::MsoMdoc,
1847:             encoded: encoded.into(),
1848:             expected_nonce: "verifier-nonce".into(),
1849:             expected_audience: "https://verifier.example".into(),
1850:             mdoc_session_transcript: Some(transcript.into()),
1851:             additional_trust_anchors: vec![certs.ca_der].into(),
1852:         };
1853:         assert_eq!(
1854:             crypto.verify_mdoc(&presentation),
1855:             Err(CredentialTrustError::UntrustedIssuer),
1856:             "pinning an IACA does not authorize it to serve as a DS end entity"
1857:         );
1858:     });
1859: }
1860: >>>>>>> e0014c4a7088085b7b08288ae5f739f27f3f818c
1861: 
1862: #[test]
1863: fn mdoc_verification_requires_document_signer_profile() {
1864:     futures_executor::block_on(async {

## crates/key-management/src/model.rs

12: 
13: use crate::ExternalKeySigner;
14: use arc_swap::ArcSwap;
15: use base64::{Engine, encoded_len, engine::general_purpose::URL_SAFE_NO_PAD};
16: <<<<<<< HEAD
17: use jiff::Timestamp;
18: =======
19: use chrono::{DateTime, Utc};
20: >>>>>>> e0014c4a7088085b7b08288ae5f739f27f3f818c
21: use nazo_auth::{SignError, SignRequest, Signature, Signer, SigningPurpose};
22: use serde::{Deserialize, Serialize};
23: use serde_json::Value;
24: 

