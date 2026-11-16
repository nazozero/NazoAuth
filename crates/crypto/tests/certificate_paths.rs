#![cfg(feature = "x509")]

use nazo_crypto::certificate::{self as certs, CertificateDer};
use rustls_pki_types::pem::PemObject as _;

// Public certificates issued once by rcgen's native backend. Their private
// keys are not retained. Both backends consume these exact DER/PEM bytes.
const ROOT: &str = include_str!("fixtures/certificates/root.pem");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/certificates/intermediate.der");
const CLIENT: &[u8] = include_bytes!("fixtures/certificates/client.der");
const SERVER: &[u8] = include_bytes!("fixtures/certificates/server.der");
const KEY_ENCIPHERMENT: &[u8] = include_bytes!("fixtures/certificates/key-encipherment.der");
const CRITICAL: &[u8] = include_bytes!("fixtures/certificates/critical.der");
const SUBISSUER: &[u8] = include_bytes!("fixtures/certificates/subissuer.der");
const SUBCLIENT: &[u8] = include_bytes!("fixtures/certificates/subclient.der");
const NOW: u64 = 1_800_000_000;

fn root() -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(ROOT.as_bytes()).unwrap()
}

fn chain(leaf: &'static [u8]) -> [CertificateDer<'static>; 2] {
    [leaf.into(), INTERMEDIATE.into()]
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn portable_certificate_signatures_and_paths_accept_native_fixtures() {
    certs::verify_document_signing_chain_at(&chain(CLIENT), &root(), NOW).unwrap();
    certs::verify_client_chain_at(&chain(CLIENT), ROOT, NOW).unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(CLIENT).unwrap();
    let (_, issuer) = x509_parser::parse_x509_certificate(INTERMEDIATE).unwrap();
    certs::verify_signature(&leaf, issuer.public_key()).unwrap();
    assert!(certs::verify_signature(&leaf, leaf.public_key()).is_err());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn portable_certificate_paths_keep_purpose_and_key_usage_distinct() {
    certs::verify_document_signing_chain_at(&chain(SERVER), &root(), NOW).unwrap();
    assert!(certs::verify_client_chain_at(&chain(SERVER), ROOT, NOW).is_err());
    assert!(
        certs::verify_document_signing_chain_at(&chain(KEY_ENCIPHERMENT), &root(), NOW).is_err()
    );
    assert!(certs::verify_document_signing_chain_at(&chain(INTERMEDIATE), &root(), NOW).is_err());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn portable_certificate_paths_reject_invalid_time_signature_and_constraints() {
    for now in [0, 100_000_000_000] {
        assert!(certs::verify_document_signing_chain_at(&chain(CLIENT), &root(), now).is_err());
        assert!(certs::verify_client_chain_at(&chain(CLIENT), ROOT, now).is_err());
    }
    assert!(certs::verify_document_signing_chain_at(&chain(CRITICAL), &root(), NOW).is_err());
    assert!(certs::verify_client_chain_at(&chain(CRITICAL), ROOT, NOW).is_err());
    let too_deep = [SUBCLIENT.into(), SUBISSUER.into(), INTERMEDIATE.into()];
    assert!(certs::verify_document_signing_chain_at(&too_deep, &root(), NOW).is_err());
    assert!(certs::verify_client_chain_at(&too_deep, ROOT, NOW).is_err());
    let mut tampered = CLIENT.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let tampered = [tampered.into(), INTERMEDIATE.into()];
    assert!(certs::verify_document_signing_chain_at(&tampered, &root(), NOW).is_err());
    assert!(certs::verify_client_chain_at(&tampered, ROOT, NOW).is_err());
}

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn portable_certificate_paths_require_the_exact_document_chain_and_nonempty_roots() {
    let with_unused_intermediate = [CLIENT.into(), INTERMEDIATE.into(), INTERMEDIATE.into()];
    assert!(
        certs::verify_document_signing_chain_at(&with_unused_intermediate, &root(), NOW).is_err()
    );
    assert!(certs::verify_document_signing_chain_at(&[CLIENT.into()], &root(), NOW).is_err());
    assert!(certs::verify_document_signing_chain_at(&[], &root(), NOW).is_err());
    assert!(certs::verify_client_chain_at(&chain(CLIENT), "not a certificate", NOW).is_err());
    assert!(certs::verify_client_chain_at(&[], ROOT, NOW).is_err());
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[test]
fn client_path_validation_matches_previous_tls_verifier() {
    use nazo_crypto::CryptoError;
    use rustls_pki_types::UnixTime;
    use std::{sync::Arc, time::Duration};

    fn previous(
        chain: &[CertificateDer<'_>],
        anchors: &str,
        unix_seconds: u64,
    ) -> nazo_crypto::Result<()> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(anchors.as_bytes()) {
            roots
                .add(certificate.map_err(|_| CryptoError::InvalidInput)?)
                .map_err(|_| CryptoError::InvalidInput)?;
        }
        if roots.is_empty() {
            return Err(CryptoError::InvalidInput);
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .map_err(|_| CryptoError::OperationFailed)?;
        let (leaf, intermediates) = chain.split_first().ok_or(CryptoError::InvalidInput)?;
        verifier
            .verify_client_cert(
                leaf,
                intermediates,
                UnixTime::since_unix_epoch(Duration::from_secs(unix_seconds)),
            )
            .map(|_| ())
            .map_err(|_| CryptoError::InvalidSignature)
    }

    for leaf in [CLIENT, SERVER, KEY_ENCIPHERMENT, CRITICAL, INTERMEDIATE] {
        for now in [0, NOW, 100_000_000_000] {
            for anchors in [ROOT, "", "not a certificate"] {
                assert_eq!(
                    certs::verify_client_chain_at(&chain(leaf), anchors, now),
                    previous(&chain(leaf), anchors, now),
                );
            }
        }
    }
    for chain in [
        vec![],
        vec![CLIENT.into()],
        vec![
            CertificateDer::from(&b"invalid DER"[..]),
            INTERMEDIATE.into(),
        ],
        vec![SUBCLIENT.into(), SUBISSUER.into(), INTERMEDIATE.into()],
        vec![CLIENT.into(), INTERMEDIATE.into(), INTERMEDIATE.into()],
    ] {
        assert_eq!(
            certs::verify_client_chain_at(&chain, ROOT, NOW),
            previous(&chain, ROOT, NOW),
        );
    }
}
