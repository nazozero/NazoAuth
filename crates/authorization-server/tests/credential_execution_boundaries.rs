use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::Algorithm;
use nazo_auth::SigningPurpose;
use nazo_digital_credentials::{
    CredentialFormat, CredentialFuture, CredentialPayload, CredentialSignInput,
    CredentialSignerPort, CredentialTrustError, HolderBinding, VcIssuerTrustPolicy,
};
use nazo_key_management::{KeyManager, Openid4vcPublicMaterial, Openid4vcSigningLease};
use nazo_oauth_server::{
    domain::openid4vc::Openid4vcCredentialCrypto, policy::Openid4vcRevocationPolicy,
    ports::mdoc::MdocDocumentSigner,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::json;

#[path = "support/mdoc_signer.rs"]
mod mdoc_signer;

struct RecordingSigner {
    keyset: KeyManager,
    expected_kid: String,
    expected_certificate: Vec<u8>,
    calls: AtomicUsize,
}

impl MdocDocumentSigner for RecordingSigner {
    fn sign<'a>(
        &'a self,
        builder: mdoc_rs::builder::DocumentBuilder,
        lease: Openid4vcSigningLease,
        certificate_der: Vec<u8>,
    ) -> CredentialFuture<
        'a,
        Result<mdoc_rs::model::document::IssuerSignedDocument, CredentialTrustError>,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(lease.kid(), self.expected_kid);
            assert_eq!(certificate_der, self.expected_certificate);
            let pinned_material = lease.material().clone();
            self.keyset
                .set_openid4vc_material_for_test(Openid4vcPublicMaterial {
                    signing_kid: "replacement-generation".to_owned(),
                    certificate_chain_pem: String::new(),
                    trust_anchors_pem: String::new(),
                    revocation_snapshot: None,
                });
            assert_eq!(lease.kid(), pinned_material.signing_kid);
            assert_eq!(
                lease.material().certificate_chain_pem,
                pinned_material.certificate_chain_pem
            );
            let document = mdoc_signer::LocalTestMdocDocumentSigner
                .sign(builder, lease, certificate_der)
                .await?;
            assert_eq!(document.doc_type, "org.example.credential");
            let values = &document.issuer_signed.name_spaces["org.example.namespace"];
            assert_eq!(values.len(), 1);
            assert_eq!(values[0].element_identifier, "family_name");
            assert_eq!(
                values[0].element_value,
                ciborium::Value::Text("Lovelace".to_owned())
            );
            Ok(document)
        })
    }
}

#[test]
fn credential_execution_uses_completed_builder_and_pinned_lease_without_native_runtime() {
    futures_executor::block_on(async {
        let keyset = KeyManager::for_test_with_auxiliary(Algorithm::ES256);
        let kid = keyset
            .snapshot()
            .signing_verification_key(SigningPurpose::Credential, Algorithm::ES256)
            .unwrap()
            .kid
            .clone();
        let leaf_key =
            KeyPair::from_pem(&keyset.database_local_private_key_pem(&kid).unwrap()).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.not_before = now - time::Duration::minutes(1);
        ca_params.not_after = now + time::Duration::hours(1);
        let ca = CertifiedIssuer::self_signed(
            ca_params,
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
        )
        .unwrap();
        let mut leaf_params = CertificateParams::new(vec!["issuer.example".to_owned()]).unwrap();
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.not_before = now - time::Duration::minutes(1);
        leaf_params.not_after = now + time::Duration::hours(1);
        let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();
        keyset.set_openid4vc_material_for_test(Openid4vcPublicMaterial {
            signing_kid: kid.clone(),
            certificate_chain_pem: format!("{}{}", leaf.pem(), ca.pem()),
            trust_anchors_pem: ca.pem(),
            revocation_snapshot: None,
        });
        let signer = Arc::new(RecordingSigner {
            keyset: keyset.clone(),
            expected_kid: kid,
            expected_certificate: leaf.der().to_vec(),
            calls: AtomicUsize::new(0),
        });
        let crypto = Openid4vcCredentialCrypto::new_with_policies(
            keyset,
            VcIssuerTrustPolicy::san_bound(),
            Openid4vcRevocationPolicy::Disabled,
            signer.clone(),
        )
        .unwrap();
        let holder = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
        let point = holder.verifying_key().to_sec1_point(false);
        let issued_at = Utc::now();
        let request = CredentialSignInput {
            payload: CredentialPayload {
                format: CredentialFormat::MsoMdoc,
                issuer: "https://issuer.example".to_owned(),
                configuration_id: "example".to_owned(),
                credential_type: "org.example.credential".to_owned(),
                subject_claims: json!({"org.example.namespace":{"family_name":"Lovelace"}}),
                holder_binding: Some(HolderBinding::Jwk {
                    jwk: json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())}),
                }),
                selectively_disclosable_claims: Vec::new(),
            },
            issued_at,
            expires_at: issued_at + Duration::minutes(10),
            status: None,
        };
        let encoded = crypto.sign(&request).await.unwrap();
        assert!(!URL_SAFE_NO_PAD.decode(encoded).unwrap().is_empty());
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    });
}
