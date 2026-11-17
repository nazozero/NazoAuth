use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::Algorithm;
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{
    CredentialFormat, CredentialPayload, CredentialSignInput, CredentialSignerPort, HolderBinding,
    VcIssuerTrustPolicy,
};
use nazo_key_management::{KeyManager, Openid4vcPublicMaterial};
use nazo_oauth_server::{
    domain::openid4vc::Openid4vcCredentialCrypto, policy::Openid4vcRevocationPolicy,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::json;

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
        let crypto = Openid4vcCredentialCrypto::new_with_policies(
            keyset.clone(),
            VcIssuerTrustPolicy::san_bound(),
            Openid4vcRevocationPolicy::Disabled,
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
            },
            issued_at,
            expires_at: issued_at + Duration::minutes(10),
            status: None,
        };
        let encoded = crypto.sign(&request).await.unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let document = nazo_mdoc::parser::parse_issued(&bytes).unwrap();
        assert_eq!(
            document.issuer_auth.certificate_chain_der().unwrap(),
            vec![leaf.der().to_vec()]
        );
        let values = &document.name_spaces["org.example.namespace"];
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].element_identifier, "family_name");
        assert_eq!(
            values[0].element_value,
            ciborium::Value::Text("Lovelace".to_owned())
        );

        // Preparation never owns a private key or depends on a native runtime.
        // A concurrent material publication cannot replace the selected lease.
        let lease = keyset.prepare_openid4vc_signing().unwrap();
        let device_key = coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
        .build();
        let prepared = nazo_mdoc::builder::DocumentBuilder::new("org.example.credential")
            .device_key(device_key)
            .validity(nazo_mdoc::model::types::ValidityInfo {
                signed: issued_at,
                valid_from: issued_at,
                valid_until: issued_at + Duration::minutes(10),
                expected_update: None,
            })
            .add_namespace(
                "org.example.namespace",
                vec![("family_name", ciborium::Value::Text("Lovelace".to_owned()))],
            )
            .prepare(
                nazo_mdoc::model::types::CoseAlgorithm::ES256,
                vec![leaf.der().to_vec()],
            )
            .unwrap();
        keyset.set_openid4vc_material_for_test(Openid4vcPublicMaterial {
            signing_kid: "replacement-generation".to_owned(),
            certificate_chain_pem: String::new(),
            trust_anchors_pem: String::new(),
            revocation_snapshot: None,
        });
        assert_eq!(lease.kid(), kid);
        let signature = lease
            .sign(SignRequest {
                purpose: SigningPurpose::Credential,
                algorithm: "ES256",
                signing_input: prepared.signing_input(),
            })
            .await
            .unwrap();
        let pinned = prepared.finish(signature.into_bytes()).unwrap();
        assert_eq!(
            pinned
                .issuer_signed
                .issuer_auth
                .certificate_chain_der()
                .unwrap(),
            vec![leaf.der().to_vec()]
        );
        let authenticated = nazo_mdoc::verifier::verify_issued(
            &pinned.to_issuer_signed_cbor().unwrap(),
            "org.example.credential",
            Utc::now(),
        )
        .unwrap();
        assert_eq!(authenticated.document().doc_type, "org.example.credential");
    });
}
