use super::*;
use nazo_key_management::{KeyManager, Openid4vcPublicMaterial, TestSigningBehavior};

fn signing_lease(behavior: TestSigningBehavior) -> Openid4vcSigningLease {
    let keyset = KeyManager::for_test_behavior(jsonwebtoken::Algorithm::ES256, behavior);
    keyset.set_openid4vc_material_for_test(Openid4vcPublicMaterial {
        signing_kid: keyset.snapshot().active_kid.clone(),
        certificate_chain_pem: String::new(),
        trust_anchors_pem: String::new(),
        revocation_snapshot: None,
    });
    keyset
        .prepare_openid4vc_signing()
        .expect("fixture signing lease")
}

#[test]
fn async_cose_signer_uses_credential_scope_and_propagates_signing_errors() {
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    let signer = AsyncCoseSigner {
        lease: signing_lease(TestSigningBehavior::Working),
        certificate_der: vec![1, 2, 3],
        runtime: runtime.handle().clone(),
    };
    let signature = signer.sign(b"credential tbs").expect("signature");
    assert_eq!(signature.len(), 64);
    assert_eq!(signer.algorithm(), -7);
    assert_eq!(signer.certificate_der(), &[1, 2, 3]);
    let failing = AsyncCoseSigner {
        lease: signing_lease(TestSigningBehavior::Failing),
        certificate_der: vec![1, 2, 3],
        runtime: runtime.handle().clone(),
    };
    assert!(failing.sign(b"credential tbs").is_err());
}

#[tokio::test]
async fn tokio_mdoc_signer_builds_document_and_propagates_lease_failure() {
    use mdoc_rs::model::types::ValidityInfo;
    let key = p256::ecdsa::SigningKey::from_slice(&[83; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    for behavior in [TestSigningBehavior::Working, TestSigningBehavior::Failing] {
        let now = chrono::Utc::now();
        let device_key = coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
        .build();
        let builder = DocumentBuilder::new("org.iso.18013.5.1.mDL")
            .device_key(device_key)
            .validity(ValidityInfo {
                signed: now,
                valid_from: now,
                valid_until: now + chrono::Duration::minutes(10),
                expected_update: None,
            })
            .add_namespace(
                "org.iso.18013.5.1",
                vec![("given_name", ciborium::Value::Text("Ada".into()))],
            );
        let succeeds = matches!(behavior, TestSigningBehavior::Working);
        let result = TokioMdocDocumentSigner
            .sign(builder, signing_lease(behavior), vec![1, 2, 3])
            .await;
        if succeeds {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(CredentialTrustError::Unavailable)));
        }
    }
}
