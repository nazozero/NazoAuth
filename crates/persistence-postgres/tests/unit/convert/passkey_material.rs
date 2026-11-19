use super::*;
use nazo_passkey::{CosePublicKey, PasskeyCredential as WebauthnCredential};

#[test]
fn owned_credential_value_keeps_existing_webauthn_key_material_and_wire() {
    // COSE OKP/Ed25519 material uses the existing library persistence interface;
    // this checks encoding rather than authenticator signature verification.
    let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    cose.extend_from_slice(&[7_u8; 32]);
    let credential = WebauthnCredential {
        id: nazo_passkey::CredentialId(vec![9_u8; 32]),
        public_key_cose: CosePublicKey(cose.clone()),
        counter: 12,
        transports: vec!["internal".to_owned()],
        aaguid: [3_u8; 16],
        user_handle: None,
        uv_initialized: None,
        backup_eligible: None,
        backup_state: None,
        attestation: nazo_passkey::AttestationEvidence::Unknown,
    };
    let wire = serde_json::to_value(&credential).unwrap();
    let expected_wire = wire.clone();
    let decoded = passkey_material(&credential.id.to_b64url(), 12, wire).unwrap();
    assert_eq!(decoded.id.0, credential.id.0);
    assert_eq!(decoded.public_key_cose.0, cose);
    assert_eq!(decoded.counter, 12);
    assert_eq!(decoded.aaguid, credential.aaguid);
    assert_eq!(decoded.transports, credential.transports);
    assert_eq!(serde_json::to_value(decoded).unwrap(), expected_wire);
}

#[test]
fn malformed_owned_credential_keeps_the_existing_consistency_failure() {
    for value in [
        serde_json::Value::Null,
        serde_json::json!([]),
        serde_json::json!({}),
    ] {
        match passkey_material("AQID", 0, value) {
            Err(ConversionError(message)) => {
                assert_eq!(message, "stored passkey credential is malformed");
            }
            _ => panic!("malformed credential must remain a consistency failure"),
        }
    }
}

#[test]
fn legacy_jsonb_es256_and_ed25519_credentials_authenticate_without_registration() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use ed25519_dalek::Signer as _;
    use sha2::{Digest, Sha256};

    let es = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
    let ed = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    let point = es.verifying_key().to_sec1_point(false);
    let mut es_cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    es_cose.extend_from_slice(point.x().unwrap());
    es_cose.extend_from_slice(&[0x22, 0x58, 0x20]);
    es_cose.extend_from_slice(point.y().unwrap());
    let mut ed_cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    ed_cose.extend_from_slice(ed.verifying_key().as_bytes());
    let wa = nazo_passkey::Webauthn::new("example.com", "Example", "https://example.com")
        .require_user_verification(true);
    for (alg, cose) in [(-7, es_cose), (-8, ed_cose)] {
        // Exact pre-upgrade JSONB keys; no registration is run by this test.
        let old = serde_json::json!({
            "id": [1, 2, 3],
            "public_key_cose": cose,
            "counter": 12,
            "transports": ["internal"],
            "aaguid": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        });
        let credential = passkey_material("AQID", 12, old.clone()).unwrap();
        assert_eq!(credential.public_key_cose.0, cose);
        assert_eq!(credential.uv_initialized, None);
        assert_eq!(credential.backup_eligible, None);
        assert_eq!(credential.backup_state, None);
        assert_eq!(credential.user_handle, None);
        assert_eq!(
            credential.attestation,
            nazo_passkey::AttestationEvidence::Unknown
        );
        let (challenge, state) = wa.start_authentication_with_creds_for_user(
            b"existing-user",
            std::slice::from_ref(&credential),
        );
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get", "challenge": challenge.challenge,
            "origin": "https://example.com", "crossOrigin": false,
        }))
        .unwrap();
        let mut auth_data = Sha256::digest(b"example.com").to_vec();
        auth_data.push(0x05);
        auth_data.extend_from_slice(&13_u32.to_be_bytes());
        let mut message = auth_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature = if alg == -7 {
            let signature: p256::ecdsa::Signature = es.sign(&message);
            signature.to_der().as_bytes().to_vec()
        } else {
            ed.sign(&message).to_bytes().to_vec()
        };
        let mut response: nazo_passkey::AuthenticationResponse =
            serde_json::from_value(serde_json::json!({
                "id": "AQID", "rawId": "AQID", "type": "public-key",
                "response": {
                    "authenticatorData": B64.encode(auth_data),
                    "signature": B64.encode(&signature),
                    "clientDataJSON": B64.encode(client_data),
                    "userHandle": B64.encode(b"existing-user"),
                },
                "clientExtensionResults": {},
            }))
            .unwrap();
        let result = wa
            .finish_authentication(&state, &response, &credential)
            .unwrap();
        assert_eq!(result.update.new_counter, 13);
        assert_eq!(result.update.expected_counter, 12);
        assert!(result.user_verified);
        assert!(
            !result.user_verification_eligible,
            "legacy UV history remains unknown"
        );
        // Preserve the real signature's DER/raw shape while corrupting its
        // scalar, so this exercises verification rather than just framing.
        let mut corrupted_signature = signature;
        *corrupted_signature.last_mut().unwrap() ^= 1;
        response.response.signature = B64.encode(corrupted_signature);
        assert!(
            wa.finish_authentication(&state, &response, &credential)
                .is_err()
        );

        let mut material_only = old;
        material_only.as_object_mut().unwrap().remove("id");
        material_only.as_object_mut().unwrap().remove("counter");
        let decoded = passkey_material("AQID", 12, material_only).unwrap();
        assert_eq!(decoded.public_key_cose.0, cose);
        let encoded = encoded_passkey(&decoded).unwrap();
        assert!(encoded.get("id").is_none());
        assert!(encoded.get("counter").is_none());
        assert_eq!(encoded["public_key_cose"], serde_json::json!(cose));
    }
}
