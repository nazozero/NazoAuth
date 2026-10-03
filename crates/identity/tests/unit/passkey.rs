use super::*;

#[test]
fn owned_credential_value_keeps_existing_webauthn_key_material_and_wire() {
    // COSE OKP/Ed25519 material uses the existing library persistence interface;
    // this checks encoding rather than authenticator signature verification.
    let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    cose.extend_from_slice(&[7_u8; 32]);
    let credential = WebauthnCredential {
        id: passkey_auth::CredentialId(vec![9_u8; 32]),
        public_key_cose: CosePublicKey(cose.clone()),
        counter: 12,
        transports: vec!["internal".to_owned()],
        aaguid: [3_u8; 16],
    };
    let wire = serde_json::to_value(&credential).unwrap();
    let expected_wire = wire.clone();
    let decoded = decode_credential(wire).unwrap();
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
        match decode_credential(value) {
            Err(PasskeyError::State(RepositoryError::Consistency(message))) => {
                assert_eq!(message, "stored passkey credential is malformed");
            }
            _ => panic!("malformed credential must remain a consistency failure"),
        }
    }
}
