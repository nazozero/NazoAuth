use super::*;

#[test]
fn verified_mdoc_holder_binding_preserves_the_device_cose_key() {
    let key =
        CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![7; 32], vec![11; 32])
            .build();

    let holder = mdoc_holder_key(Some(&key)).expect("device key must be retained");
    let encoded = holder
        .get("cose_key")
        .and_then(Value::as_str)
        .expect("holder binding must expose the verified COSE key");

    assert_eq!(
        URL_SAFE_NO_PAD.decode(encoded).expect("base64url COSE key"),
        key.to_vec().expect("CBOR COSE key")
    );
    assert_eq!(
        mdoc_holder_key(None),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
}
