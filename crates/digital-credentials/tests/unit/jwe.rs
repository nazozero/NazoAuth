use super::*;

#[test]
fn decryption_header_borrows_strings_and_ephemeral_key() {
    let encoded = br#"{"alg":"ECDH-ES","enc":"A256GCM","kid":"key","cty":"json","apu":"YQ","epk":{"kty":"EC","crv":"P-256","x":"x","y":"y"}}"#;
    let header: DecryptionHeader<'_> = serde_json::from_slice(encoded).unwrap();
    assert!(matches!(header.alg, Cow::Borrowed(_)));
    assert!(matches!(header.enc, Cow::Borrowed(_)));
    assert!(matches!(header.kid, Some(Cow::Borrowed(_))));
    assert!(matches!(header.cty, Some(Cow::Borrowed(_))));
    assert!(matches!(header.apu, Some(Cow::Borrowed(_))));
    let key: EphemeralPublicJwk<'_> = serde_json::from_str(header.epk.get()).unwrap();
    for field in [key.kty, key.crv, key.x, key.y] {
        let Cow::Borrowed(value) = field else {
            panic!("unexpected owned field")
        };
        assert!(encoded.as_ptr_range().contains(&value.as_ptr()));
    }
}

#[test]
fn optional_key_algorithm_and_party_info_reject_explicit_null() {
    assert!(
        serde_json::from_str::<EphemeralPublicJwk<'_>>(
            r#"{"kty":"EC","crv":"P-256","x":"x","y":"y","alg":null}"#
        )
        .is_err()
    );
    for field in ["apu", "apv"] {
        let input = format!(r#"{{"alg":"ECDH-ES","enc":"A256GCM","epk":{{}},"{field}":null}}"#);
        assert!(serde_json::from_str::<DecryptionHeader<'_>>(&input).is_err());
    }
}
