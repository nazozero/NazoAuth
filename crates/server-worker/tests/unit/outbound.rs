use super::*;
#[test]
fn exact_origin_admission_rejects_authority_and_private_host_confusion() {
    let client = Outbound::new(&["https://issuer.example".into()]).unwrap();
    assert!(client.admit("https://issuer.example/jwks", false).is_ok());
    assert!(
        client
            .admit("https://issuer.example/request#sha256=value", true)
            .is_ok()
    );
    for uri in [
        "http://issuer.example/key",
        "https://issuer.example.evil/key",
        "https://user@issuer.example/key",
        "https://issuer.example:444/key",
        "https://127.0.0.1/key",
        "https://[::1]/key",
        "https://issuer.example/key#value",
    ] {
        assert!(client.admit(uri, false).is_err(), "{uri}");
    }
    for origin in [
        "https://localhost",
        "https://a.local",
        "https://10.0.0.1",
        "https://issuer.example/path",
        "https://issuer.example?query",
        "https://issuer.example#fragment",
    ] {
        assert!(Outbound::new(&[origin.into()]).is_err(), "{origin}");
    }
}
