use super::*;

#[test]
fn callback_uris_include_local_and_official_suite_bases() {
    let urls = suite_base_urls("https://nginx:8443/");

    assert!(urls.contains(&"https://nginx:8443".to_owned()));
    assert!(urls.contains(&"https://www.certification.openid.net".to_owned()));
    let callbacks = callback_uris(&urls, "local-nazo-oauth-oidf");
    assert!(
        callbacks
            .iter()
            .any(|value| value == "https://nginx:8443/test/a/local-nazo-oauth-oidf/callback")
    );
    assert!(callbacks.iter().any(|value| value
        == "https://www.certification.openid.net/test/a/local-nazo-oauth-oidf/callback"));
}

#[test]
fn oidf_seed_public_jwks_strip_private_key_material() {
    let private_jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "client-key",
            "n": "modulus",
            "e": "AQAB",
            "d": "private",
            "p": "private",
            "q": "private",
            "dp": "private",
            "dq": "private",
            "qi": "private",
            "oth": [{"r": "private"}]
        }]
    });

    let public = oidf_config::public_jwks(&private_jwks).unwrap();
    let key = public
        .get("keys")
        .and_then(Value::as_array)
        .and_then(|keys| keys.first())
        .and_then(Value::as_object)
        .expect("public jwks should contain one public key");

    assert_eq!(key.get("kid").and_then(Value::as_str), Some("client-key"));
    assert_eq!(key.get("n").and_then(Value::as_str), Some("modulus"));
    for private_field in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
        assert!(
            !key.contains_key(private_field),
            "public JWKS leaked private field {private_field}"
        );
    }
}
