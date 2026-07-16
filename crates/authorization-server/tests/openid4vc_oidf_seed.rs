use nazo_oauth_server::oidf_seed::openid4vc::{
    ATTESTED_CLIENT_ID, PRIVATE_KEY_CLIENT_ID, client_seeds,
};
use serde_json::json;

#[test]
fn seed_materialization_keeps_authentication_classes_distinct_and_public() {
    let bundle = json!({
        "configs": {
            "private.json": {
                "alias": "vci-private",
                "nazo": {"openid4vc_role": "issuer", "client_auth_type": "private_key_jwt"},
                "client": {
                    "client_id": PRIVATE_KEY_CLIENT_ID,
                    "scope": "openid pid-scope",
                    "jwks": {"keys": [{
                        "kty": "EC", "crv": "P-256", "kid": "client", "x": "x", "y": "y", "d": "private"
                    }]}
                }
            },
            "attested.json": {
                "alias": "vci-attested",
                "nazo": {"openid4vc_role": "issuer", "client_auth_type": "client_attestation"},
                "client": {"client_id": ATTESTED_CLIENT_ID, "scope": "openid pid-scope"}
            },
            "verifier.json": {
                "alias": "vp",
                "nazo": {"openid4vc_role": "verifier"}
            }
        }
    });
    let suite_urls = vec![
        "https://localhost:8443".to_owned(),
        "https://www.certification.openid.net".to_owned(),
    ];

    let seeds = client_seeds(&bundle, &suite_urls).expect("bounded clients");

    assert_eq!(seeds.len(), 2);
    let private = seeds
        .iter()
        .find(|seed| seed.client_id == PRIVATE_KEY_CLIENT_ID)
        .expect("private-key client");
    assert_eq!(private.auth_method, "private_key_jwt");
    assert_eq!(private.redirect_uris.len(), 2);
    assert_eq!(private.jwks.as_ref().unwrap()["keys"][0].get("d"), None);
    let attested = seeds
        .iter()
        .find(|seed| seed.client_id == ATTESTED_CLIENT_ID)
        .expect("attested client");
    assert_eq!(attested.auth_method, "attest_jwt_client_auth");
    assert_eq!(attested.redirect_uris.len(), 2);
    assert!(attested.jwks.is_none());
}

#[test]
fn seed_materialization_rejects_one_client_id_for_two_authentication_methods() {
    let bundle = json!({
        "configs": {
            "wrong.json": {
                "alias": "wrong",
                "nazo": {"openid4vc_role": "issuer", "client_auth_type": "client_attestation"},
                "client": {"client_id": PRIVATE_KEY_CLIENT_ID}
            }
        }
    });

    let error = client_seeds(&bundle, &["https://suite.example".to_owned()])
        .expect_err("mismatched client class must fail closed");

    assert!(error.to_string().contains(ATTESTED_CLIENT_ID));
}
