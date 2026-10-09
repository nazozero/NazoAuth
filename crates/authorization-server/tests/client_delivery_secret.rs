use nazo_oauth_server::crypto::{client_secret_digest, client_secret_matches_digest};

#[test]
fn delivery_secret_binding_uses_the_issued_generation_and_rejects_malformed_hashes() {
    let digest = client_secret_digest("issued-secret", "pepper", "attempt-salt");
    assert!(client_secret_matches_digest(
        "issued-secret",
        "pepper",
        &digest
    ));
    assert!(!client_secret_matches_digest(
        "other-secret",
        "pepper",
        &digest
    ));
    assert!(!client_secret_matches_digest(
        "issued-secret",
        "other-pepper",
        &digest
    ));
    for malformed in [
        "",
        "client-secret-v0:salt:mac",
        "client-secret-v1::mac",
        "client-secret-v1:salt:",
        "client-secret-v1:salt:mac:extra",
    ] {
        assert!(!client_secret_matches_digest(
            "issued-secret",
            "pepper",
            malformed
        ));
    }
}
