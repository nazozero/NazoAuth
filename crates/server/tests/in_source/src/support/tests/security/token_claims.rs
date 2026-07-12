use super::*;

#[test]
fn signing_adapters_do_not_define_or_call_claim_forwarders() {
    let server_tokens =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/support/security/tokens.rs");
    let source = std::fs::read_to_string(&server_tokens)
        .expect("server token adapter source must exist relative to its manifest");

    for forbidden in [
        "pub(super) fn access_token_claims(",
        "pub(super) fn id_token_claims(",
        "pub(super) fn backchannel_logout_token_claims(",
        "pub(super) fn authorization_response_jwt_claims(",
        "let claims = access_token_claims(",
        "let claims = id_token_claims(",
        "let claims = backchannel_logout_token_claims(",
        "let claims = authorization_response_jwt_claims(",
    ] {
        assert!(
            !source.contains(forbidden),
            "server claim forwarding boundary remains: {forbidden}"
        );
    }

    for required in [
        "nazo_auth::access_token_claims(",
        "nazo_auth::id_token_claims(",
        "nazo_auth::backchannel_logout_token_claims(",
        "nazo_auth::authorization_response_jwt_claims(",
    ] {
        assert!(
            source.contains(required),
            "signing adapter must call public auth builder directly: {required}"
        );
    }
}

#[test]
fn access_token_header_uses_active_alg_kid_and_at_jwt_type() {
    let header = access_token_header(jsonwebtoken::Algorithm::PS256, "active-kid");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::PS256);
    assert_eq!(header.kid.as_deref(), Some("active-kid"));
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
}

#[test]
fn access_token_rejects_conflicting_sender_constraints() {
    assert!(validate_access_token_sender_constraint(Some("jkt"), Some("x5t")).is_err());
}

#[tokio::test]
async fn make_jwt_rejects_conflicting_sender_constraints_before_signing() {
    let state = AppState {
        diesel_db: crate::db::create_pool(
            "postgres://nazo_token_test_invalid:nazo_token_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: std::sync::Arc::new(test_settings()),
        keyset: crate::domain::KeysetStore::new(Keyset {
            active_kid: "invalid-test-key".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    };
    let audiences = vec!["resource://default".to_owned()];
    let scopes = vec!["read".to_owned()];
    let authorization_details = json!([]);

    let result = make_jwt(
        &state,
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: "subject-1",
            user_id: None,
            subject_type: "client",
            client_id: "client-1",
            audiences: &audiences,
            scopes: &scopes,
            authorization_details: &authorization_details,
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 120,
            dpop_jkt: Some("jkt"),
            mtls_x5t_s256: Some("x5t"),
            actor: None,
        },
    )
    .await;

    let error = match result {
        Ok(_) => panic!("conflicting sender constraints must fail before signing"),
        Err(error) => error,
    };
    assert!(matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidToken
    ));
}

#[tokio::test]
async fn response_signing_uses_auxiliary_key_from_current_keyset_snapshot() {
    let auxiliary = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("auxiliary response signing key should generate");
    let public_jwk = public_jwk_from_private_der(
        "auxiliary-rs256",
        jsonwebtoken::Algorithm::RS256,
        &auxiliary.private_pkcs8_der,
    )
    .expect("auxiliary public JWK should derive");
    let state = AppState {
        diesel_db: crate::db::create_pool(
            "postgres://nazo_token_test_invalid:nazo_token_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: std::sync::Arc::new(test_settings()),
        keyset: crate::domain::KeysetStore::new(Keyset {
            active_kid: "active-eddsa".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: vec![VerificationKey {
                kid: "auxiliary-rs256".to_owned(),
                public_jwk,
                local_signing_key: Some(auxiliary.private_pkcs8_der),
            }],
        }),
    };

    let token = sign_response_jwt(
        &state,
        &json!({"sub": "subject-1"}),
        "JWT",
        Some(jsonwebtoken::Algorithm::RS256),
    )
    .await
    .expect("response signing should use the key material loaded in the snapshot");
    let header = jsonwebtoken::decode_header(&token).expect("signed response header should decode");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(header.kid.as_deref(), Some("auxiliary-rs256"));
}
