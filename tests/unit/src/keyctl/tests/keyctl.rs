use super::*;
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, FederationSettings,
    PasskeySettings, RateLimitSettings, RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, try_load_keyset};

#[test]
fn generate_alg_parser_accepts_only_supported_key_algorithms() {
    assert_eq!(
        parse_generate_alg(Vec::new()).unwrap(),
        jsonwebtoken::Algorithm::EdDSA
    );
    assert_eq!(
        parse_generate_alg(vec!["--alg".to_owned(), "RS256".to_owned()]).unwrap(),
        jsonwebtoken::Algorithm::RS256
    );
    assert_eq!(
        parse_generate_alg(vec!["--alg".to_owned(), "ES256".to_owned()]).unwrap(),
        jsonwebtoken::Algorithm::ES256
    );
    assert_eq!(
        parse_generate_alg(vec!["--alg".to_owned(), "PS256".to_owned()]).unwrap(),
        jsonwebtoken::Algorithm::PS256
    );

    let err = parse_generate_alg(vec!["--alg".to_owned(), "HS256".to_owned()]).unwrap_err();
    assert!(
        err.to_string().contains("unsupported signing alg HS256"),
        "symmetric or unsupported signing algorithms must fail closed"
    );

    let err = parse_generate_alg(vec!["RS256".to_owned()]).unwrap_err();
    assert!(
        err.to_string()
            .contains("usage: nazo-oauth-keyctl generate"),
        "malformed generate CLI syntax must not fall back to default key generation"
    );
}

#[test]
fn register_external_parser_requires_complete_metadata() {
    let options = parse_register_external_args(vec![
        "--kid".to_owned(),
        "rs256-kms-2026".to_owned(),
        "--alg".to_owned(),
        "RS256".to_owned(),
        "--key-ref".to_owned(),
        "kms://key/1".to_owned(),
        "--public-jwk".to_owned(),
        "/tmp/public.jwk".to_owned(),
    ])
    .unwrap();

    assert_eq!(options.kid, "rs256-kms-2026");
    assert_eq!(options.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(options.key_ref, "kms://key/1");
    assert_eq!(options.public_jwk_file, PathBuf::from("/tmp/public.jwk"));

    for args in [
        vec!["--kid", "kid", "--alg", "RS256", "--key-ref", "ref"],
        vec!["--kid", "kid", "--alg", "RS256", "--public-jwk", "/tmp/jwk"],
        vec![
            "--kid",
            "kid",
            "--key-ref",
            "ref",
            "--public-jwk",
            "/tmp/jwk",
        ],
    ] {
        let err = expect_register_external_error(args.into_iter().map(str::to_owned).collect());
        assert!(
            err.to_string().contains("register-external requires"),
            "missing external signing metadata must be rejected, got {err}"
        );
    }

    let err = expect_register_external_error(vec![
        "--kid".to_owned(),
        "kid".to_owned(),
        "--alg".to_owned(),
        "none".to_owned(),
        "--key-ref".to_owned(),
        "ref".to_owned(),
        "--public-jwk".to_owned(),
        "/tmp/jwk".to_owned(),
    ]);
    assert!(
        err.to_string().contains("unsupported signing alg none"),
        "alg=none must never be accepted for external signing keys"
    );

    let err = expect_register_external_error(vec!["--kid".to_owned()]);
    assert!(
        err.to_string().contains("missing value for --kid"),
        "dangling CLI flags must fail before partial key registration"
    );
}

#[test]
fn keyset_validation_requires_active_unique_supported_non_retired_key() {
    let valid = keyset_with_keys(
        "active",
        vec![local_key("active", "EdDSA", "active.pem", None)],
    );
    assert!(validate_keyset_json(&valid).is_ok());

    let duplicate = keyset_with_keys(
        "active",
        vec![
            local_key("active", "EdDSA", "active.pem", None),
            local_key("active", "RS256", "other.pem", None),
        ],
    );
    assert_error_contains(
        validate_keyset_json(&duplicate).unwrap_err(),
        "duplicate key kid active",
    );

    let missing_active = keyset_with_keys(
        "missing",
        vec![local_key("active", "EdDSA", "active.pem", None)],
    );
    assert_error_contains(
        validate_keyset_json(&missing_active).unwrap_err(),
        "active key missing does not exist",
    );

    let unsupported_alg = keyset_with_keys(
        "active",
        vec![local_key("active", "HS256", "active.pem", None)],
    );
    assert_error_contains(
        validate_keyset_json(&unsupported_alg).unwrap_err(),
        "unsupported alg HS256",
    );

    let retired_active = keyset_with_keys(
        "active",
        vec![local_key("active", "EdDSA", "active.pem", Some(past()))],
    );
    assert_error_contains(
        validate_keyset_json(&retired_active).unwrap_err(),
        "active key active cannot be retired",
    );
}

#[test]
fn keyset_validation_enforces_backend_specific_required_fields() {
    let missing_file = keyset_with_keys(
        "active",
        vec![json!({
            "kid": "active",
            "alg": "EdDSA",
            "created_at": "2026-01-01T00:00:00Z",
            "retire_at": null
        })],
    );
    assert_error_contains(
        validate_keyset_json(&missing_file).unwrap_err(),
        "key active missing file",
    );

    let unsupported_backend = keyset_with_keys(
        "active",
        vec![json!({
            "kid": "active",
            "alg": "EdDSA",
            "backend": "network-hsm",
            "key_ref": "ref"
        })],
    );
    assert_error_contains(
        validate_keyset_json(&unsupported_backend).unwrap_err(),
        "unsupported backend network-hsm",
    );

    let missing_external_ref = keyset_with_keys(
        "active",
        vec![json!({
            "kid": "active",
            "alg": "RS256",
            "backend": "external-command",
            "public_jwk": public_jwk("active", "RS256", "sig")
        })],
    );
    assert_error_contains(
        validate_keyset_json(&missing_external_ref).unwrap_err(),
        "key active missing key_ref",
    );

    let missing_public_jwk = keyset_with_keys(
        "active",
        vec![json!({
            "kid": "active",
            "alg": "RS256",
            "backend": "external-command",
            "key_ref": "kms://key/1"
        })],
    );
    assert_error_contains(
        validate_keyset_json(&missing_public_jwk).unwrap_err(),
        "key active missing public_jwk",
    );
}

#[test]
fn external_public_jwk_metadata_is_bound_to_keyset_entry() {
    let valid = keyset_with_keys(
        "active",
        vec![external_key(
            "active",
            "RS256",
            public_jwk("active", "RS256", "sig"),
        )],
    );
    assert!(validate_keyset_json(&valid).is_ok());

    let kid_mismatch = keyset_with_keys(
        "active",
        vec![external_key(
            "active",
            "RS256",
            public_jwk("other", "RS256", "sig"),
        )],
    );
    assert_error_contains(
        validate_keyset_json(&kid_mismatch).unwrap_err(),
        "public_jwk kid mismatch",
    );

    let alg_mismatch = keyset_with_keys(
        "active",
        vec![external_key(
            "active",
            "RS256",
            public_jwk("active", "PS256", "sig"),
        )],
    );
    assert_error_contains(
        validate_keyset_json(&alg_mismatch).unwrap_err(),
        "public_jwk alg mismatch",
    );

    let use_mismatch = keyset_with_keys(
        "active",
        vec![external_key(
            "active",
            "RS256",
            public_jwk("active", "RS256", "enc"),
        )],
    );
    assert_error_contains(
        validate_keyset_json(&use_mismatch).unwrap_err(),
        "public_jwk use must be sig",
    );
}

#[test]
fn retired_key_detection_uses_rfc3339_time_and_fails_open_for_malformed_metadata() {
    assert!(key_is_retired(&local_key(
        "old",
        "EdDSA",
        "old.pem",
        Some(past())
    )));
    assert!(!key_is_retired(&local_key(
        "future",
        "EdDSA",
        "future.pem",
        Some(future())
    )));
    assert!(!key_is_retired(&local_key(
        "bad",
        "EdDSA",
        "bad.pem",
        Some("not-rfc3339".to_owned())
    )));
    assert!(!key_is_retired(&local_key(
        "none", "EdDSA", "none.pem", None
    )));
}

#[tokio::test]
async fn generate_key_writes_private_material_and_valid_keyset_without_reusing_kids() {
    let dir = temp_keys_dir("generate");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let settings = test_settings(dir.clone());

    generate_key(&settings, jsonwebtoken::Algorithm::RS256)
        .await
        .unwrap();
    generate_key(&settings, jsonwebtoken::Algorithm::ES256)
        .await
        .unwrap();

    let keyset = load_keyset_json(&settings).await.unwrap();
    let active = active_kid(&keyset).unwrap().to_owned();
    let keys = keys_array(&keyset).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|key| key["alg"] == "RS256"));
    assert!(keys.iter().any(|key| key["alg"] == "ES256"));
    assert_eq!(active, keys[0]["kid"].as_str().unwrap());

    for key in keys {
        let file = key["file"].as_str().unwrap();
        let pem = tokio::fs::read_to_string(dir.join(file)).await.unwrap();
        assert!(
            pem.contains("BEGIN PRIVATE KEY") && pem.contains("END PRIVATE KEY"),
            "generated signing key must be written as PKCS#8 private key PEM"
        );
    }
    assert!(
        try_load_keyset(&settings, &keyset_path(&settings))
            .await
            .unwrap()
            .is_some(),
        "generated keyset must be loadable by production signing-key loader"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn activate_and_retire_enforce_signing_key_lifecycle_invariants() {
    let dir = temp_keys_dir("lifecycle");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let settings = test_settings(dir.clone());
    let keyset = keyset_with_keys(
        "active",
        vec![
            local_key("active", "EdDSA", "active.pem", None),
            local_key("previous", "RS256", "previous.pem", None),
            local_key("retired", "PS256", "retired.pem", Some(past())),
        ],
    );
    write_json_atomic(&keyset_path(&settings), &keyset)
        .await
        .unwrap();

    let err = retire_key(&settings, "active", "2026-01-01T00:00:00Z")
        .await
        .unwrap_err();
    assert_error_contains(err, "active key active cannot be retired");

    let err = activate_key(&settings, "retired").await.unwrap_err();
    assert_error_contains(err, "retired key retired cannot be activated");

    activate_key(&settings, "previous").await.unwrap();
    let keyset = load_keyset_json(&settings).await.unwrap();
    assert_eq!(active_kid(&keyset).unwrap(), "previous");

    retire_key(&settings, "active", "2026-01-01T00:00:00Z")
        .await
        .unwrap();
    let retired = load_keyset_json(&settings).await.unwrap();
    let old_active = keys_array(&retired)
        .unwrap()
        .iter()
        .find(|key| key["kid"] == "active")
        .unwrap();
    assert_eq!(old_active["retire_at"], "2026-01-01T00:00:00Z");

    let err = retire_key(&settings, "missing", "2026-01-01T00:00:00Z")
        .await
        .unwrap_err();
    assert_error_contains(err, "key missing does not exist");

    let err = retire_key(&settings, "active", "not-rfc3339")
        .await
        .unwrap_err();
    assert_error_contains(err, "--at must be RFC3339");

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn register_external_key_persists_only_valid_public_signing_metadata() {
    let dir = temp_keys_dir("external");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let settings = test_settings(dir.clone());
    let jwk_file = dir.join("public.jwk.json");
    tokio::fs::write(
        &jwk_file,
        serde_json::to_string(&public_jwk("external", "RS256", "sig")).unwrap(),
    )
    .await
    .unwrap();

    register_external_key(
        &settings,
        RegisterExternalKeyOptions {
            kid: "external".to_owned(),
            alg: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://key/1".to_owned(),
            public_jwk_file: jwk_file,
        },
    )
    .await
    .unwrap();

    let keyset = load_keyset_json(&settings).await.unwrap();
    assert_eq!(active_kid(&keyset).unwrap(), "external");
    let entry = &keys_array(&keyset).unwrap()[0];
    assert_eq!(entry["backend"], "external-command");
    assert_eq!(entry["key_ref"], "kms://key/1");
    assert_eq!(entry["public_jwk"]["kid"], "external");
    assert!(
        try_load_keyset(&settings, &keyset_path(&settings))
            .await
            .unwrap()
            .is_some(),
        "registered external key must be loadable by production keyset validator"
    );

    let bad_jwk = dir.join("bad-public.jwk.json");
    tokio::fs::write(
        &bad_jwk,
        serde_json::to_string(&public_jwk("other", "RS256", "sig")).unwrap(),
    )
    .await
    .unwrap();
    let err = register_external_key(
        &settings,
        RegisterExternalKeyOptions {
            kid: "external-2".to_owned(),
            alg: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://key/2".to_owned(),
            public_jwk_file: bad_jwk,
        },
    )
    .await
    .unwrap_err();
    assert_error_contains(err, "public_jwk kid mismatch");

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

fn keyset_with_keys(active_kid: &str, keys: Vec<Value>) -> Value {
    json!({
        "active_kid": active_kid,
        "keys": keys,
    })
}

fn local_key(kid: &str, alg: &str, file: &str, retire_at: Option<String>) -> Value {
    json!({
        "kid": kid,
        "alg": alg,
        "file": file,
        "created_at": "2026-01-01T00:00:00Z",
        "retire_at": retire_at,
    })
}

fn external_key(kid: &str, alg: &str, public_jwk: Value) -> Value {
    json!({
        "kid": kid,
        "alg": alg,
        "backend": "external-command",
        "key_ref": "kms://key/1",
        "public_jwk": public_jwk,
        "created_at": "2026-01-01T00:00:00Z",
        "retire_at": null,
    })
}

fn public_jwk(kid: &str, alg: &str, key_use: &str) -> Value {
    json!({
        "kty": "RSA",
        "kid": kid,
        "alg": alg,
        "use": key_use,
        "n": "modulus",
        "e": "AQAB"
    })
}

fn past() -> String {
    (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn future() -> String {
    (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn assert_error_contains(error: anyhow::Error, expected: &str) {
    assert!(
        error.to_string().contains(expected),
        "expected error to contain {expected:?}, got {error}"
    );
}

fn expect_register_external_error(args: Vec<String>) -> anyhow::Error {
    match parse_register_external_args(args) {
        Ok(_) => panic!("register-external parser unexpectedly accepted invalid input"),
        Err(error) => error,
    }
}

fn temp_keys_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nazo_keyctl_{label}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn test_settings(jwk_keys_dir: PathBuf) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://frontend.example".to_owned(),
        cors_allowed_origins: vec!["https://frontend.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "session".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 28_800,
        auth_code_ttl_seconds: 300,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: jwk_keys_dir.join("avatars"),
        jwk_keys_dir,
        signing_external_command: vec!["/bin/false".to_owned()],
        signing_external_timeout_ms: 2_000,
        trusted_proxy_cidrs: Vec::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: FederationSettings {
            oidc: None,
            saml_gateway: None,
        },
    }
}
