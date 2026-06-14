use base64::{Engine, engine::general_purpose::STANDARD};
use nazo_oauth_server::oidf_seed::{callback_uris, config};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[test]
fn callback_uris_include_local_official_and_extra_suite_bases() {
    let primary = "https://nginx:8443";
    let mut urls = vec![
        primary.to_owned(),
        "https://www.certification.openid.net".to_owned(),
        "https://suite.example".to_owned(),
    ];
    urls.sort();

    let callbacks = callback_uris(&urls, "local-nazo-oauth-oidf");

    assert!(
        callbacks
            .iter()
            .any(|value| value == "https://nginx:8443/test/a/local-nazo-oauth-oidf/callback")
    );
    assert!(callbacks.iter().any(|value| value
        == "https://www.certification.openid.net/test/a/local-nazo-oauth-oidf/callback"));
    assert!(
        callbacks
            .iter()
            .any(|value| value == "https://suite.example/test/a/local-nazo-oauth-oidf/callback")
    );
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

    let public = config::public_jwks(&private_jwks).unwrap();
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

#[test]
fn oidf_seed_config_requires_string_values_without_coercion() {
    let plan = json!({
        "client_id": "client-1",
        "numeric": 42,
    });

    assert_eq!(
        config::string_value(&plan, "client_id").unwrap(),
        "client-1"
    );
    let missing = config::string_value(&plan, "missing").unwrap_err();
    assert!(
        missing.to_string().contains("missing string field missing"),
        "missing string field should produce a stable diagnostic, got {missing}"
    );
    let wrong_type = config::string_value(&plan, "numeric").unwrap_err();
    assert!(
        wrong_type
            .to_string()
            .contains("missing string field numeric"),
        "non-string values must not be coerced into OIDF config strings"
    );
}

#[test]
fn oidf_seed_client_scopes_default_and_normalize_whitespace() {
    let default_client = serde_json::Map::new();
    assert_eq!(
        config::client_scopes(&default_client),
        json!(["openid", "profile", "email", "offline_access"])
    );

    let mut explicit_client = serde_json::Map::new();
    explicit_client.insert(
        "scope".to_owned(),
        Value::String(" openid  payments   accounts ".to_owned()),
    );
    assert_eq!(
        config::client_scopes(&explicit_client),
        json!(["openid", "payments", "accounts"])
    );
}

#[test]
fn oidf_seed_plan_config_files_are_sorted_and_filtered() {
    let dir = test_temp_dir("oidf-plan-files");
    fs::write(dir.join("z-plan-config.json"), "{}").unwrap();
    fs::write(dir.join("ignored.json"), "{}").unwrap();
    fs::write(dir.join("a-plan-config.json"), "{}").unwrap();
    fs::write(dir.join("plan-config.json.bak"), "{}").unwrap();

    let files = config::plan_config_files(&dir).unwrap();
    fs::remove_dir_all(&dir).unwrap();

    assert_eq!(
        files,
        vec![
            "a-plan-config.json".to_owned(),
            "z-plan-config.json".to_owned()
        ],
        "OIDF seed input order must be deterministic and limited to plan config files"
    );
}

#[test]
fn oidf_seed_read_plan_config_reports_parse_and_path_errors() {
    let dir = test_temp_dir("oidf-read-plan");
    fs::write(
        dir.join("valid-plan-config.json"),
        r#"{"client_id":"client-1"}"#,
    )
    .unwrap();
    fs::write(dir.join("invalid-plan-config.json"), "{").unwrap();

    let valid = config::read_plan_config(&dir, "valid-plan-config.json").unwrap();
    assert_eq!(valid["client_id"], "client-1");

    let invalid = config::read_plan_config(&dir, "invalid-plan-config.json").unwrap_err();
    assert!(
        invalid.to_string().contains("invalid-plan-config.json"),
        "parse failures should identify the bad plan config path"
    );
    let missing = config::read_plan_config(&dir, "missing-plan-config.json").unwrap_err();
    assert!(
        missing.to_string().contains("missing-plan-config.json"),
        "read failures should identify the missing plan config path"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn oidf_seed_mtls_thumbprint_is_bound_to_requested_client_slot() {
    let cert1 = certificate_pem([1u8, 2, 3, 4]);
    let cert2 = certificate_pem([5u8, 6, 7, 8]);
    let plan = json!({
        "mtls": { "cert": cert1 },
        "mtls2": { "cert": cert2 },
    });

    assert_eq!(
        config::mtls_thumbprint(&plan, "client").unwrap(),
        Some(expected_thumbprint([1u8, 2, 3, 4]))
    );
    assert_eq!(
        config::mtls_thumbprint(&plan, "client2").unwrap(),
        Some(expected_thumbprint([5u8, 6, 7, 8]))
    );
    assert_eq!(config::mtls_thumbprint(&json!({}), "client").unwrap(), None);
}

#[test]
fn oidf_seed_mtls_thumbprint_fails_closed_for_malformed_certificate() {
    let missing_end = json!({
        "mtls": { "cert": "-----BEGIN CERTIFICATE-----\nAQID" },
    });
    let err = config::mtls_thumbprint(&missing_end, "client").unwrap_err();
    assert!(
        err.to_string().contains("missing END marker"),
        "malformed configured mTLS certificates must not produce a thumbprint"
    );

    let invalid_base64 = json!({
        "mtls": {
            "cert": "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"
        },
    });
    let err = config::mtls_thumbprint(&invalid_base64, "client").unwrap_err();
    assert!(
        err.to_string().contains("base64 decode failed"),
        "invalid configured mTLS certificate bytes must fail closed"
    );
}

fn certificate_pem<const N: usize>(bytes: [u8; N]) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        STANDARD.encode(bytes)
    )
}

fn expected_thumbprint<const N: usize>(bytes: [u8; N]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

fn test_temp_dir(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("nazo-auth-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}
