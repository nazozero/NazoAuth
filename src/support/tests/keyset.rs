use super::*;
use proptest::prelude::*;
use std::path::PathBuf;

use crate::settings::{EmailDelivery, EmailSettings, RateLimitSettings};
use crate::support::ClientIpHeaderMode;

#[test]
fn jwks_publishes_active_and_previous_verification_keys() {
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    let previous_der = ed25519_pkcs8_private_der(&[2u8; 32]);
    let keyset = Keyset {
        active_kid: "active".to_owned(),
        active_alg: jsonwebtoken::Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(active_der.clone()),
        verification_keys: vec![
            VerificationKey {
                kid: "active".to_owned(),
                public_jwk: public_jwk_from_private_der(
                    "active",
                    jsonwebtoken::Algorithm::EdDSA,
                    &active_der,
                )
                .unwrap(),
            },
            VerificationKey {
                kid: "previous".to_owned(),
                public_jwk: public_jwk_from_private_der(
                    "previous",
                    jsonwebtoken::Algorithm::EdDSA,
                    &previous_der,
                )
                .unwrap(),
            },
        ],
    };

    let jwks = keyset.jwks();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
    assert!(keyset.verification_key("previous").is_some());
}

#[test]
fn retired_non_active_key_entries_are_detected() {
    let retired = json!({"retire_at": "2000-01-01T00:00:00Z"});
    let live = json!({"retire_at": "2999-01-01T00:00:00Z"});

    assert!(key_entry_is_retired(&retired));
    assert!(!key_entry_is_retired(&live));
}

proptest! {
    #[test]
    fn ed25519_pkcs8_seed_roundtrips_through_der(seed in any::<[u8; 32]>()) {
        let der = ed25519_pkcs8_private_der(&seed);

        prop_assert_eq!(ed25519_seed_from_pkcs8(&der), Some(seed));
        prop_assert!(public_jwk_from_private_der(
            "kid-1",
            jsonwebtoken::Algorithm::EdDSA,
            &der
        ).is_ok());
    }

    #[test]
    fn pem_der_roundtrip_preserves_key_material(seed in any::<[u8; 32]>()) {
        let der = ed25519_pkcs8_private_der(&seed);
        let pem = der_to_pem(&der, "PRIVATE KEY");
        let decoded = pem_to_der(&pem);

        prop_assert_eq!(decoded.as_deref(), Some(der.as_slice()));
    }

    #[test]
    fn unsupported_keyset_algorithms_are_rejected(alg in "[A-Z0-9]{1,12}") {
        prop_assume!(!matches!(alg.as_str(), "EdDSA" | "RS256" | "ES256" | "PS256"));
        let entry = json!({"alg": alg});

        prop_assert!(key_entry_algorithm(&entry).is_err());
    }
}

#[tokio::test]
async fn missing_keyset_file_allows_initial_creation() {
    let keys_dir = temp_keys_dir("missing");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await.unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(result.is_none());
}

#[tokio::test]
async fn created_keyset_uses_oidc_mandatory_default_signing_alg() {
    let keys_dir = temp_keys_dir("create_default_alg");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let settings = test_settings(keys_dir.clone());

    let keyset = create_new_keyset(&settings).await.unwrap();
    let keyset_json = tokio::fs::read_to_string(keys_dir.join("keyset.json"))
        .await
        .unwrap();
    let payload: Value = serde_json::from_str(&keyset_json).unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(keyset.active_kid.starts_with("rs256-"));
    assert_eq!(keyset.active_alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(payload["keys"][0]["alg"], "RS256");
    assert_eq!(keyset.jwks()["keys"][0]["alg"], "RS256");
}

#[tokio::test]
async fn duplicate_keyset_kids_are_rejected() {
    let keys_dir = temp_keys_dir("duplicate_kid");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let first_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    let second_der = ed25519_pkcs8_private_der(&[2u8; 32]);
    tokio::fs::write(
        keys_dir.join("first.pem"),
        der_to_pem(&first_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("second.pem"),
        der_to_pem(&second_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "duplicate",
            "keys": [
                {"kid": "duplicate", "file": "first.pem", "retire_at": null},
                {"kid": "duplicate", "file": "second.pem", "retire_at": null}
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    match result {
        Ok(_) => panic!("duplicate keyset kid should be rejected"),
        Err(error) => assert!(format!("{error:#}").contains("duplicate kid duplicate")),
    }
}

#[tokio::test]
async fn live_previous_key_entry_must_load_successfully() {
    let keys_dir = temp_keys_dir("missing_previous");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    tokio::fs::write(
        keys_dir.join("active.pem"),
        der_to_pem(&active_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {"kid": "active", "file": "active.pem", "retire_at": null},
                {"kid": "previous", "file": "missing.pem", "retire_at": null}
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn retired_previous_key_entry_is_skipped() {
    let keys_dir = temp_keys_dir("retired_previous");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    tokio::fs::write(
        keys_dir.join("active.pem"),
        der_to_pem(&active_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {"kid": "active", "file": "active.pem", "retire_at": null},
                {
                    "kid": "previous",
                    "file": "missing.pem",
                    "retire_at": "2000-01-01T00:00:00Z"
                }
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let keyset = try_load_keyset(&settings, &keyset_path)
        .await
        .unwrap()
        .unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(keyset.active_kid, "active");
    assert_eq!(keyset.verification_keys.len(), 1);
}

#[tokio::test]
async fn retired_active_key_entry_is_rejected() {
    let keys_dir = temp_keys_dir("retired_active");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = ed25519_pkcs8_private_der(&[1u8; 32]);
    tokio::fs::write(
        keys_dir.join("active.pem"),
        der_to_pem(&active_der, "PRIVATE KEY"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "active",
            "keys": [
                {
                    "kid": "active",
                    "file": "active.pem",
                    "retire_at": "2000-01-01T00:00:00Z"
                }
            ]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn active_external_command_key_requires_signer_command() {
    let keys_dir = temp_keys_dir("external_missing_command");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let public_jwk = public_jwk_from_private_der(
        "external-active",
        jsonwebtoken::Algorithm::RS256,
        &active_der,
    )
    .unwrap();
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "external-active",
            "keys": [{
                "kid": "external-active",
                "alg": "RS256",
                "backend": "external-command",
                "key_ref": "kms://tenant/signing/external-active",
                "public_jwk": public_jwk,
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let settings = test_settings(keys_dir.clone());
    let keyset_path = keys_dir.join("keyset.json");

    let result = try_load_keyset(&settings, &keyset_path).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    match result {
        Ok(_) => panic!("active external-command key without command should fail"),
        Err(error) => assert!(format!("{error:#}").contains("SIGNING_EXTERNAL_COMMAND")),
    }
}

#[tokio::test]
async fn external_command_signer_produces_verifiable_jwt() {
    let keys_dir = temp_keys_dir("external_signer");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let private_pem = der_to_pem(&active_der, "RSA PRIVATE KEY");
    let public_jwk = public_jwk_from_private_der(
        "external-active",
        jsonwebtoken::Algorithm::RS256,
        &active_der,
    )
    .unwrap();
    let private_key_path = keys_dir.join("external-active.pem");
    tokio::fs::write(&private_key_path, &private_pem)
        .await
        .unwrap();
    let signer = keys_dir.join("signer.sh");
    tokio::fs::write(
        &signer,
        r#"#!/bin/sh
set -eu
key_file="$1"
request=$(cat)
signing_input=$(printf '%s' "$request" | sed -n 's/.*"signing_input":"\([^"]*\)".*/\1/p')
signature=$(printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$key_file" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
printf '{"signature":"%s"}' "$signature"
"#
        ,
    )
    .await
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
    }
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "external-active",
            "keys": [{
                "kid": "external-active",
                "alg": "RS256",
                "backend": "external-command",
                "key_ref": "test-ed25519",
                "public_jwk": public_jwk,
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_external_command = vec![
        signer.display().to_string(),
        private_key_path.display().to_string(),
    ];
    let keyset_path = keys_dir.join("keyset.json");
    let keyset = try_load_keyset(&settings, &keyset_path)
        .await
        .unwrap()
        .unwrap();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("external-active".to_owned());
    let claims = json!({"sub": "subject-1", "exp": 4_102_444_800_i64});

    let token = keyset.sign_jwt(&header, &claims).await.unwrap();
    let decoding_key =
        crate::support::jwt_decoding_key_from_jwk(&keyset.jwks()["keys"][0], header.alg).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = false;
    let decoded = jsonwebtoken::decode::<Value>(&token, &decoding_key, &validation).unwrap();
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    assert_eq!(decoded.claims["sub"], "subject-1");
}

#[tokio::test]
async fn external_command_signer_signature_must_match_active_public_jwk() {
    let keys_dir = temp_keys_dir("external_signer_bad_signature");
    tokio::fs::create_dir_all(&keys_dir).await.unwrap();
    let active_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let wrong_der = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .unwrap()
        .private_pkcs8_der;
    let wrong_private_pem = der_to_pem(&wrong_der, "RSA PRIVATE KEY");
    let public_jwk = public_jwk_from_private_der(
        "external-active",
        jsonwebtoken::Algorithm::RS256,
        &active_der,
    )
    .unwrap();
    let wrong_private_key_path = keys_dir.join("wrong-external-active.pem");
    tokio::fs::write(&wrong_private_key_path, &wrong_private_pem)
        .await
        .unwrap();
    let signer = keys_dir.join("signer.sh");
    tokio::fs::write(
        &signer,
        r#"#!/bin/sh
set -eu
key_file="$1"
request=$(cat)
signing_input=$(printf '%s' "$request" | sed -n 's/.*"signing_input":"\([^"]*\)".*/\1/p')
signature=$(printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$key_file" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
printf '{"signature":"%s"}' "$signature"
"#,
    )
    .await
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
    }
    tokio::fs::write(
        keys_dir.join("keyset.json"),
        serde_json::to_string_pretty(&json!({
            "active_kid": "external-active",
            "keys": [{
                "kid": "external-active",
                "alg": "RS256",
                "backend": "external-command",
                "key_ref": "kms://tenant/signing/external-active",
                "public_jwk": public_jwk,
                "retire_at": null
            }]
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let mut settings = test_settings(keys_dir.clone());
    settings.signing_external_command = vec![
        signer.display().to_string(),
        wrong_private_key_path.display().to_string(),
    ];
    let keyset_path = keys_dir.join("keyset.json");
    let keyset = try_load_keyset(&settings, &keyset_path)
        .await
        .unwrap()
        .unwrap();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("external-active".to_owned());
    let claims = json!({"sub": "subject-1", "exp": 4_102_444_800_i64});

    let result = keyset.sign_jwt(&header, &claims).await;
    let _ = tokio::fs::remove_dir_all(&keys_dir).await;

    match result {
        Ok(_) => panic!("external signer signature mismatch should fail"),
        Err(error) => assert!(format!("{error}").contains("does not verify")),
    }
}

fn temp_keys_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nazo_keyset_{label}_{}",
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
        authorization_server_profile: crate::settings::AuthorizationServerProfile::Oauth2Baseline,
        dpop_nonce_policy: crate::settings::DpopNoncePolicy::Required,
        request_object_jti_policy: crate::settings::RequestObjectJtiPolicy::Optional,
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
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        trusted_proxy_cidrs: Vec::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: crate::settings::SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: false,
        scim_bearer_token: None,
        passkey: crate::settings::PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: crate::settings::FederationSettings {
            oidc: None,
            saml_gateway: None,
        },
    }
}
