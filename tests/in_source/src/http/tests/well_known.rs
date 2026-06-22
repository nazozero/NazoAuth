use super::*;
use std::path::PathBuf;

use crate::domain::SUPPORTED_AUTHORIZATION_DETAILS_TYPES;
use crate::domain::VerificationKey;
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, RateLimitSettings,
    RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr};

fn keyset(alg: jsonwebtoken::Algorithm) -> Keyset {
    let alg_name = signing_algorithm_name(alg).expect("test alg should be supported");
    Keyset {
        active_kid: "active".to_owned(),
        active_alg: alg,
        active_signing_key: crate::domain::ActiveSigningKey::LocalPkcs8Der(Vec::new()),
        verification_keys: vec![VerificationKey {
            kid: "active".to_owned(),
            public_jwk: json!({"kty": "RSA", "kid": "active", "alg": alg_name, "use": "sig"}),
        }],
    }
}

fn settings(profile: AuthorizationServerProfile, trusted_proxy_cidrs: Vec<IpCidr>) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://mtls.issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins: vec!["https://app.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        authorization_server_profile: profile,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "sid".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 3600,
        auth_code_ttl_seconds: 60,
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
        avatar_storage_dir: PathBuf::from("runtime/avatars"),
        jwk_keys_dir: PathBuf::from("runtime/keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        trusted_proxy_cidrs,
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: profile.requires_fapi2_security(),
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
        enable_request_object: false,
        enable_request_uri_parameter: false,
        enable_par_request_object: false,
        enable_authorization_details: false,
        enable_legacy_audience_param: false,
    }
}

#[test]
fn discovery_prompt_values_match_authorization_request_parser() {
    assert_eq!(
        PROMPT_VALUES_SUPPORTED,
        ["login", "consent", "select_account", "none"]
    );
}

#[test]
fn discovery_claims_include_supported_id_token_acr() {
    assert!(CLAIMS_SUPPORTED.contains(&"acr"));
}

#[test]
fn discovery_advertises_supported_rar_types() {
    let mut s = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    s.enable_authorization_details = true;
    let metadata = authorization_server_metadata(&s, &keyset(jsonwebtoken::Algorithm::RS256));

    assert_eq!(
        metadata
            .get("authorization_details_types_supported")
            .and_then(Value::as_array)
            .expect("RAR type metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        SUPPORTED_AUTHORIZATION_DETAILS_TYPES
    );
}

#[test]
fn discovery_advertises_oidc_logout_endpoints_and_backchannel_support() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert_eq!(
        metadata.get("end_session_endpoint").and_then(Value::as_str),
        Some("https://issuer.example/logout")
    );
    assert_eq!(
        metadata
            .get("backchannel_logout_supported")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .get("backchannel_logout_session_supported")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn discovery_id_token_algs_include_oidc_rs256_baseline() {
    let keyset = keyset(jsonwebtoken::Algorithm::RS256);

    assert_eq!(
        id_token_signing_alg_values_supported(&keyset),
        vec!["RS256"]
    );
}

#[test]
fn discovery_id_token_algs_include_active_alg_and_rs256_baseline() {
    let keyset = keyset(jsonwebtoken::Algorithm::PS256);

    assert_eq!(
        id_token_signing_alg_values_supported(&keyset),
        vec!["PS256", "RS256"]
    );
}

#[test]
fn discovery_authorization_response_algs_match_active_key_only() {
    let keyset = keyset(jsonwebtoken::Algorithm::PS256);

    assert_eq!(active_signing_alg_values_supported(&keyset), vec!["PS256"]);
}

#[test]
fn discovery_does_not_advertise_mtls_when_no_trusted_proxy_is_configured() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert!(metadata.get("authorization_server_profile").is_none());
    assert!(
        metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .expect("methods should be an array")
            .iter()
            .all(|method| !matches!(
                method.as_str(),
                Some("tls_client_auth" | "self_signed_tls_client_auth")
            ))
    );
    assert!(metadata.get("mtls_endpoint_aliases").is_none());
    assert!(
        metadata
            .get("tls_client_certificate_bound_access_tokens")
            .is_none()
    );
}

#[test]
fn discovery_advertises_mtls_only_for_configured_proxy_profile() {
    let metadata = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Oauth2Baseline,
            vec![IpCidr::parse("192.0.2.0/24").unwrap()],
        ),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert_eq!(
        metadata
            .get("tls_client_certificate_bound_access_tokens")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .pointer("/mtls_endpoint_aliases/token_endpoint")
            .and_then(Value::as_str),
        Some("https://mtls.issuer.example/token")
    );
}

#[test]
fn discovery_fapi2_security_metadata_is_profile_scoped() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Fapi2Security, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert!(metadata.get("authorization_server_profile").is_none());
    assert_eq!(
        metadata
            .get("require_pushed_authorization_requests")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .expect("methods should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["private_key_jwt"]
    );
}

#[test]
fn discovery_fapi2_with_mtls_advertises_only_fapi_client_auth_methods() {
    let metadata = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Fapi2Security,
            vec![IpCidr::parse("192.0.2.0/24").unwrap()],
        ),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert_eq!(
        metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .expect("methods should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec![
            "private_key_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth"
        ]
    );
    assert!(
        !metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .any(|method| matches!(method.as_str(), Some("client_secret_basic" | "none")))
    );
}

#[test]
fn discovery_message_signing_profile_requires_signed_request_object_algs() {
    let metadata = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
            Vec::new(),
        ),
        &keyset(jsonwebtoken::Algorithm::PS256),
    );

    assert!(metadata.get("authorization_server_profile").is_none());
    assert_eq!(
        metadata
            .get("request_object_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("request object algs should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["PS256"]
    );
}
