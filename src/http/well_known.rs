use super::prelude::*;
use crate::domain::{Keyset, SUPPORTED_AUTHORIZATION_DETAILS_TYPES};
use crate::settings::{AuthorizationServerProfile, Settings};

const CLIENT_JWT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const REQUEST_OBJECT_SIGNING_ALGS: [&str; 5] = ["none", "EdDSA", "RS256", "ES256", "PS256"];
const PROMPT_VALUES_SUPPORTED: [&str; 4] = ["login", "consent", "select_account", "none"];
const CLAIMS_SUPPORTED: [&str; 24] = [
    "sub",
    "auth_time",
    "amr",
    "acr",
    "nonce",
    "preferred_username",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
    "updated_at",
];
const CLIENT_AUTH_METHODS: [&str; 6] = [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "none",
];
const FAPI2_CLIENT_AUTH_METHODS: [&str; 3] = [
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
];

pub(crate) async fn health() -> Json<Value> {
    Json(json!({"status": "正常"}))
}

pub(crate) async fn captcha_config() -> Json<Value> {
    Json(json!({
        "turnstile_enabled": false,
        "turnstile_site_key": null,
        "registration_enabled": true
    }))
}

fn authorization_server_metadata_value(state: &AppState) -> Value {
    authorization_server_metadata(&state.settings, &state.keyset)
}

fn authorization_server_metadata(settings: &Settings, keyset: &Keyset) -> Value {
    let issuer = settings.issuer.as_str();
    let mtls_base = settings.mtls_endpoint_base_url.as_str();
    let id_token_signing_algs = id_token_signing_alg_values_supported(keyset);
    let authorization_signing_algs = active_signing_alg_values_supported(keyset);
    let mtls_enabled = !settings.trusted_proxy_cidrs.is_empty();
    let token_auth_methods =
        token_endpoint_auth_methods_supported(settings.authorization_server_profile, mtls_enabled);
    let request_object_signing_algs = request_object_signing_alg_values_supported(
        settings.authorization_server_profile,
        authorization_signing_algs.as_slice(),
    );
    let mut metadata = json!({
        "issuer": issuer,
        "authorization_server_profile": settings.authorization_server_profile.as_str(),
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "jwt"],
        "subject_types_supported": [settings.subject_type.as_str()],
        "id_token_signing_alg_values_supported": id_token_signing_algs,
        "authorization_signing_alg_values_supported": authorization_signing_algs,
        "token_endpoint_auth_methods_supported": token_auth_methods,
        "token_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "revocation_endpoint_auth_methods_supported": token_auth_methods,
        "revocation_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "introspection_endpoint_auth_methods_supported": token_auth_methods,
        "introspection_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
        "claims_supported": CLAIMS_SUPPORTED,
        "prompt_values_supported": PROMPT_VALUES_SUPPORTED,
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "authorization_response_iss_parameter_supported": true,
        "claims_parameter_supported": true,
        "authorization_details_types_supported": SUPPORTED_AUTHORIZATION_DETAILS_TYPES,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "request_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "require_pushed_authorization_requests": settings.require_pushed_authorization_requests,
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "request_object_signing_alg_values_supported": request_object_signing_algs
    });
    if mtls_enabled {
        metadata["tls_client_certificate_bound_access_tokens"] = json!(true);
        metadata["mtls_endpoint_aliases"] = json!({
            "token_endpoint": format!("{mtls_base}/token"),
            "pushed_authorization_request_endpoint": format!("{mtls_base}/par"),
            "revocation_endpoint": format!("{mtls_base}/revoke"),
            "introspection_endpoint": format!("{mtls_base}/introspect"),
            "userinfo_endpoint": format!("{mtls_base}/userinfo")
        });
    }
    metadata
}

fn token_endpoint_auth_methods_supported(
    profile: AuthorizationServerProfile,
    mtls_enabled: bool,
) -> Vec<&'static str> {
    let methods = if profile.requires_fapi2_security() {
        FAPI2_CLIENT_AUTH_METHODS.as_slice()
    } else {
        CLIENT_AUTH_METHODS.as_slice()
    };
    methods
        .iter()
        .copied()
        .filter(|method| {
            mtls_enabled || !matches!(*method, "tls_client_auth" | "self_signed_tls_client_auth")
        })
        .collect()
}

fn request_object_signing_alg_values_supported(
    profile: AuthorizationServerProfile,
    active_signing_algs: &[&'static str],
) -> Vec<&'static str> {
    if profile.requires_signed_authorization_request() {
        return active_signing_algs.to_vec();
    }
    REQUEST_OBJECT_SIGNING_ALGS.to_vec()
}

fn active_signing_alg_values_supported(keyset: &Keyset) -> Vec<&'static str> {
    signing_algorithm_name(keyset.active_alg)
        .map(|alg| vec![alg])
        .unwrap_or_default()
}

fn id_token_signing_alg_values_supported(keyset: &Keyset) -> Vec<&'static str> {
    let mut values = active_signing_alg_values_supported(keyset);
    values.push("RS256");
    values.sort_unstable();
    values.dedup();
    values
}

pub(crate) async fn discovery(state: Data<AppState>) -> Json<Value> {
    Json(authorization_server_metadata_value(&state))
}

pub(crate) async fn oauth_authorization_server_metadata(state: Data<AppState>) -> Json<Value> {
    Json(authorization_server_metadata_value(&state))
}

pub(crate) async fn jwks(state: Data<AppState>) -> Json<Value> {
    Json(state.keyset.jwks())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::domain::VerificationKey;
    use crate::settings::{
        AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings,
        RateLimitSettings, RequestObjectJtiPolicy, SubjectType,
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
        let metadata = authorization_server_metadata(
            &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
            &keyset(jsonwebtoken::Algorithm::RS256),
        );

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

        assert_eq!(
            metadata
                .get("authorization_server_profile")
                .and_then(Value::as_str),
            Some("oauth2-baseline")
        );
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

        assert_eq!(
            metadata
                .get("authorization_server_profile")
                .and_then(Value::as_str),
            Some("fapi2-security")
        );
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
    fn discovery_message_signing_profile_requires_signed_request_object_algs() {
        let metadata = authorization_server_metadata(
            &settings(
                AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
                Vec::new(),
            ),
            &keyset(jsonwebtoken::Algorithm::PS256),
        );

        assert_eq!(
            metadata
                .get("authorization_server_profile")
                .and_then(Value::as_str),
            Some("fapi2-message-signing-authz-request")
        );
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
}
