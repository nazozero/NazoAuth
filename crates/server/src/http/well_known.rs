use actix_web::web::{Data, Json};
use serde_json::{Value, json};

use crate::domain::{KeySnapshot, MetadataConfig, MetadataHandles};
use crate::http::authorization::BASELINE_ACR_VALUE;
#[cfg(test)]
use crate::http::token::CIBA_GRANT_TYPE;
#[cfg(test)]
use crate::settings::Settings;
use crate::settings::{AuthorizationServerProfile, CibaSecurityProfile, SubjectType};
use crate::support::{
    SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS, SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
    signing_algorithm_name,
};
use nazo_auth::MetadataCapabilities;

const CLIENT_JWT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const DPOP_SIGNING_ALGS: [&str; 2] = ["EdDSA", "ES256"];
const FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS: [&str; 3] = ["EdDSA", "ES256", "PS256"];
const REQUEST_OBJECT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const BASELINE_REQUEST_OBJECT_SIGNING_ALGS: [&str; 5] =
    ["none", "EdDSA", "RS256", "ES256", "PS256"];
const PROMPT_VALUES_SUPPORTED: [&str; 4] = ["login", "consent", "select_account", "none"];
const CLAIMS_SUPPORTED: [&str; 24] = [
    "sub",
    "auth_time",
    "amr",
    "nonce",
    "acr",
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
const SCOPES_SUPPORTED: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
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

fn authorization_server_metadata_value(handles: &MetadataHandles) -> Value {
    let keyset = handles.keyset.snapshot();
    let capabilities = MetadataCapabilities::from_snapshot(&handles.runtime_modules.snapshot());
    authorization_server_metadata_with_capabilities(&handles.config, &keyset, &capabilities)
}

#[cfg(test)]
fn authorization_server_metadata(settings: &Settings, keyset: &KeySnapshot) -> Value {
    let config = MetadataConfig::from(settings);
    authorization_server_metadata_with_capabilities(
        &config,
        keyset,
        &metadata_capabilities_from_settings(settings),
    )
}

fn authorization_server_metadata_with_capabilities(
    config: &MetadataConfig,
    keyset: &KeySnapshot,
    capabilities: &MetadataCapabilities,
) -> Value {
    let issuer = config.issuer.as_str();
    let mtls_base = config.mtls_endpoint_base_url.as_str();
    let id_token_signing_algs = id_token_signing_alg_values_supported(keyset);
    let response_signing_algs = keyset.response_signing_alg_values_supported();
    let userinfo_signing_algs = response_signing_algs.clone();
    let authorization_signing_algs = response_signing_algs;
    let active_signing_algs = active_signing_alg_values_supported(keyset);
    let mtls_enabled = config.mtls_enabled;
    let token_auth_methods = token_endpoint_auth_methods_supported(
        config.authorization_server_profile,
        config.ciba_security_profile,
        mtls_enabled,
    );
    let token_auth_signing_algs = token_endpoint_auth_signing_alg_values_supported(config);
    let request_object_signing_algs = request_object_signing_alg_values_supported(
        config.authorization_server_profile,
        active_signing_algs.as_slice(),
    );
    let mut response_modes = response_modes_supported(config.authorization_server_profile);
    if !capabilities.jarm {
        response_modes.retain(|mode| *mode != "jwt");
    }
    let grant_types = capabilities.grant_types.clone();
    let mut scopes_supported = SCOPES_SUPPORTED.to_vec();
    if capabilities.native_sso {
        scopes_supported.push("device_sso");
    }
    let mut metadata = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "response_modes_supported": response_modes,
        "subject_types_supported": match (config.pairwise_subject_enabled, config.subject_type) {
            (false, _) => vec!["public"],
            (true, SubjectType::Pairwise) => vec!["pairwise"],
            (true, _) => vec!["public", "pairwise"],
        },
        "id_token_signing_alg_values_supported": id_token_signing_algs,
        "userinfo_signing_alg_values_supported": userinfo_signing_algs,
        "userinfo_encryption_alg_values_supported": SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        "userinfo_encryption_enc_values_supported": SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
        "authorization_signing_alg_values_supported": authorization_signing_algs,
        "authorization_encryption_alg_values_supported": SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        "authorization_encryption_enc_values_supported": SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
        "token_endpoint_auth_methods_supported": token_auth_methods,
        "token_endpoint_auth_signing_alg_values_supported": token_auth_signing_algs,
        "revocation_endpoint_auth_methods_supported": token_auth_methods,
        "revocation_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "introspection_endpoint_auth_methods_supported": token_auth_methods,
        "introspection_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "scopes_supported": scopes_supported,
        "claims_supported": CLAIMS_SUPPORTED,
        "acr_values_supported": [BASELINE_ACR_VALUE],
        "prompt_values_supported": PROMPT_VALUES_SUPPORTED,
        "grant_types_supported": grant_types,
        "protected_resources": [config.protected_resource_identifier.as_str()],
        "authorization_response_iss_parameter_supported": true,
        "claims_parameter_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "require_pushed_authorization_requests": config.require_pushed_authorization_requests,
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": DPOP_SIGNING_ALGS,
        "request_object_signing_alg_values_supported": request_object_signing_algs
    });
    if capabilities.authorization_details {
        metadata["authorization_details_types_supported"] =
            json!(["account_information", "payment_initiation"]);
    }
    if capabilities.device_authorization {
        metadata["device_authorization_endpoint"] = json!(format!("{issuer}/device_authorization"));
    }
    if capabilities.dynamic_client_registration {
        metadata["registration_endpoint"] = json!(format!("{issuer}/register"));
    }
    if capabilities.frontchannel_logout {
        metadata["frontchannel_logout_supported"] = json!(true);
        metadata["frontchannel_logout_session_supported"] = json!(true);
    }
    if capabilities.session_management {
        metadata["check_session_iframe"] = json!(format!("{issuer}/check_session"));
    }
    if capabilities.ciba {
        metadata["backchannel_authentication_endpoint"] = json!(format!("{issuer}/bc-authorize"));
        metadata["backchannel_token_delivery_modes_supported"] = json!(["poll"]);
        metadata["backchannel_user_code_parameter_supported"] = json!(false);
        metadata["backchannel_authentication_request_signing_alg_values_supported"] =
            json!(FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS);
    }
    if capabilities.native_sso {
        metadata["native_sso_supported"] = json!(true);
    }
    if config
        .authorization_server_profile
        .requires_signed_introspection()
    {
        metadata["introspection_signing_alg_values_supported"] =
            json!(active_signing_alg_values_supported(keyset));
        metadata["introspection_encryption_alg_values_supported"] =
            json!(SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS);
        metadata["introspection_encryption_enc_values_supported"] =
            json!(SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS);
    }
    if capabilities.request_objects {
        metadata["request_parameter_supported"] = json!(true);
    }
    if config.request_uri_parameter_enabled {
        metadata["request_uri_parameter_supported"] = json!(true);
        metadata["require_request_uri_registration"] = json!(true);
    } else {
        metadata["request_uri_parameter_supported"] = json!(false);
    }
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

#[cfg(test)]
fn protected_resource_metadata(settings: &Settings) -> Value {
    let config = MetadataConfig::from(settings);
    protected_resource_metadata_with_capabilities(
        &config,
        &metadata_capabilities_from_settings(settings),
    )
}

fn protected_resource_metadata_with_capabilities(
    config: &MetadataConfig,
    capabilities: &MetadataCapabilities,
) -> Value {
    let mtls_enabled = config.mtls_enabled;
    let mut metadata = json!({
        "resource": config.protected_resource_identifier,
        "authorization_servers": [config.issuer.as_str()],
        "resource_name": "Nazo OAuth Protected Resource",
        "bearer_methods_supported": ["header", "body"],
        "scopes_supported": SCOPES_SUPPORTED,
        "dpop_signing_alg_values_supported": DPOP_SIGNING_ALGS
    });
    if mtls_enabled {
        metadata["tls_client_certificate_bound_access_tokens"] = json!(true);
    }
    if capabilities.authorization_details {
        metadata["authorization_details_types_supported"] =
            json!(["account_information", "payment_initiation"]);
    }
    metadata
}

fn token_endpoint_auth_methods_supported(
    profile: AuthorizationServerProfile,
    ciba_profile: CibaSecurityProfile,
    mtls_enabled: bool,
) -> Vec<&'static str> {
    let methods = if profile.requires_fapi2_security() || ciba_profile.requires_fapi2_hardening() {
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

fn token_endpoint_auth_signing_alg_values_supported(config: &MetadataConfig) -> Vec<&'static str> {
    if config.ciba_security_profile.requires_fapi2_hardening() {
        return FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS.to_vec();
    }
    CLIENT_JWT_SIGNING_ALGS.to_vec()
}

fn request_object_signing_alg_values_supported(
    profile: AuthorizationServerProfile,
    active_signing_algs: &[&'static str],
) -> Vec<&'static str> {
    if profile.requires_signed_authorization_request() {
        return active_signing_algs.to_vec();
    }
    if profile.requires_fapi2_security() {
        return REQUEST_OBJECT_SIGNING_ALGS.to_vec();
    }
    BASELINE_REQUEST_OBJECT_SIGNING_ALGS.to_vec()
}

fn response_modes_supported(profile: AuthorizationServerProfile) -> Vec<&'static str> {
    if profile.requires_signed_authorization_response() {
        return vec!["jwt"];
    }
    vec!["query", "jwt"]
}

fn active_signing_alg_values_supported(keyset: &KeySnapshot) -> Vec<&'static str> {
    signing_algorithm_name(keyset.active_alg)
        .map(|alg| vec![alg])
        .unwrap_or_default()
}

fn id_token_signing_alg_values_supported(keyset: &KeySnapshot) -> Vec<&'static str> {
    let mut values = active_signing_alg_values_supported(keyset);
    values.push("RS256");
    values.sort_unstable();
    values.dedup();
    values
}

pub(crate) async fn discovery(handles: Data<MetadataHandles>) -> Json<Value> {
    Json(authorization_server_metadata_value(&handles))
}

pub(crate) async fn oauth_authorization_server_metadata(
    handles: Data<MetadataHandles>,
) -> Json<Value> {
    Json(authorization_server_metadata_value(&handles))
}

pub(crate) async fn oauth_protected_resource_metadata(
    handles: Data<MetadataHandles>,
) -> Json<Value> {
    let capabilities = MetadataCapabilities::from_snapshot(&handles.runtime_modules.snapshot());
    Json(protected_resource_metadata_with_capabilities(
        &handles.config,
        &capabilities,
    ))
}

#[cfg(test)]
fn metadata_capabilities_from_settings(settings: &Settings) -> MetadataCapabilities {
    let settings = settings.modules();
    let accepting = nazo_runtime_modules::ModuleId::ALL
        .into_iter()
        .filter(|module_id| match module_id {
            nazo_runtime_modules::ModuleId::DeviceAuthorization => {
                settings.enable_device_authorization_grant
            }
            nazo_runtime_modules::ModuleId::TokenExchange
            | nazo_runtime_modules::ModuleId::JwtBearerGrant
            | nazo_runtime_modules::ModuleId::Jarm
            | nazo_runtime_modules::ModuleId::Scim => true,
            nazo_runtime_modules::ModuleId::Ciba => settings.enable_ciba,
            nazo_runtime_modules::ModuleId::DynamicClientRegistration => {
                settings.enable_dynamic_client_registration
            }
            nazo_runtime_modules::ModuleId::RequestObjects => settings.enable_request_object,
            nazo_runtime_modules::ModuleId::AuthorizationDetails => {
                settings.enable_authorization_details
            }
            nazo_runtime_modules::ModuleId::HttpMessageSignatures => {
                settings.enable_fapi_http_signatures
            }
            nazo_runtime_modules::ModuleId::NativeSso => settings.enable_native_sso,
            nazo_runtime_modules::ModuleId::FrontchannelLogout => {
                settings.enable_frontchannel_logout
            }
            nazo_runtime_modules::ModuleId::SessionManagement => settings.enable_session_management,
        })
        .collect();
    MetadataCapabilities::from_snapshot(&nazo_runtime_modules::ActiveModuleSnapshot {
        revision: nazo_runtime_modules::ModuleRevision::new(0),
        accepting,
        draining: std::collections::BTreeSet::new(),
    })
}

pub(crate) async fn jwks(handles: Data<MetadataHandles>) -> Json<Value> {
    Json(handles.keyset.snapshot().jwks())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/well_known.rs"]
mod tests;
