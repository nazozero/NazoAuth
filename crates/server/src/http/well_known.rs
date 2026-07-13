use actix_web::web::Json;
use serde_json::{Value, json};

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

#[cfg(test)]
use crate::domain::{KeySnapshot, MetadataConfig};
#[cfg(test)]
use crate::http::token::ciba::CIBA_GRANT_TYPE;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use nazo_auth::{
    AuthorizationServerMetadataInput, MetadataCapabilities, MetadataSigningAlgorithms,
    ProtectedResourceMetadataInput,
};
#[cfg(test)]
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision};

#[cfg(test)]
const PROMPT_VALUES_SUPPORTED: [&str; 4] = ["login", "consent", "select_account", "none"];
#[cfg(test)]
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

#[cfg(test)]
fn authorization_server_metadata(settings: &Settings, keyset: &KeySnapshot) -> Value {
    let config = MetadataConfig::from(settings);
    let capabilities = metadata_capabilities_from_settings(settings);
    authorization_server_metadata_with_capabilities(&config, keyset, &capabilities)
}

#[cfg(test)]
fn protected_resource_metadata(settings: &Settings) -> Value {
    let config = MetadataConfig::from(settings);
    let capabilities = metadata_capabilities_from_settings(settings);
    protected_resource_metadata_with_capabilities(&config, &capabilities)
}

#[cfg(test)]
fn authorization_server_metadata_with_capabilities(
    config: &MetadataConfig,
    keyset: &KeySnapshot,
    capabilities: &MetadataCapabilities,
) -> Value {
    let active = active_signing_alg_values_supported(keyset);
    let response = keyset.response_signing_alg_values_supported();
    nazo_auth::authorization_server_metadata(
        AuthorizationServerMetadataInput {
            issuer: &config.issuer,
            mtls_endpoint_base_url: &config.mtls_endpoint_base_url,
            mtls_enabled: config.mtls_enabled,
            profile: config.authorization_server_profile,
            ciba_profile: config.ciba_security_profile,
            subject_type: config.subject_type,
            pairwise_subject_enabled: config.pairwise_subject_enabled,
            protected_resource_identifier: &config.protected_resource_identifier,
            require_pushed_authorization_requests: config.require_pushed_authorization_requests,
            request_uri_parameter_enabled: config.request_uri_parameter_enabled,
            signing_algorithms: MetadataSigningAlgorithms {
                active: &active,
                response: &response,
            },
        },
        &snapshot_from_capabilities(capabilities),
    )
}

#[cfg(test)]
fn protected_resource_metadata_with_capabilities(
    config: &MetadataConfig,
    capabilities: &MetadataCapabilities,
) -> Value {
    nazo_auth::protected_resource_metadata(
        ProtectedResourceMetadataInput {
            issuer: &config.issuer,
            protected_resource_identifier: &config.protected_resource_identifier,
            mtls_enabled: config.mtls_enabled,
        },
        &snapshot_from_capabilities(capabilities),
    )
}

#[cfg(test)]
fn snapshot_from_capabilities(capabilities: &MetadataCapabilities) -> ActiveModuleSnapshot {
    let mut accepting = std::collections::BTreeSet::new();
    let mut enable = |module_id, enabled| {
        if enabled {
            accepting.insert(module_id);
        }
    };
    enable(
        ModuleId::JwtBearerGrant,
        capabilities
            .grant_types
            .contains(&nazo_auth::GrantType::JwtBearer.as_str()),
    );
    enable(
        ModuleId::TokenExchange,
        capabilities
            .grant_types
            .contains(&nazo_auth::GrantType::TokenExchange.as_str()),
    );
    enable(
        ModuleId::DeviceAuthorization,
        capabilities.device_authorization,
    );
    enable(ModuleId::Ciba, capabilities.ciba);
    enable(
        ModuleId::DynamicClientRegistration,
        capabilities.dynamic_client_registration,
    );
    enable(ModuleId::RequestObjects, capabilities.request_objects);
    enable(ModuleId::Jarm, capabilities.jarm);
    enable(
        ModuleId::AuthorizationDetails,
        capabilities.authorization_details,
    );
    enable(
        ModuleId::HttpMessageSignatures,
        capabilities.http_message_signatures,
    );
    enable(ModuleId::Scim, capabilities.scim);
    enable(ModuleId::NativeSso, capabilities.native_sso);
    enable(
        ModuleId::FrontchannelLogout,
        capabilities.frontchannel_logout,
    );
    enable(ModuleId::SessionManagement, capabilities.session_management);
    ActiveModuleSnapshot {
        revision: ModuleRevision::new(0),
        accepting,
        draining: std::collections::BTreeSet::new(),
    }
}

#[cfg(test)]
fn metadata_capabilities_from_settings(settings: &Settings) -> MetadataCapabilities {
    let settings = &settings.modules;
    let accepting = ModuleId::ALL
        .into_iter()
        .filter(|module_id| match module_id {
            ModuleId::DeviceAuthorization => settings.enable_device_authorization_grant,
            ModuleId::TokenExchange
            | ModuleId::JwtBearerGrant
            | ModuleId::Jarm
            | ModuleId::Scim => true,
            ModuleId::Ciba => settings.enable_ciba,
            ModuleId::DynamicClientRegistration => settings.enable_dynamic_client_registration,
            ModuleId::RequestObjects => settings.enable_request_object,
            ModuleId::AuthorizationDetails => settings.enable_authorization_details,
            ModuleId::HttpMessageSignatures => settings.enable_fapi_http_signatures,
            ModuleId::NativeSso => settings.enable_native_sso,
            ModuleId::FrontchannelLogout => settings.enable_frontchannel_logout,
            ModuleId::SessionManagement => settings.enable_session_management,
        })
        .collect();
    MetadataCapabilities::from_snapshot(&ActiveModuleSnapshot {
        revision: ModuleRevision::new(0),
        accepting,
        draining: std::collections::BTreeSet::new(),
    })
}

#[cfg(test)]
fn active_signing_alg_values_supported(keyset: &KeySnapshot) -> Vec<&'static str> {
    nazo_key_management::signing_algorithm_name(keyset.active_alg)
        .into_iter()
        .collect()
}

#[cfg(test)]
fn id_token_signing_alg_values_supported(keyset: &KeySnapshot) -> Vec<&'static str> {
    let mut values = active_signing_alg_values_supported(keyset);
    values.push("RS256");
    values.sort_unstable();
    values.dedup();
    values
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/well_known.rs"]
mod tests;
