use serde::{Serialize, Serializer, ser::SerializeMap};

use super::{CapabilityAdmission, MetadataCapabilities, module_admissible};
use crate::{
    SUPPORTED_AUTHORIZATION_DETAILS_TYPES, SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
    SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS, SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
};
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId};

const DPOP_SIGNING_ALGS: [&str; 2] = ["EdDSA", "ES256"];
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
const CLIENT_AUTH_METHODS: [&str; 7] = [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "none",
    "attest_jwt_client_auth",
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
const BASELINE_ACR_VALUE: &str = "1";

/// Authorization-server profile choices that affect standard metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataAuthorizationServerProfile {
    Composable,
    Oauth2Baseline,
    Fapi2Security,
    Fapi2MessageSigningAuthorizationRequest,
    Fapi2MessageSigningJarm,
    Fapi2MessageSigningIntrospection,
}

impl MetadataAuthorizationServerProfile {
    const fn requires_fapi2_security(self) -> bool {
        !matches!(self, Self::Composable | Self::Oauth2Baseline)
    }

    const fn requires_signed_authorization_request(self) -> bool {
        matches!(self, Self::Fapi2MessageSigningAuthorizationRequest)
    }

    const fn requires_signed_authorization_response(self) -> bool {
        matches!(self, Self::Fapi2MessageSigningJarm)
    }
}

/// CIBA policy choices that affect client-authentication metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaMetadataProfile {
    FapiCiba,
    Fapi2Ciba,
}

/// Signing algorithms made available by the current key snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataSigningAlgorithms<'a> {
    /// Algorithms backed by the active signing key.
    pub active: &'a [&'a str],
    /// Algorithms backed by keys eligible to sign ID Tokens.
    pub id_token: &'a [&'a str],
    /// Algorithms backed by all keys eligible for protocol responses.
    pub response: &'a [&'a str],
}

/// Framework- and infrastructure-free input for OAuth AS and OIDC discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationServerMetadataInput<'a> {
    pub issuer: &'a str,
    pub mtls_endpoint_base_url: &'a str,
    pub mtls_enabled: bool,
    pub backchannel_logout_supported: bool,
    pub profile: MetadataAuthorizationServerProfile,
    pub ciba_profile: CibaMetadataProfile,
    pub pairwise_subject_enabled: bool,
    pub protected_resource_identifier: &'a str,
    pub additional_scopes_supported: &'a [String],
    pub credential_scopes: &'a [String],
    pub require_pushed_authorization_requests: bool,
    pub signing_algorithms: MetadataSigningAlgorithms<'a>,
}

/// Framework- and infrastructure-free input for RFC 9728 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedResourceMetadataInput<'a> {
    pub issuer: &'a str,
    pub protected_resource_identifier: &'a str,
    pub mtls_enabled: bool,
}

/// Borrows one immutable OAuth AS/OIDC metadata snapshot for direct serialization.
#[must_use]
pub fn authorization_server_metadata<'a>(
    input: AuthorizationServerMetadataInput<'a>,
    snapshot: &'a ActiveModuleSnapshot,
) -> impl Serialize + 'a {
    AuthorizationServerMetadata { input, snapshot }
}

struct AuthorizationServerMetadata<'a> {
    input: AuthorizationServerMetadataInput<'a>,
    snapshot: &'a ActiveModuleSnapshot,
}

impl Serialize for AuthorizationServerMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let input = self.input;
        let capabilities = MetadataCapabilities::from_snapshot(self.snapshot);
        let issuer = input.issuer;
        let response_signing_algs: Vec<_> = input
            .signing_algorithms
            .response
            .iter()
            .copied()
            .filter(|algorithm| {
                !input.profile.requires_fapi2_security()
                    || crate::FAPI2_JWT_SIGNING_ALGS.contains(algorithm)
            })
            .collect();
        let active_signing_algs = input.signing_algorithms.active;
        let mut id_token_signing_algs =
            id_token_signing_alg_values_supported(input.signing_algorithms.id_token);
        if input.profile.requires_fapi2_security() {
            id_token_signing_algs
                .retain(|algorithm| crate::FAPI2_JWT_SIGNING_ALGS.contains(algorithm));
        }
        let token_auth_methods = token_endpoint_auth_methods_supported(
            input.profile,
            input.mtls_enabled,
            capabilities.openid4vci_issuer,
        );
        let revocation_auth_methods: Vec<_> = token_auth_methods
            .iter()
            .copied()
            .filter(|method| *method != "attest_jwt_client_auth")
            .collect();
        let introspection_auth_methods: Vec<_> = revocation_auth_methods
            .iter()
            .copied()
            .filter(|method| *method != "none")
            .collect();
        let token_auth_signing_algs =
            token_endpoint_auth_signing_alg_values_supported(input.profile);
        let request_object_signing_algs =
            request_object_signing_alg_values_supported(input.profile, active_signing_algs);
        let mut response_modes = response_modes_supported(input.profile);
        if !capabilities.jarm {
            response_modes.retain(|mode| *mode != "jwt");
        }
        let mut scopes_supported = SCOPES_SUPPORTED.to_vec();
        if capabilities.native_sso {
            scopes_supported.push("device_sso");
        }
        for scope in input.additional_scopes_supported.iter().chain(
            input
                .credential_scopes
                .iter()
                .filter(|_| capabilities.openid4vci_issuer),
        ) {
            if !scopes_supported.contains(&scope.as_str()) {
                scopes_supported.push(scope.as_str());
            }
        }
        // Preserve the previous JSON object's lexical field order without building
        // an owned Value tree. Static strings and snapshot lists serialize by reference.
        let mut metadata = serializer.serialize_map(None)?;
        metadata.serialize_entry("acr_values_supported", &[BASELINE_ACR_VALUE])?;
        if capabilities.authorization_details {
            metadata.serialize_entry(
                "authorization_details_types_supported",
                &SUPPORTED_AUTHORIZATION_DETAILS_TYPES
                    .iter()
                    .copied()
                    .filter(|type_| capabilities.openid4vci_issuer || *type_ != "openid_credential")
                    .collect::<Vec<_>>(),
            )?;
        }
        metadata.serialize_entry(
            "authorization_encryption_alg_values_supported",
            SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        )?;
        metadata.serialize_entry(
            "authorization_encryption_enc_values_supported",
            SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
        )?;
        metadata.serialize_entry("authorization_endpoint", &format!("{issuer}/authorize"))?;
        metadata.serialize_entry("authorization_response_iss_parameter_supported", &true)?;
        metadata.serialize_entry(
            "authorization_signing_alg_values_supported",
            &response_signing_algs,
        )?;
        if capabilities.ciba {
            metadata.serialize_entry(
                "backchannel_authentication_endpoint",
                &format!("{issuer}/bc-authorize"),
            )?;
            metadata.serialize_entry(
                "backchannel_authentication_request_signing_alg_values_supported",
                crate::CIBA_JWT_SIGNING_ALGS,
            )?;
        }
        metadata.serialize_entry(
            "backchannel_logout_session_supported",
            &input.backchannel_logout_supported,
        )?;
        metadata.serialize_entry(
            "backchannel_logout_supported",
            &input.backchannel_logout_supported,
        )?;
        if capabilities.ciba {
            metadata.serialize_entry(
                "backchannel_token_delivery_modes_supported",
                &["poll", "ping"],
            )?;
            metadata.serialize_entry("backchannel_user_code_parameter_supported", &false)?;
        }
        if capabilities.session_management {
            metadata.serialize_entry("check_session_iframe", &format!("{issuer}/check_session"))?;
        }
        metadata.serialize_entry("claims_parameter_supported", &true)?;
        metadata.serialize_entry("claims_supported", &CLAIMS_SUPPORTED)?;
        if capabilities.openid4vci_issuer {
            metadata.serialize_entry(
                "client_attestation_pop_signing_alg_values_supported",
                &["ES256"],
            )?;
            metadata.serialize_entry(
                "client_attestation_signing_alg_values_supported",
                &["ES256"],
            )?;
        }
        metadata.serialize_entry("code_challenge_methods_supported", &["S256"])?;
        if capabilities.device_authorization {
            metadata.serialize_entry(
                "device_authorization_endpoint",
                &format!("{issuer}/device_authorization"),
            )?;
        }
        metadata.serialize_entry("dpop_signing_alg_values_supported", &DPOP_SIGNING_ALGS)?;
        metadata.serialize_entry("end_session_endpoint", &format!("{issuer}/logout"))?;
        if capabilities.frontchannel_logout {
            metadata.serialize_entry("frontchannel_logout_session_supported", &true)?;
            metadata.serialize_entry("frontchannel_logout_supported", &true)?;
        }
        metadata.serialize_entry("grant_types_supported", &capabilities.grant_types)?;
        metadata.serialize_entry(
            "id_token_encryption_alg_values_supported",
            SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        )?;
        metadata.serialize_entry(
            "id_token_encryption_enc_values_supported",
            SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
        )?;
        metadata.serialize_entry(
            "id_token_signing_alg_values_supported",
            &id_token_signing_algs,
        )?;
        metadata.serialize_entry(
            "introspection_encryption_alg_values_supported",
            SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        )?;
        metadata.serialize_entry(
            "introspection_encryption_enc_values_supported",
            SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
        )?;
        metadata.serialize_entry("introspection_endpoint", &format!("{issuer}/introspect"))?;
        metadata.serialize_entry(
            "introspection_endpoint_auth_methods_supported",
            &introspection_auth_methods,
        )?;
        metadata.serialize_entry(
            "introspection_endpoint_auth_signing_alg_values_supported",
            token_auth_signing_algs,
        )?;
        metadata.serialize_entry(
            "introspection_signing_alg_values_supported",
            active_signing_algs,
        )?;
        metadata.serialize_entry("issuer", issuer)?;
        metadata.serialize_entry("jwks_uri", &format!("{issuer}/jwks.json"))?;
        if input.mtls_enabled {
            metadata.serialize_entry(
                "mtls_endpoint_aliases",
                &MtlsEndpointAliases {
                    base: input.mtls_endpoint_base_url,
                    ciba: capabilities.ciba,
                },
            )?;
        }
        metadata.serialize_entry("prompt_values_supported", &PROMPT_VALUES_SUPPORTED)?;
        metadata.serialize_entry(
            "protected_resources",
            &[input.protected_resource_identifier],
        )?;
        metadata.serialize_entry(
            "pushed_authorization_request_endpoint",
            &format!("{issuer}/par"),
        )?;
        if capabilities.dynamic_client_registration {
            metadata.serialize_entry("registration_endpoint", &format!("{issuer}/register"))?;
        }
        if capabilities.request_objects {
            metadata.serialize_entry(
                "request_object_encryption_alg_values_supported",
                &["RSA-OAEP-256"],
            )?;
            metadata.serialize_entry(
                "request_object_encryption_enc_values_supported",
                &["A256GCM"],
            )?;
            metadata.serialize_entry(
                "request_object_signing_alg_values_supported",
                request_object_signing_algs,
            )?;
            metadata.serialize_entry("request_parameter_supported", &true)?;
        }
        // External request_uri is available only with the dynamically registered,
        // signed-Request-Object baseline. FAPI continues to require AS-issued PAR handles.
        metadata.serialize_entry(
            "request_uri_parameter_supported",
            &(capabilities.dynamic_client_registration
                && capabilities.request_objects
                && !input.profile.requires_fapi2_security()),
        )?;
        metadata.serialize_entry(
            "require_pushed_authorization_requests",
            &input.require_pushed_authorization_requests,
        )?;
        metadata.serialize_entry("response_modes_supported", &response_modes)?;
        metadata.serialize_entry("response_types_supported", &["code"])?;
        metadata.serialize_entry("revocation_endpoint", &format!("{issuer}/revoke"))?;
        metadata.serialize_entry(
            "revocation_endpoint_auth_methods_supported",
            &revocation_auth_methods,
        )?;
        metadata.serialize_entry(
            "revocation_endpoint_auth_signing_alg_values_supported",
            token_auth_signing_algs,
        )?;
        metadata.serialize_entry("scopes_supported", &scopes_supported)?;
        metadata.serialize_entry("subject_types_supported", subject_types_supported(input))?;
        if input.mtls_enabled {
            metadata.serialize_entry("tls_client_certificate_bound_access_tokens", &true)?;
        }
        metadata.serialize_entry("token_endpoint", &format!("{issuer}/token"))?;
        metadata.serialize_entry("token_endpoint_auth_methods_supported", &token_auth_methods)?;
        metadata.serialize_entry(
            "token_endpoint_auth_signing_alg_values_supported",
            token_auth_signing_algs,
        )?;
        metadata.serialize_entry(
            "userinfo_encryption_alg_values_supported",
            SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        )?;
        metadata.serialize_entry(
            "userinfo_encryption_enc_values_supported",
            SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
        )?;
        metadata.serialize_entry("userinfo_endpoint", &format!("{issuer}/userinfo"))?;
        metadata.serialize_entry(
            "userinfo_signing_alg_values_supported",
            &response_signing_algs,
        )?;
        metadata.end()
    }
}

struct MtlsEndpointAliases<'a> {
    base: &'a str,
    ciba: bool,
}

impl Serialize for MtlsEndpointAliases<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let base = self.base;
        let mut aliases = serializer.serialize_map(Some(if self.ciba { 6 } else { 5 }))?;
        if self.ciba {
            aliases.serialize_entry(
                "backchannel_authentication_endpoint",
                &format!("{base}/bc-authorize"),
            )?;
        }
        aliases.serialize_entry("introspection_endpoint", &format!("{base}/introspect"))?;
        aliases.serialize_entry(
            "pushed_authorization_request_endpoint",
            &format!("{base}/par"),
        )?;
        aliases.serialize_entry("revocation_endpoint", &format!("{base}/revoke"))?;
        aliases.serialize_entry("token_endpoint", &format!("{base}/token"))?;
        aliases.serialize_entry("userinfo_endpoint", &format!("{base}/userinfo"))?;
        aliases.end()
    }
}

/// Borrows the same capability snapshot for RFC 9728 metadata serialization.
#[must_use]
pub fn protected_resource_metadata<'a>(
    input: ProtectedResourceMetadataInput<'a>,
    snapshot: &'a ActiveModuleSnapshot,
) -> impl Serialize + 'a {
    ProtectedResourceMetadata { input, snapshot }
}

struct ProtectedResourceMetadata<'a> {
    input: ProtectedResourceMetadataInput<'a>,
    snapshot: &'a ActiveModuleSnapshot,
}

impl Serialize for ProtectedResourceMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let input = self.input;
        let mut metadata = serializer.serialize_map(None)?;
        if module_admissible(
            self.snapshot,
            ModuleId::AuthorizationDetails,
            CapabilityAdmission::NewRequest,
        ) {
            metadata.serialize_entry(
                "authorization_details_types_supported",
                &SUPPORTED_AUTHORIZATION_DETAILS_TYPES
                    .iter()
                    .copied()
                    .filter(|type_| *type_ != "openid_credential")
                    .collect::<Vec<_>>(),
            )?;
        }
        metadata.serialize_entry("authorization_servers", &[input.issuer])?;
        // This document describes the configured protected resource (the
        // FAPI resource by default), whose transport rejects form-body bearer
        // tokens. Baseline UserInfo compatibility is a different resource.
        metadata.serialize_entry("bearer_methods_supported", &["header"])?;
        metadata.serialize_entry("dpop_signing_alg_values_supported", &DPOP_SIGNING_ALGS)?;
        metadata.serialize_entry("resource", input.protected_resource_identifier)?;
        metadata.serialize_entry("resource_name", "Nazo OAuth Protected Resource")?;
        metadata.serialize_entry("scopes_supported", &SCOPES_SUPPORTED)?;
        if input.mtls_enabled {
            metadata.serialize_entry("tls_client_certificate_bound_access_tokens", &true)?;
        }
        metadata.end()
    }
}

fn subject_types_supported(input: AuthorizationServerMetadataInput<'_>) -> &'static [&'static str] {
    if input.pairwise_subject_enabled {
        &["public", "pairwise"]
    } else {
        &["public"]
    }
}

fn token_endpoint_auth_methods_supported(
    profile: MetadataAuthorizationServerProfile,
    mtls_enabled: bool,
    client_attestation_enabled: bool,
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
            (mtls_enabled || !matches!(*method, "tls_client_auth" | "self_signed_tls_client_auth"))
                && (client_attestation_enabled || *method != "attest_jwt_client_auth")
        })
        .collect()
}

fn token_endpoint_auth_signing_alg_values_supported(
    profile: MetadataAuthorizationServerProfile,
) -> &'static [&'static str] {
    if profile.requires_fapi2_security() {
        return crate::FAPI2_JWT_SIGNING_ALGS;
    }
    SUPPORTED_CLIENT_JWT_SIGNING_ALGS
}

fn request_object_signing_alg_values_supported<'a>(
    profile: MetadataAuthorizationServerProfile,
    active_signing_algs: &'a [&'a str],
) -> &'a [&'a str] {
    if profile.requires_fapi2_security() {
        return crate::FAPI2_JWT_SIGNING_ALGS;
    }
    if profile.requires_signed_authorization_request() {
        return active_signing_algs;
    }
    SUPPORTED_CLIENT_JWT_SIGNING_ALGS
}

fn response_modes_supported(profile: MetadataAuthorizationServerProfile) -> Vec<&'static str> {
    if profile.requires_signed_authorization_response() {
        return vec!["jwt"];
    }
    if profile.requires_fapi2_security() {
        return vec!["query", "jwt"];
    }
    vec!["query", "form_post", "jwt"]
}

fn id_token_signing_alg_values_supported<'a>(active: &'a [&'a str]) -> Vec<&'a str> {
    let mut values = active.to_vec();
    values.push("RS256");
    values.sort_unstable();
    values.dedup();
    values
}

#[cfg(test)]
#[path = "../../tests/unit/metadata/document.rs"]
mod tests;
