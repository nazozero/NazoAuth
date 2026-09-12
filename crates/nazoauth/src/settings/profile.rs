use crate::config::ConfigSource;
use anyhow::bail;
use nazo_auth::DpopNoncePolicy;
use nazo_oauth_server::policy::{
    AuthorizationServerProfile, CibaSecurityProfile, Openid4vcRevocationPolicy,
    RequestObjectJtiPolicy, SubjectType,
};

pub(super) fn authorization_server_profile_from_config(
    config: &ConfigSource,
) -> anyhow::Result<AuthorizationServerProfile> {
    match config
        .string("AUTHORIZATION_SERVER_PROFILE", "oauth2-baseline")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "oauth2-baseline" | "baseline" => Ok(AuthorizationServerProfile::Oauth2Baseline),
        "fapi2-security" => Ok(AuthorizationServerProfile::Fapi2Security),
        "fapi2-message-signing-authz-request" => {
            Ok(AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest)
        }
        "fapi2-message-signing-jarm" => Ok(AuthorizationServerProfile::Fapi2MessageSigningJarm),
        "fapi2-message-signing-introspection" => {
            Ok(AuthorizationServerProfile::Fapi2MessageSigningIntrospection)
        }
        value => bail!("AUTHORIZATION_SERVER_PROFILE is not supported: {value}"),
    }
}

pub(super) fn ciba_security_profile_from_config(
    config: &ConfigSource,
) -> anyhow::Result<CibaSecurityProfile> {
    match config
        .string("CIBA_SECURITY_PROFILE", "fapi-ciba-id1")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "fapi-ciba-id1" => Ok(CibaSecurityProfile::FapiCibaId1),
        "fapi2-ciba" => Ok(CibaSecurityProfile::Fapi2Ciba),
        value => bail!("CIBA_SECURITY_PROFILE is not supported: {value}"),
    }
}

pub(super) fn request_object_jti_policy_from_config(
    config: &ConfigSource,
) -> anyhow::Result<RequestObjectJtiPolicy> {
    match config
        .string("REQUEST_OBJECT_JTI_POLICY", "optional")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "optional" => Ok(RequestObjectJtiPolicy::Optional),
        "required-for-signed-jar" | "required_signed_jar" | "required" => {
            Ok(RequestObjectJtiPolicy::RequiredForSignedJar)
        }
        value => bail!(
            "REQUEST_OBJECT_JTI_POLICY must be optional or required-for-signed-jar, got {value}"
        ),
    }
}

pub(super) fn subject_type_from_config(config: &ConfigSource) -> anyhow::Result<SubjectType> {
    match config
        .string("SUBJECT_TYPE", "public")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "public" => Ok(SubjectType::Public),
        "pairwise" => Ok(SubjectType::Pairwise),
        value => bail!("SUBJECT_TYPE must be public or pairwise, got {value}"),
    }
}

pub(super) fn openid4vc_revocation_policy_from_config(
    config: &ConfigSource,
) -> anyhow::Result<Openid4vcRevocationPolicy> {
    match config
        .string("OPENID4VC_REVOCATION_POLICY", "disabled")
        .as_str()
    {
        "disabled" => Ok(Openid4vcRevocationPolicy::Disabled),
        "optional" => Ok(Openid4vcRevocationPolicy::Optional),
        "required" => Ok(Openid4vcRevocationPolicy::Required),
        value => bail!(
            "OPENID4VC_REVOCATION_POLICY must be disabled, optional, or required; got {value}"
        ),
    }
}

pub(super) fn dpop_nonce_policy_from_config(
    config: &ConfigSource,
) -> anyhow::Result<DpopNoncePolicy> {
    dpop_nonce_policy_from_config_key(config, "DPOP_NONCE_POLICY", "required")
}

pub(super) fn fapi_resource_dpop_nonce_policy_from_config(
    config: &ConfigSource,
) -> anyhow::Result<DpopNoncePolicy> {
    // RFC 9449 resource-server nonces are optional. The official FAPI2 DPoP
    // resource tests do not retry an initial protected-resource nonce
    // challenge, so the resource endpoint keeps nonce challenges optional by
    // default while DPoP jti replay protection remains mandatory.
    dpop_nonce_policy_from_config_key(config, "FAPI_RESOURCE_DPOP_NONCE_POLICY", "optional")
}

fn dpop_nonce_policy_from_config_key(
    config: &ConfigSource,
    key: &str,
    default: &str,
) -> anyhow::Result<DpopNoncePolicy> {
    match config
        .string(key, default)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "required" | "require" | "strict" => Ok(DpopNoncePolicy::Required),
        "optional" => Ok(DpopNoncePolicy::Optional),
        value => bail!("{key} must be required or optional, got {value}"),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/settings_profile.rs"]
mod tests;
