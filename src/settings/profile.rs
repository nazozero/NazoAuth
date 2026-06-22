use anyhow::bail;

use crate::config::ConfigSource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationServerProfile {
    Oauth2Baseline,
    Fapi2Security,
    Fapi2MessageSigningAuthzRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DpopNoncePolicy {
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestObjectJtiPolicy {
    Optional,
    RequiredForSignedJar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubjectType {
    Public,
    Pairwise,
}

impl AuthorizationServerProfile {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("AUTHORIZATION_SERVER_PROFILE", "oauth2-baseline")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "oauth2-baseline" | "baseline" => Ok(Self::Oauth2Baseline),
            "fapi2-security" => Ok(Self::Fapi2Security),
            "fapi2-message-signing-authz-request" => Ok(Self::Fapi2MessageSigningAuthzRequest),
            value => bail!("AUTHORIZATION_SERVER_PROFILE is not supported: {value}"),
        }
    }

    pub(crate) fn requires_fapi2_security(self) -> bool {
        matches!(
            self,
            Self::Fapi2Security | Self::Fapi2MessageSigningAuthzRequest
        )
    }

    pub(crate) fn requires_signed_authorization_request(self) -> bool {
        self == Self::Fapi2MessageSigningAuthzRequest
    }

    pub(crate) fn requires_signed_request_object_at_par(self) -> bool {
        self == Self::Fapi2MessageSigningAuthzRequest
    }
}

impl DpopNoncePolicy {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("DPOP_NONCE_POLICY", "required")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "required" | "require" | "strict" => Ok(Self::Required),
            "optional" => Ok(Self::Optional),
            value => bail!("DPOP_NONCE_POLICY must be required or optional, got {value}"),
        }
    }
}

impl RequestObjectJtiPolicy {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("REQUEST_OBJECT_JTI_POLICY", "optional")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "optional" => Ok(Self::Optional),
            "required-for-signed-jar" | "required_signed_jar" | "required" => {
                Ok(Self::RequiredForSignedJar)
            }
            value => bail!(
                "REQUEST_OBJECT_JTI_POLICY must be optional or required-for-signed-jar, got {value}"
            ),
        }
    }
}

impl SubjectType {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("SUBJECT_TYPE", "public")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "public" => Ok(Self::Public),
            "pairwise" => Ok(Self::Pairwise),
            value => bail!("SUBJECT_TYPE must be public or pairwise, got {value}"),
        }
    }
}
