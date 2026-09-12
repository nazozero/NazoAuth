#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationServerProfile {
    Oauth2Baseline,
    Fapi2Security,
    Fapi2MessageSigningAuthzRequest,
    Fapi2MessageSigningJarm,
    Fapi2MessageSigningIntrospection,
}

impl AuthorizationServerProfile {
    pub fn requires_fapi2_security(self) -> bool {
        matches!(
            self,
            Self::Fapi2Security
                | Self::Fapi2MessageSigningAuthzRequest
                | Self::Fapi2MessageSigningJarm
                | Self::Fapi2MessageSigningIntrospection
        )
    }

    pub fn requires_signed_authorization_request(self) -> bool {
        self == Self::Fapi2MessageSigningAuthzRequest
    }

    pub fn requires_signed_authorization_response(self) -> bool {
        self == Self::Fapi2MessageSigningJarm
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CibaSecurityProfile {
    FapiCibaId1,
    Fapi2Ciba,
}

impl CibaSecurityProfile {
    pub fn requires_fapi2_hardening(self) -> bool {
        self == Self::Fapi2Ciba
    }

    pub const fn requires_fapi_ciba(self) -> bool {
        matches!(self, Self::FapiCibaId1 | Self::Fapi2Ciba)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestObjectJtiPolicy {
    Optional,
    RequiredForSignedJar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SubjectType {
    Public,
    Pairwise,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Openid4vcRevocationPolicy {
    Disabled,
    Optional,
    Required,
}
