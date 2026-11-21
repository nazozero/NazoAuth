use nazo_runtime_modules::ModuleId;

use crate::GrantType;

/// The protocol and identity surface available to a deployment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeploymentProfile {
    #[default]
    Full,
    PasskeyOnly,
    MachineToMachine,
}

impl DeploymentProfile {
    #[must_use]
    pub const fn user_authorization(self) -> bool {
        !matches!(self, Self::MachineToMachine)
    }

    #[must_use]
    pub const fn allows_module(self, module: ModuleId) -> bool {
        match self {
            Self::Full => true,
            Self::PasskeyOnly => match module {
                ModuleId::RequestObjects
                | ModuleId::DeviceAuthorization
                | ModuleId::DynamicClientRegistration
                | ModuleId::Jarm
                | ModuleId::SessionManagement
                | ModuleId::TokenExchange
                | ModuleId::JwtBearerGrant
                | ModuleId::NativeSso
                | ModuleId::AuthorizationDetails
                | ModuleId::FrontchannelLogout
                | ModuleId::HttpMessageSignatures => true,
                ModuleId::Ciba
                | ModuleId::Scim
                | ModuleId::ScimSecurityEvents
                | ModuleId::Openid4vciIssuer
                | ModuleId::Openid4vpVerifier => false,
            },
            Self::MachineToMachine => matches!(
                module,
                ModuleId::TokenExchange
                    | ModuleId::JwtBearerGrant
                    | ModuleId::HttpMessageSignatures
                    | ModuleId::DynamicClientRegistration
            ),
        }
    }

    #[must_use]
    pub const fn allows_grant(self, grant: GrantType) -> bool {
        if let Some(module) = grant.required_module() {
            return self.allows_module(module);
        }
        match grant {
            GrantType::AuthorizationCode | GrantType::RefreshToken => self.user_authorization(),
            _ => true,
        }
    }

    /// Grants exposed by both the deployment and its currently available modules.
    #[must_use]
    pub fn grant_types(self, module_enabled: impl Fn(ModuleId) -> bool) -> Vec<&'static str> {
        [
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::JwtBearer,
            GrantType::TokenExchange,
            GrantType::DeviceCode,
            GrantType::Ciba,
        ]
        .into_iter()
        .filter(|grant| {
            self.allows_grant(*grant) && grant.required_module().is_none_or(&module_enabled)
        })
        .map(GrantType::as_str)
        .collect()
    }
}
