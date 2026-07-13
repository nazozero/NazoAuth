use std::path::Path;

use super::{
    AuthorizationServerProfile, CibaSecurityProfile, DpopNoncePolicy, EmailSettings,
    FederationSettings, PasskeySettings, RateLimitSettings, RequestObjectJtiPolicy, Settings,
    SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr};

#[derive(Clone, Copy)]
pub(crate) struct EndpointRuntimeSettings<'a> {
    pub(crate) cors_allowed_origins: &'a [String],
    pub(crate) trusted_proxy_cidrs: &'a [IpCidr],
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
}

#[derive(Clone, Copy)]
pub(crate) struct SessionRuntimeSettings {
    pub(crate) session_ttl_seconds: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct ProtocolRuntimeSettings<'a> {
    pub(crate) default_audience: &'a str,
    pub(crate) protected_resource_identifier: &'a str,
    pub(crate) authorization_server_profile: AuthorizationServerProfile,
    pub(crate) ciba_security_profile: CibaSecurityProfile,
    pub(crate) dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) request_object_jti_policy: RequestObjectJtiPolicy,
    pub(crate) auth_code_ttl_seconds: u64,
    pub(crate) access_token_ttl_seconds: i64,
    pub(crate) id_token_ttl_seconds: i64,
    pub(crate) refresh_token_ttl_seconds: i64,
    pub(crate) client_secret_pepper: &'a str,
    pub(crate) subject_type: SubjectType,
    pub(crate) pairwise_subject_secret: Option<&'a str>,
    pub(crate) par_ttl_seconds: u64,
    pub(crate) require_pushed_authorization_requests: bool,
    pub(crate) fapi_http_signature_max_age_seconds: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct StorageRuntimeSettings<'a> {
    pub(crate) avatar_max_bytes: usize,
    pub(crate) avatar_storage_dir: &'a Path,
    pub(crate) client_delivery_ttl_seconds: u64,
    pub(crate) scim_bearer_token: Option<&'a str>,
}

#[derive(Clone, Copy)]
pub(crate) struct IdentityRuntimeSettings<'a> {
    pub(crate) rate_limit: &'a RateLimitSettings,
    pub(crate) email: &'a EmailSettings,
    pub(crate) email_code_dev_response_enabled: bool,
    pub(crate) passkey: &'a PasskeySettings,
    pub(crate) federation: &'a FederationSettings,
}

impl Settings {
    pub(crate) fn endpoint(&self) -> EndpointRuntimeSettings<'_> {
        EndpointRuntimeSettings {
            cors_allowed_origins: &self.cors_allowed_origins,
            trusted_proxy_cidrs: &self.trusted_proxy_cidrs,
            client_ip_header_mode: self.client_ip_header_mode,
        }
    }

    pub(crate) fn session(&self) -> SessionRuntimeSettings {
        SessionRuntimeSettings {
            session_ttl_seconds: self.session_ttl_seconds,
        }
    }

    pub(crate) fn protocol(&self) -> ProtocolRuntimeSettings<'_> {
        ProtocolRuntimeSettings {
            default_audience: &self.default_audience,
            protected_resource_identifier: &self.protected_resource_identifier,
            authorization_server_profile: self.authorization_server_profile,
            ciba_security_profile: self.ciba_security_profile,
            dpop_nonce_policy: self.dpop_nonce_policy,
            request_object_jti_policy: self.request_object_jti_policy,
            auth_code_ttl_seconds: self.auth_code_ttl_seconds,
            access_token_ttl_seconds: self.access_token_ttl_seconds,
            id_token_ttl_seconds: self.id_token_ttl_seconds,
            refresh_token_ttl_seconds: self.refresh_token_ttl_seconds,
            client_secret_pepper: &self.client_secret_pepper,
            subject_type: self.subject_type,
            pairwise_subject_secret: self.pairwise_subject_secret.as_deref(),
            par_ttl_seconds: self.par_ttl_seconds,
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
            fapi_http_signature_max_age_seconds: self.fapi_http_signature_max_age_seconds,
        }
    }

    pub(crate) fn storage(&self) -> StorageRuntimeSettings<'_> {
        StorageRuntimeSettings {
            avatar_max_bytes: self.avatar_max_bytes,
            avatar_storage_dir: &self.avatar_storage_dir,
            client_delivery_ttl_seconds: self.client_delivery_ttl_seconds,
            scim_bearer_token: self.scim_bearer_token.as_deref(),
        }
    }

    pub(crate) fn identity(&self) -> IdentityRuntimeSettings<'_> {
        IdentityRuntimeSettings {
            rate_limit: &self.rate_limit,
            email: &self.email,
            email_code_dev_response_enabled: self.email_code_dev_response_enabled,
            passkey: &self.passkey,
            federation: &self.federation,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::ConfigSource, settings::Settings};

    #[test]
    fn focused_views_preserve_the_validated_startup_snapshot() {
        let settings = Settings::from_config(&ConfigSource::from_pairs_for_test([])).unwrap();
        assert_eq!(
            settings.endpoint().cors_allowed_origins,
            settings.cors_allowed_origins
        );
        assert_eq!(
            settings.session().session_ttl_seconds,
            settings.session_ttl_seconds
        );
        assert_eq!(
            settings.protocol().access_token_ttl_seconds,
            settings.access_token_ttl_seconds
        );
        assert_eq!(
            settings.storage().avatar_storage_dir,
            settings.avatar_storage_dir
        );
        assert_eq!(
            settings.identity().email.code_ttl_seconds,
            settings.email.code_ttl_seconds
        );
    }
}
