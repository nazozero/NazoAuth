use std::path::Path;

use super::{EmailSettings, Settings};
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
pub(crate) struct ProtocolRuntimeSettings {
    pub(crate) access_token_ttl_seconds: i64,
    pub(crate) id_token_ttl_seconds: i64,
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
    pub(crate) email: &'a EmailSettings,
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

    pub(crate) fn protocol(&self) -> ProtocolRuntimeSettings {
        ProtocolRuntimeSettings {
            access_token_ttl_seconds: self.access_token_ttl_seconds,
            id_token_ttl_seconds: self.id_token_ttl_seconds,
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
        IdentityRuntimeSettings { email: &self.email }
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
