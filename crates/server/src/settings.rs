//! Runtime settings.
// Settings are built from the startup configuration snapshot.

use std::path::PathBuf;

use anyhow::bail;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::validate_issuer_url;

use crate::config::{ConfigSource, DEFAULT_DATA_DIR};
use nazoauth::config::{
    ClientIpHeaderMode, IpCidr, MtlsCertificateSourceMode, parse_trusted_proxy_cidrs,
};
pub(crate) use nazoauth::config::{
    DeviceGrantSettings, Openid4vcSettings, ProtocolSettings, SessionSettings, TenantSettings,
};

/// Access tokens are stateless JWTs. Recovery can close ingress only after
/// this bounded lifetime plus the verifier skew has elapsed.
pub(crate) use nazoauth::config::{MAX_ACCESS_TOKEN_TTL_SECONDS, MAX_ID_TOKEN_TTL_SECONDS};
pub(crate) const RECOVERY_ACCESS_TOKEN_CLOCK_SKEW_SECONDS: i64 = 60;

mod config_loader;
mod email;
mod federation;
mod passkey;
mod profile;
mod rate_limit;

pub(crate) use config_loader::{
    credential_configurations_from_config, mdoc_issuing_country_from_config,
};
pub(crate) use email::{EmailDelivery, EmailSettings, SmtpEmailSettings, SmtpTlsMode};
use nazo_oauth_server::policy::SubjectType;
use nazoauth::config::FederationSettings;
pub(crate) use passkey::PasskeySettings;
pub(crate) use rate_limit::RateLimitSettings;

/// OAuth service runtime parameters.
#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) tenant: TenantSettings,
    pub(crate) endpoint: EndpointSettings,
    pub(crate) protocol: ProtocolSettings,
    pub(crate) session: SessionSettings,
    pub(crate) storage: StorageSettings,
    pub(crate) identity: IdentityRuntimeSettings,
    pub(crate) keys: KeyManagementSettings,
    pub(crate) modules: ModuleSettings,
    pub(crate) device: DeviceGrantSettings,
    pub(crate) ciba: CibaSettings,
    pub(crate) openid4vc: Openid4vcSettings,
}

/// Canonicalizes a configured tenant host without accepting a URL, userinfo,
/// path, or port. Ports cannot distinguish tenants because TLS SNI has none.
pub(crate) use nazo_identity::canonical_tenant_host;

#[derive(Clone)]
pub(crate) struct EndpointSettings {
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) frontend_base_url: String,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) transport_mode: TransportMode,
    pub(crate) mtls_certificate_source: MtlsCertificateSourceMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportMode {
    LoopbackHttp,
    DirectTls,
    TrustedProxy,
}

impl TransportMode {
    fn from_config(
        value: Option<&str>,
        issuer: &str,
        issuer_is_loopback_http: bool,
    ) -> anyhow::Result<Self> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None if issuer_is_loopback_http => Ok(Self::LoopbackHttp),
            None => bail!(
                "TRANSPORT_MODE is required for non-loopback issuers and must be direct-tls or trusted-proxy"
            ),
            Some("loopback-http") if issuer_is_loopback_http => Ok(Self::LoopbackHttp),
            Some("loopback-http") => {
                bail!("TRANSPORT_MODE=loopback-http requires a loopback HTTP issuer")
            }
            Some("direct-tls") if issuer.starts_with("https://") => Ok(Self::DirectTls),
            Some("direct-tls") => bail!("direct-tls transport requires an HTTPS issuer"),
            Some("trusted-proxy") if issuer.starts_with("https://") || issuer_is_loopback_http => {
                Ok(Self::TrustedProxy)
            }
            Some("trusted-proxy") => {
                bail!("trusted-proxy transport requires an HTTPS or loopback HTTP issuer")
            }
            Some(value) => bail!(
                "TRANSPORT_MODE must be loopback-http, direct-tls, or trusted-proxy; got {value}"
            ),
        }
    }
}

#[derive(Clone)]
pub(crate) struct StorageSettings {
    pub(crate) avatar_max_bytes: usize,
    pub(crate) client_delivery_ttl_seconds: u64,
    pub(crate) data_dir: PathBuf,
    pub(crate) avatar_storage_dir: PathBuf,
    pub(crate) scim_event_retention_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct IdentityRuntimeSettings {
    pub(crate) rate_limit: RateLimitSettings,
    pub(crate) email: EmailSettings,
    pub(crate) email_code_dev_response_enabled: bool,
    pub(crate) passkey: PasskeySettings,
    pub(crate) federation: FederationSettings,
}

#[derive(Clone)]
pub(crate) struct KeyManagementSettings {
    pub(crate) signing_external_command: Vec<String>,
    pub(crate) signing_external_timeout_ms: u64,
    pub(crate) signing_key_rotation_interval_seconds: i64,
    pub(crate) signing_key_prepublish_seconds: i64,
}

#[derive(Clone)]
pub(crate) struct ModuleSettings {
    pub(crate) enable_openid4vci_issuer: bool,
    pub(crate) enable_openid4vp_verifier: bool,
    /// Route registration is process-wide, while module services are selected
    /// from the request tenant's runtime. These flags cover both the control
    /// tenant and directory-managed tenants without enabling either service
    /// for the control tenant.
    pub(crate) register_openid4vci_routes: bool,
    pub(crate) register_openid4vp_routes: bool,
    pub(crate) dynamic_client_registration_initial_access_token: Option<String>,
    pub(crate) remote_client_document_private_origins: Vec<String>,
    pub(crate) backchannel_logout_private_origins: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct CibaSettings {
    pub(crate) ciba_auth_req_id_ttl_seconds: u64,
    pub(crate) ciba_poll_interval_seconds: u64,
    pub(crate) ciba_notification_private_origins: Vec<String>,
}

impl Settings {
    pub(crate) fn application_configuration(&self) -> nazoauth::config::Configuration {
        use nazoauth::config as app;
        app::Configuration {
            tenant: self.tenant.clone(),
            protocol: self.protocol.clone(),
            session: self.session.clone(),
            device: self.device.clone(),
            openid4vc: self.openid4vc.clone(),
            endpoint: app::EndpointSettings {
                issuer: self.endpoint.issuer.clone(),
                mtls_endpoint_base_url: self.endpoint.mtls_endpoint_base_url.clone(),
                frontend_base_url: self.endpoint.frontend_base_url.clone(),
                cors_allowed_origins: self.endpoint.cors_allowed_origins.clone(),
                trusted_proxy_cidrs: self.endpoint.trusted_proxy_cidrs.clone(),
                client_ip_header_mode: self.endpoint.client_ip_header_mode,
                mtls_certificate_source: self.endpoint.mtls_certificate_source,
            },
            storage: app::StorageSettings {
                avatar_max_bytes: self.storage.avatar_max_bytes,
                client_delivery_ttl_seconds: self.storage.client_delivery_ttl_seconds,
                scim_event_retention_seconds: self.storage.scim_event_retention_seconds,
            },
            identity: app::IdentitySettings {
                rate_limit: self.identity.rate_limit.clone(),
                passkey: self.identity.passkey.clone(),
                federation: self.identity.federation.clone(),
                email_code_dev_response_enabled: self.identity.email_code_dev_response_enabled,
                email: app::EmailSettings {
                    delivery_enabled: !matches!(
                        self.identity.email.delivery,
                        EmailDelivery::Disabled
                    ),
                    code_ttl_seconds: self.identity.email.code_ttl_seconds,
                    send_cooldown_seconds: self.identity.email.send_cooldown_seconds,
                    send_peer_cooldown_seconds: self.identity.email.send_peer_cooldown_seconds,
                },
            },
            modules: app::ModuleSettings {
                enable_openid4vci_issuer: self.modules.enable_openid4vci_issuer,
                enable_openid4vp_verifier: self.modules.enable_openid4vp_verifier,
                register_openid4vci_routes: self.modules.register_openid4vci_routes,
                register_openid4vp_routes: self.modules.register_openid4vp_routes,
                dynamic_client_registration_initial_access_token: self
                    .modules
                    .dynamic_client_registration_initial_access_token
                    .clone(),
            },
            ciba: app::CibaSettings {
                ciba_auth_req_id_ttl_seconds: self.ciba.ciba_auth_req_id_ttl_seconds,
                ciba_poll_interval_seconds: self.ciba.ciba_poll_interval_seconds,
            },
        }
    }

    pub(crate) fn external_key_signer(
        &self,
    ) -> Option<std::sync::Arc<dyn nazo_key_management::ExternalKeySigner>> {
        if self.keys.signing_external_command.is_empty() {
            return None;
        }
        Some(std::sync::Arc::new(
            crate::adapters::external_signer::CommandExternalKeySigner::new(
                self.keys.signing_external_command.clone(),
                std::time::Duration::from_millis(self.keys.signing_external_timeout_ms),
            ),
        ))
    }

    pub(crate) fn key_settings(&self) -> nazo_key_management::KeySettings {
        nazo_key_management::KeySettings {
            rotation_interval: chrono::Duration::seconds(
                self.keys.signing_key_rotation_interval_seconds,
            ),
            prepublish_window: chrono::Duration::seconds(self.keys.signing_key_prepublish_seconds),
            verification_grace: chrono::Duration::seconds(
                self.protocol
                    .access_token_ttl_seconds
                    .max(self.protocol.id_token_ttl_seconds),
            ),
        }
    }
}

pub(crate) fn mfa_totp_key_ring(
    config: &ConfigSource,
) -> anyhow::Result<Option<nazo_postgres::MfaTotpKeyRing>> {
    let current_key = parse_optional_32_byte_key(config, "MFA_TOTP_ENCRYPTION_KEY")?;
    let current_key_id = config.optional_string("MFA_TOTP_ENCRYPTION_KEY_ID");
    let previous_key = parse_optional_32_byte_key(config, "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY")?;
    let previous_key_id = config.optional_string("MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID");
    validate_mfa_totp_key_pair(
        "MFA_TOTP_ENCRYPTION_KEY",
        current_key.is_some(),
        "MFA_TOTP_ENCRYPTION_KEY_ID",
        current_key_id.as_deref(),
    )?;
    validate_mfa_totp_key_pair(
        "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY",
        previous_key.is_some(),
        "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID",
        previous_key_id.as_deref(),
    )?;
    if current_key.is_none() && (previous_key.is_some() || previous_key_id.is_some()) {
        bail!(
            "MFA_TOTP_ENCRYPTION_KEY is required when a previous TOTP encryption key is configured"
        );
    }
    let Some(current_key) = current_key else {
        return Ok(None);
    };
    let current = nazo_postgres::MfaTotpKey::new(
        current_key_id.expect("validated MFA TOTP current key id"),
        current_key,
    )?;
    let previous = previous_key
        .zip(previous_key_id)
        .map(|(key, id)| nazo_postgres::MfaTotpKey::new(id, key))
        .transpose()?;
    Ok(Some(nazo_postgres::MfaTotpKeyRing::new(current, previous)?))
}

pub(crate) fn signing_key_wrapping_key_ring(
    config: &ConfigSource,
) -> anyhow::Result<nazo_key_management::SigningKeyWrappingKeyRing> {
    let current_key = parse_required_32_byte_key(config, "SIGNING_KEY_ENCRYPTION_KEY")?;
    let current_id = config.required_string("SIGNING_KEY_ENCRYPTION_KEY_ID")?;
    let previous_key = parse_optional_32_byte_key(config, "SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY")?;
    let previous_id = config.optional_string("SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_ID");
    if previous_key.is_some() != previous_id.is_some() {
        bail!(
            "SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY and SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_ID must be configured together"
        );
    }
    nazo_key_management::SigningKeyWrappingKeyRing::new(
        current_id,
        current_key,
        previous_key.zip(previous_id).map(|(key, id)| (id, key)),
    )
    .map_err(anyhow::Error::from)
}

fn parse_required_32_byte_key(
    config: &ConfigSource,
    name: &'static str,
) -> anyhow::Result<[u8; 32]> {
    let value = config.required_string(name)?;
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(anyhow::Error::from)?;
    <[u8; 32]>::try_from(decoded)
        .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))
}

fn parse_optional_32_byte_key(
    config: &ConfigSource,
    name: &'static str,
) -> anyhow::Result<Option<[u8; 32]>> {
    config
        .optional_string(name)
        .map(|value| URL_SAFE_NO_PAD.decode(value).map_err(anyhow::Error::from))
        .transpose()?
        .map(|value| {
            <[u8; 32]>::try_from(value)
                .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))
        })
        .transpose()
}

fn validate_mfa_totp_key_pair(
    key_name: &'static str,
    key_present: bool,
    id_name: &'static str,
    id: Option<&str>,
) -> anyhow::Result<()> {
    if key_present != id.is_some() {
        bail!("{key_name} and {id_name} must be configured together");
    }
    Ok(())
}

fn parse_attestation_jwk_set(
    config: &ConfigSource,
    key: &'static str,
) -> anyhow::Result<Option<serde_json::Value>> {
    config
        .optional_string(key)
        .map(|encoded| serde_json::from_str(&encoded).map_err(anyhow::Error::from))
        .transpose()
}

fn parse_signing_external_command(value: Option<String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn key_settings_from_config(
    config: &ConfigSource,
) -> anyhow::Result<nazo_key_management::KeySettings> {
    let rotation_interval_seconds =
        config.parse("SIGNING_KEY_ROTATION_INTERVAL_SECONDS", 7_776_000)?;
    let prepublish_seconds = config.parse("SIGNING_KEY_PREPUBLISH_SECONDS", 86_400)?;
    if rotation_interval_seconds <= 0 {
        bail!("SIGNING_KEY_ROTATION_INTERVAL_SECONDS must be positive");
    }
    if prepublish_seconds <= 0 {
        bail!("SIGNING_KEY_PREPUBLISH_SECONDS must be positive");
    }
    if prepublish_seconds >= rotation_interval_seconds {
        bail!(
            "SIGNING_KEY_PREPUBLISH_SECONDS must be less than SIGNING_KEY_ROTATION_INTERVAL_SECONDS"
        );
    }
    let access_token_ttl_seconds = config.parse("ACCESS_TOKEN_TTL_SECONDS", 300)?;
    let id_token_ttl_seconds = config.parse("ID_TOKEN_TTL_SECONDS", 600)?;
    nazoauth::config::validate_token_lifetimes(access_token_ttl_seconds, id_token_ttl_seconds)?;
    Ok(nazo_key_management::KeySettings {
        rotation_interval: chrono::Duration::seconds(rotation_interval_seconds),
        prepublish_window: chrono::Duration::seconds(prepublish_seconds),
        verification_grace: chrono::Duration::seconds(
            access_token_ttl_seconds.max(id_token_ttl_seconds),
        ),
    })
}

fn default_protected_resource_identifier(issuer: &str) -> String {
    format!("{}/fapi/resource", issuer.trim_end_matches('/'))
}

#[cfg(test)]
#[path = "../tests/unit/settings.rs"]
mod tests;
