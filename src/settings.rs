//! Runtime settings.
// Settings are built from the startup configuration snapshot.

use std::path::PathBuf;

use anyhow::bail;

use crate::config::ConfigSource;
use crate::support::{
    ClientIpHeaderMode, IpCidr, is_loopback_http_url, parse_trusted_proxy_cidrs,
    validate_cors_origin, validate_frontend_base_url, validate_issuer_url,
};

mod email;
mod federation;
mod passkey;
mod profile;
mod rate_limit;

pub(crate) use email::{EmailDelivery, EmailSettings, SmtpEmailSettings, SmtpTlsMode};
pub(crate) use federation::{FederationSettings, OidcFederationSettings, SamlGatewaySettings};
pub(crate) use passkey::PasskeySettings;
pub(crate) use profile::{
    AuthorizationServerProfile, DpopNoncePolicy, RequestObjectJtiPolicy, SubjectType,
};
pub(crate) use rate_limit::RateLimitSettings;

/// OAuth service runtime parameters.
#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) frontend_base_url: String,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) default_audience: String,
    pub(crate) authorization_server_profile: AuthorizationServerProfile,
    pub(crate) dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) request_object_jti_policy: RequestObjectJtiPolicy,
    pub(crate) session_cookie_name: String,
    pub(crate) csrf_cookie_name: String,
    pub(crate) cookie_secure: bool,
    pub(crate) session_ttl_seconds: u64,
    pub(crate) auth_code_ttl_seconds: u64,
    pub(crate) access_token_ttl_seconds: i64,
    pub(crate) id_token_ttl_seconds: i64,
    pub(crate) refresh_token_ttl_seconds: i64,
    pub(crate) avatar_max_bytes: usize,
    pub(crate) client_delivery_ttl_seconds: u64,
    pub(crate) rate_limit: RateLimitSettings,
    pub(crate) email: EmailSettings,
    pub(crate) email_code_dev_response_enabled: bool,
    pub(crate) avatar_storage_dir: PathBuf,
    pub(crate) jwk_keys_dir: PathBuf,
    pub(crate) signing_external_command: Vec<String>,
    pub(crate) signing_external_timeout_ms: u64,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) subject_type: SubjectType,
    pub(crate) pairwise_subject_secret: Option<String>,
    pub(crate) par_ttl_seconds: u64,
    pub(crate) require_pushed_authorization_requests: bool,
    pub(crate) scim_bearer_token: Option<String>,
    pub(crate) passkey: PasskeySettings,
    pub(crate) federation: FederationSettings,
}

impl Settings {
    /// Builds settings from the startup configuration source.
    pub(crate) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let issuer = config.string("ISSUER", "http://127.0.0.1:8000");
        validate_issuer_url(&issuer)?;
        let mtls_endpoint_base_url = config
            .optional_string("MTLS_ENDPOINT_BASE_URL")
            .unwrap_or_else(|| issuer.clone());
        validate_issuer_url(&mtls_endpoint_base_url)?;
        let frontend_base_url = config.string("FRONTEND_BASE_URL", "http://127.0.0.1:3000");
        validate_frontend_base_url(&frontend_base_url)?;
        let cors_allowed_origins = config
            .get("CORS_ALLOWED_ORIGINS")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .filter(|values: &Vec<String>| !values.is_empty())
            .unwrap_or_else(|| vec!["http://127.0.0.1:3000".into()]);
        for origin in &cors_allowed_origins {
            validate_cors_origin(origin)?;
        }
        let default_cookie_secure = issuer.starts_with("https://");
        let cookie_secure = config.bool("COOKIE_SECURE", default_cookie_secure)?;
        if !cookie_secure && !is_loopback_http_url(&issuer) {
            bail!("COOKIE_SECURE=false 只允许用于 loopback HTTP 本地开发 issuer");
        }
        let subject_type = SubjectType::from_config(config)?;
        let pairwise_subject_secret = config.optional_string("PAIRWISE_SUBJECT_SECRET");
        if subject_type == SubjectType::Pairwise && pairwise_subject_secret.is_none() {
            bail!("PAIRWISE_SUBJECT_SECRET is required when SUBJECT_TYPE=pairwise");
        }
        let authorization_server_profile = AuthorizationServerProfile::from_config(config)?;
        let configured_dpop_nonce_policy = DpopNoncePolicy::from_config(config)?;
        let dpop_nonce_policy = if authorization_server_profile.requires_fapi2_security() {
            DpopNoncePolicy::Required
        } else {
            configured_dpop_nonce_policy
        };
        let request_object_jti_policy = RequestObjectJtiPolicy::from_config(config)?;
        let auth_code_ttl_seconds = config.parse("AUTH_CODE_TTL_SECONDS", 60)?;
        if authorization_server_profile.requires_fapi2_security() && auth_code_ttl_seconds > 60 {
            bail!("AUTH_CODE_TTL_SECONDS must be 60 or less for FAPI2 profiles");
        }
        let require_pushed_authorization_requests = config
            .bool("REQUIRE_PUSHED_AUTHORIZATION_REQUESTS", false)?
            || authorization_server_profile.requires_fapi2_security();
        let passkey = PasskeySettings::from_config(config, &issuer)?;
        let federation = FederationSettings::from_config(config)?;

        Ok(Self {
            issuer,
            mtls_endpoint_base_url,
            frontend_base_url,
            cors_allowed_origins,
            default_audience: config.string("DEFAULT_AUDIENCE", "resource://default"),
            authorization_server_profile,
            dpop_nonce_policy,
            request_object_jti_policy,
            session_cookie_name: config.string("SESSION_COOKIE_NAME", "nazo_oauth_session"),
            csrf_cookie_name: config.string("CSRF_COOKIE_NAME", "nazo_oauth_csrf"),
            cookie_secure,
            session_ttl_seconds: config.parse("SESSION_TTL_SECONDS", 28_800)?,
            auth_code_ttl_seconds,
            access_token_ttl_seconds: config.parse("ACCESS_TOKEN_TTL_SECONDS", 300)?,
            id_token_ttl_seconds: config.parse("ID_TOKEN_TTL_SECONDS", 600)?,
            refresh_token_ttl_seconds: config.parse("REFRESH_TOKEN_TTL_SECONDS", 2_592_000)?,
            avatar_max_bytes: config.parse("AVATAR_MAX_BYTES", 2_097_152)?,
            client_delivery_ttl_seconds: config.parse("CLIENT_DELIVERY_TTL_SECONDS", 86_400)?,
            rate_limit: RateLimitSettings::from_config(config)?,
            email: EmailSettings::from_config(config)?,
            email_code_dev_response_enabled: config
                .bool("EMAIL_CODE_DEV_RESPONSE_ENABLED", false)?,
            avatar_storage_dir: PathBuf::from(
                config.string("AVATAR_STORAGE_DIR", "runtime/avatars"),
            ),
            jwk_keys_dir: PathBuf::from(config.string("JWK_KEYS_DIR", "runtime/keys")),
            signing_external_command: parse_signing_external_command(
                config.optional_string("SIGNING_EXTERNAL_COMMAND"),
            ),
            signing_external_timeout_ms: config.parse("SIGNING_EXTERNAL_TIMEOUT_MS", 2_000)?,
            trusted_proxy_cidrs: parse_trusted_proxy_cidrs(config.get("TRUSTED_PROXY_CIDRS"))?,
            client_ip_header_mode: ClientIpHeaderMode::parse(
                &config.string("CLIENT_IP_HEADER_MODE", "none"),
            )?,
            subject_type,
            pairwise_subject_secret,
            par_ttl_seconds: config.parse("PAR_TTL_SECONDS", 90)?,
            require_pushed_authorization_requests,
            scim_bearer_token: config.optional_string("SCIM_BEARER_TOKEN"),
            passkey,
            federation,
        })
    }
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

#[cfg(test)]
#[path = "settings/tests.rs"]
mod tests;
