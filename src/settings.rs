//! Runtime settings.
// Settings are built from the startup configuration snapshot.

use std::path::PathBuf;

use anyhow::{Context, bail};
use lettre::message::Mailbox;

use crate::config::ConfigSource;
use crate::support::{
    ClientIpHeaderMode, IpCidr, is_loopback_http_url, parse_trusted_proxy_cidrs,
    validate_cors_origin, validate_frontend_base_url, validate_issuer_url,
};

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
}

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

#[derive(Clone)]
pub(crate) struct RateLimitSettings {
    pub(crate) window_seconds: u64,
    pub(crate) auth_max_requests: u64,
    pub(crate) token_max_requests: u64,
    pub(crate) token_management_max_requests: u64,
}

#[derive(Clone)]
pub(crate) struct EmailSettings {
    pub(crate) delivery: EmailDelivery,
    pub(crate) code_ttl_seconds: u64,
    pub(crate) send_cooldown_seconds: u64,
    pub(crate) send_peer_cooldown_seconds: u64,
}

#[derive(Clone)]
pub(crate) enum EmailDelivery {
    Disabled,
    Smtp(SmtpEmailSettings),
}

#[derive(Clone)]
pub(crate) struct SmtpEmailSettings {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: SmtpTlsMode,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) from: Mailbox,
}

#[derive(Clone, Copy)]
pub(crate) enum SmtpTlsMode {
    StartTls,
    ImplicitTls,
    None,
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

impl AuthorizationServerProfile {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
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

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Oauth2Baseline => "oauth2-baseline",
            Self::Fapi2Security => "fapi2-security",
            Self::Fapi2MessageSigningAuthzRequest => "fapi2-message-signing-authz-request",
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
}

impl DpopNoncePolicy {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("DPOP_NONCE_POLICY", "required")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "required" | "require" | "strict" => Ok(Self::Required),
            "optional" | "compat" | "compatible" => Ok(Self::Optional),
            value => bail!("DPOP_NONCE_POLICY must be required or optional, got {value}"),
        }
    }
}

impl RequestObjectJtiPolicy {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
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
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
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

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Pairwise => "pairwise",
        }
    }
}

impl RateLimitSettings {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let settings = Self {
            window_seconds: config.parse("RATE_LIMIT_WINDOW_SECONDS", 60)?,
            auth_max_requests: config.parse("AUTH_RATE_LIMIT_MAX_REQUESTS", 30)?,
            token_max_requests: config.parse("TOKEN_RATE_LIMIT_MAX_REQUESTS", 60)?,
            token_management_max_requests: config
                .parse("TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS", 120)?,
        };
        if settings.window_seconds == 0 {
            bail!("RATE_LIMIT_WINDOW_SECONDS must be greater than 0");
        }
        if settings.auth_max_requests == 0
            || settings.token_max_requests == 0
            || settings.token_management_max_requests == 0
        {
            bail!("rate limit request caps must be greater than 0");
        }
        Ok(settings)
    }
}

impl EmailSettings {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let delivery = match config
            .string("EMAIL_DELIVERY", "disabled")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "disabled" => EmailDelivery::Disabled,
            "smtp" => EmailDelivery::Smtp(SmtpEmailSettings::from_config(config)?),
            value => bail!("EMAIL_DELIVERY must be disabled or smtp, got {value}"),
        };

        Ok(Self {
            delivery,
            code_ttl_seconds: config.parse("EMAIL_CODE_TTL_SECONDS", 900)?,
            send_cooldown_seconds: config.parse("EMAIL_CODE_SEND_COOLDOWN_SECONDS", 60)?,
            send_peer_cooldown_seconds: config.parse("EMAIL_CODE_PEER_COOLDOWN_SECONDS", 5)?,
        })
    }
}

impl SmtpEmailSettings {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let username = config.optional_string("EMAIL_SMTP_USERNAME");
        let password = config.optional_string("EMAIL_SMTP_PASSWORD");
        if username.is_some() != password.is_some() {
            bail!("EMAIL_SMTP_USERNAME and EMAIL_SMTP_PASSWORD must be configured together");
        }

        let from = config
            .required_string("EMAIL_FROM")?
            .parse::<Mailbox>()
            .context("EMAIL_FROM must be a valid mailbox")?;

        Ok(Self {
            host: config.required_string("EMAIL_SMTP_HOST")?,
            port: config.parse("EMAIL_SMTP_PORT", 587)?,
            tls: SmtpTlsMode::from_config(config)?,
            username,
            password,
            from,
        })
    }
}

impl SmtpTlsMode {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("EMAIL_SMTP_TLS", "starttls")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "starttls" => Ok(Self::StartTls),
            "implicit" | "tls" => Ok(Self::ImplicitTls),
            "none" | "plain" => Ok(Self::None),
            value => bail!("EMAIL_SMTP_TLS must be starttls, implicit, or none, got {value}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dpop_nonce_policy_is_required() {
        let settings = Settings::from_config(&ConfigSource::default()).unwrap();

        assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Required);
    }

    #[test]
    fn baseline_profile_can_use_optional_dpop_nonce_policy() {
        let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", "optional")]);
        let settings = Settings::from_config(&config).unwrap();

        assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Optional);
    }

    #[test]
    fn fapi_profiles_force_required_dpop_nonce_policy() {
        let config = ConfigSource::from_pairs_for_test([
            ("AUTHORIZATION_SERVER_PROFILE", "fapi2-security"),
            ("DPOP_NONCE_POLICY", "optional"),
        ]);
        let settings = Settings::from_config(&config).unwrap();

        assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Required);
    }

    #[test]
    fn invalid_dpop_nonce_policy_is_rejected() {
        let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", "sometimes")]);

        assert!(Settings::from_config(&config).is_err());
    }

    #[test]
    fn default_request_object_jti_policy_is_optional() {
        let settings = Settings::from_config(&ConfigSource::default()).unwrap();

        assert_eq!(
            settings.request_object_jti_policy,
            RequestObjectJtiPolicy::Optional
        );
    }

    #[test]
    fn request_object_jti_policy_can_require_signed_jar_jti() {
        let config = ConfigSource::from_pairs_for_test([("REQUEST_OBJECT_JTI_POLICY", "required")]);
        let settings = Settings::from_config(&config).unwrap();

        assert_eq!(
            settings.request_object_jti_policy,
            RequestObjectJtiPolicy::RequiredForSignedJar
        );
    }

    #[test]
    fn invalid_request_object_jti_policy_is_rejected() {
        let config = ConfigSource::from_pairs_for_test([("REQUEST_OBJECT_JTI_POLICY", "always")]);

        assert!(Settings::from_config(&config).is_err());
    }
}
