//! Runtime settings.
// Settings are built from the startup configuration snapshot.

use std::path::PathBuf;

use anyhow::{Context, bail};
use lettre::message::Mailbox;

use crate::config::ConfigSource;

/// OAuth service runtime parameters.
#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) issuer: String,
    pub(crate) frontend_base_url: String,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) default_audience: String,
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
        let default_cookie_secure = issuer.starts_with("https://");
        Ok(Self {
            issuer,
            frontend_base_url: config.string("FRONTEND_BASE_URL", "http://127.0.0.1:3000"),
            cors_allowed_origins: config
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
                .unwrap_or_else(|| vec!["http://127.0.0.1:3000".into()]),
            default_audience: config.string("DEFAULT_AUDIENCE", "resource://default"),
            session_cookie_name: config.string("SESSION_COOKIE_NAME", "nazo_oauth_session"),
            csrf_cookie_name: config.string("CSRF_COOKIE_NAME", "nazo_oauth_csrf"),
            cookie_secure: config.bool("COOKIE_SECURE", default_cookie_secure)?,
            session_ttl_seconds: config.parse("SESSION_TTL_SECONDS", 28_800)?,
            auth_code_ttl_seconds: config.parse("AUTH_CODE_TTL_SECONDS", 300)?,
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
        })
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
