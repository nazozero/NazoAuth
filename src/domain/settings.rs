//! 配置读取与默认值。
// 配置只在启动阶段读取，运行期通过 AppState 共享不可变快照。
use std::path::PathBuf;

use crate::support::ConfigSource;

/// OAuth 服务的运行参数。
#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) issuer: String,
    pub(crate) frontend_base_url: String,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) default_audience: String,
    pub(crate) session_cookie_name: String,
    pub(crate) csrf_cookie_name: String,
    pub(crate) session_ttl_seconds: u64,
    pub(crate) auth_code_ttl_seconds: u64,
    pub(crate) access_token_ttl_seconds: i64,
    pub(crate) id_token_ttl_seconds: i64,
    pub(crate) refresh_token_ttl_seconds: i64,
    pub(crate) avatar_max_bytes: usize,
    pub(crate) client_delivery_ttl_seconds: u64,
    pub(crate) email_code_dev_response_enabled: bool,
    pub(crate) avatar_storage_dir: PathBuf,
    pub(crate) jwk_keys_dir: PathBuf,
}

impl Settings {
    /// 从配置源构造设置；未提供时使用本地开发默认值。
    pub(crate) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        Ok(Self {
            issuer: config.string("ISSUER", "http://127.0.0.1:8000"),
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
            session_ttl_seconds: config.parse("SESSION_TTL_SECONDS", 28_800)?,
            auth_code_ttl_seconds: config.parse("AUTH_CODE_TTL_SECONDS", 300)?,
            access_token_ttl_seconds: config.parse("ACCESS_TOKEN_TTL_SECONDS", 300)?,
            id_token_ttl_seconds: config.parse("ID_TOKEN_TTL_SECONDS", 600)?,
            refresh_token_ttl_seconds: config.parse("REFRESH_TOKEN_TTL_SECONDS", 2_592_000)?,
            avatar_max_bytes: config.parse("AVATAR_MAX_BYTES", 2_097_152)?,
            client_delivery_ttl_seconds: config.parse("CLIENT_DELIVERY_TTL_SECONDS", 86_400)?,
            email_code_dev_response_enabled: config
                .bool("EMAIL_CODE_DEV_RESPONSE_ENABLED", false)?,
            avatar_storage_dir: PathBuf::from(
                config.string("AVATAR_STORAGE_DIR", "runtime/avatars"),
            ),
            jwk_keys_dir: PathBuf::from(config.string("JWK_KEYS_DIR", "runtime/keys")),
        })
    }
}
