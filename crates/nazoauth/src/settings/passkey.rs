use anyhow::bail;
use nazo_auth::validate_issuer_url;

use crate::config::ConfigSource;

#[derive(Clone)]
pub(crate) struct PasskeySettings {
    pub(crate) rp_id: String,
    pub(crate) rp_name: String,
    pub(crate) origin: String,
    pub(crate) require_user_verification: bool,
    pub(crate) require_user_handle: bool,
    pub(crate) strict_base64: bool,
}

impl PasskeySettings {
    pub(super) fn from_config(
        config: &ConfigSource,
        issuer: &str,
        issuer_url: &url::Url,
    ) -> anyhow::Result<Self> {
        let configured_origin_url;
        let (origin, origin_url) = match config.optional_string("PASSKEY_ORIGIN") {
            Some(origin) => {
                configured_origin_url = validate_issuer_url(&origin)?;
                (origin, &configured_origin_url)
            }
            None => (issuer.to_owned(), issuer_url),
        };
        let rp_id = match config.optional_string("PASSKEY_RP_ID") {
            Some(value) => value,
            None => origin_url
                .host_str()
                .expect("validated origin has a host")
                .to_owned(),
        };
        if rp_id.trim().is_empty()
            || rp_id.contains("://")
            || rp_id.contains('/')
            || rp_id.contains(':')
        {
            bail!("PASSKEY_RP_ID must be a bare host name without scheme, port, or path");
        }
        Ok(Self {
            rp_id,
            rp_name: config.string("PASSKEY_RP_NAME", "Nazo OAuth"),
            origin,
            require_user_verification: config.bool("PASSKEY_REQUIRE_USER_VERIFICATION", true)?,
            require_user_handle: config.bool("PASSKEY_REQUIRE_USER_HANDLE", true)?,
            strict_base64: config.bool("PASSKEY_STRICT_BASE64", true)?,
        })
    }
}
