use nazo_auth::validate_issuer_url;

use crate::config::ConfigSource;

pub(crate) use nazoauth::config::PasskeySettings;

pub(super) fn from_config(
    config: &ConfigSource,
    issuer_url: &url::Url,
) -> anyhow::Result<PasskeySettings> {
    let configured_origin_url;
    let (origin, origin_url) = match config.optional_string("PASSKEY_ORIGIN") {
        Some(origin) => {
            configured_origin_url = validate_issuer_url(&origin)?;
            (origin, &configured_origin_url)
        }
        None => (issuer_url.origin().ascii_serialization(), issuer_url),
    };
    let rp_id = match config.optional_string("PASSKEY_RP_ID") {
        Some(value) => value,
        None => origin_url
            .host_str()
            .expect("validated origin has a host")
            .to_owned(),
    };
    let rp_name = config.string("PASSKEY_RP_NAME", "Nazo OAuth");
    nazo_passkey::Webauthn::try_new(&rp_id, &rp_name, &origin)?;
    Ok(PasskeySettings {
        rp_id,
        rp_name,
        origin,
        require_user_verification: config.bool("PASSKEY_REQUIRE_USER_VERIFICATION", true)?,
        require_user_handle: config.bool("PASSKEY_REQUIRE_USER_HANDLE", true)?,
    })
}
