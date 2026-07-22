use crate::adapters::security::blake3_hex;

pub(crate) fn native_sso_device_secret_key(device_secret: &str) -> String {
    format!(
        "oauth:native_sso:device_secret:{}",
        blake3_hex(device_secret)
    )
}
