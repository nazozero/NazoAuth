#[must_use]
pub fn normalize_federation_token(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() >= 32
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    .then_some(value.to_owned())
}
