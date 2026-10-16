use std::borrow::Cow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SenderConstraintPolicy {
    BearerAllowed,
    DpopRequired,
    MtlsRequired,
    DpopOrMtls,
}

impl SenderConstraintPolicy {
    #[must_use]
    pub const fn is_sender_constrained(self) -> bool {
        !matches!(self, Self::BearerAllowed)
    }
}

#[must_use]
pub fn is_valid_dpop_jkt(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode_slice(value, &mut [0; 32])
            .is_ok_and(|len| len == 32)
}

#[must_use]
pub fn normalize_sha256_thumbprint(value: &str) -> Option<Cow<'_, str>> {
    let trimmed = value.trim();
    if is_valid_dpop_jkt(trimmed) {
        return Some(Cow::Borrowed(trimmed));
    }

    let mut hex = trimmed
        .chars()
        .filter(|ch| !matches!(ch, ':' | ' ' | '\t' | '\r' | '\n'));
    let mut bytes = [0; 32];
    for byte in &mut bytes {
        *byte = (hex.next()?.to_digit(16)? * 16 + hex.next()?.to_digit(16)?) as u8;
    }
    hex.next()
        .is_none()
        .then(|| Cow::Owned(URL_SAFE_NO_PAD.encode(bytes)))
}
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
