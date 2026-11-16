use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::io::Write;

use crate::config::SamlGatewaySettings;

pub type HmacSha256 = Hmac<Sha256>;
pub const SAML_ASSERTION_CLOCK_SKEW_SECONDS: i64 = 60;
pub const SAML_ASSERTION_MAX_TTL_SECONDS: i64 = 300;

#[derive(Clone, Deserialize)]
pub struct SamlGatewayAssertion {
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
    pub iat: i64,
    pub exp: i64,
    pub signature: String,
}

pub fn valid_saml_gateway_assertion(
    settings: &SamlGatewaySettings,
    assertion: &SamlGatewayAssertion,
    normalized_email: &str,
) -> bool {
    let now = Utc::now().timestamp();
    if assertion.issuer != settings.issuer
        || assertion.audience != settings.audience
        || assertion.subject.trim().is_empty()
        || assertion.iat > now.saturating_add(SAML_ASSERTION_CLOCK_SKEW_SECONDS)
        || assertion.exp <= now
        || assertion.exp.saturating_sub(assertion.iat) > SAML_ASSERTION_MAX_TTL_SECONDS
    {
        return false;
    }
    let mut signature = [0; 32];
    if URL_SAFE_NO_PAD.decode_slice(&assertion.signature, &mut signature) != Ok(signature.len()) {
        return false;
    }
    saml_gateway_mac(
        &settings.secret,
        &assertion.issuer,
        &assertion.audience,
        &assertion.subject,
        normalized_email,
        assertion.iat,
        assertion.exp,
    )
    .verify_slice(&signature)
    .is_ok()
}

pub fn saml_gateway_mac(
    secret: &str,
    issuer: &str,
    audience: &str,
    subject: &str,
    email: &str,
    iat: i64,
    exp: i64,
) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    for field in [issuer, audience, subject, email] {
        mac.update(field.as_bytes());
        mac.update(b"\n");
    }
    // Two signed i64 decimal values (at most 20 bytes each) and one separator.
    let mut timestamps = [0; 41];
    let mut output = timestamps.as_mut_slice();
    write!(output, "{iat}\n{exp}").expect("timestamp buffer holds both i64 values");
    let written = 41 - output.len();
    mac.update(&timestamps[..written]);
    mac
}

#[cfg(test)]
#[path = "../../../../tests/unit/endpoints/auth/federation/saml.rs"]
mod tests;
