//! mTLS client certificate binding helpers.
//!
//! The application only trusts certificate data after the reverse proxy has
//! verified the client certificate and forwarded `X-SSL-Client-Verify: SUCCESS`.

use super::prelude::*;

const VERIFY_HEADER: &str = "x-ssl-client-verify";
const DIRECT_THUMBPRINT_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-sha256",
    "x-ssl-client-cert-sha256",
    "x-ssl-client-fingerprint-sha256",
];
const CERTIFICATE_HEADERS: &[&str] = &["x-ssl-client-cert", "x-forwarded-tls-client-cert"];

pub(crate) fn request_mtls_thumbprint(req: &HttpRequest) -> Option<String> {
    request_mtls_thumbprint_from_headers(req.headers())
}

pub(crate) fn request_mtls_thumbprint_from_headers(headers: &HeaderMap) -> Option<String> {
    if !headers
        .get(VERIFY_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("SUCCESS"))
    {
        return None;
    }

    for name in DIRECT_THUMBPRINT_HEADERS {
        if let Some(value) = header_str(headers, name).and_then(normalize_sha256_thumbprint) {
            return Some(value);
        }
    }
    for name in CERTIFICATE_HEADERS {
        if let Some(value) = header_str(headers, name).and_then(certificate_pem_thumbprint) {
            return Some(value);
        }
    }
    None
}

pub(crate) fn certificate_pem_thumbprint(value: &str) -> Option<String> {
    let decoded = if value.contains('%') {
        urlencoding::decode(value).ok()?.into_owned()
    } else {
        value.to_owned()
    };
    let decoded = decoded.replace("\\n", "\n");
    let start = decoded.find("-----BEGIN CERTIFICATE-----")?;
    let end = decoded.find("-----END CERTIFICATE-----")?;
    if end <= start {
        return None;
    }
    let body_start = start + "-----BEGIN CERTIFICATE-----".len();
    let body = decoded[body_start..end]
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    let der = STANDARD.decode(body).ok()?;
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(&der)))
}

pub(crate) fn normalize_sha256_thumbprint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() == 43
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        let decoded = URL_SAFE_NO_PAD.decode(trimmed).ok()?;
        return (decoded.len() == 32).then(|| trimmed.to_owned());
    }

    let hex = trimmed
        .chars()
        .filter(|ch| !matches!(ch, ':' | ' ' | '\t' | '\r' | '\n'))
        .collect::<String>();
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(32);
    for idx in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn client_mtls_thumbprint_matches(client: &ClientRow, thumbprint: &str) -> bool {
    client
        .tls_client_auth_cert_sha256
        .as_deref()
        .and_then(normalize_sha256_thumbprint)
        .is_some_and(|registered| constant_time_eq(registered.as_bytes(), thumbprint.as_bytes()))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok().map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_colon_hex_sha256_to_x5t_s256() {
        let raw = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";

        assert_eq!(
            normalize_sha256_thumbprint(raw).as_deref(),
            Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8")
        );
    }

    #[test]
    fn rejects_unverified_proxy_certificate_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-sha256"),
            HeaderValue::from_static("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
        );

        assert!(request_mtls_thumbprint_from_headers(&headers).is_none());
    }
}
