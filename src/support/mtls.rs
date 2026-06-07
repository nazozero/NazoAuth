//! mTLS client certificate binding helpers.
//!
//! The application only trusts certificate data from configured trusted proxy
//! peers after the proxy has verified the client certificate and forwarded
//! `X-SSL-Client-Verify: SUCCESS`.

use super::prelude::*;
use super::request_from_trusted_proxy;

const VERIFY_HEADER: &str = "x-ssl-client-verify";
const DIRECT_THUMBPRINT_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-sha256",
    "x-ssl-client-cert-sha256",
    "x-ssl-client-fingerprint-sha256",
];
const CERTIFICATE_HEADERS: &[&str] = &["x-ssl-client-cert", "x-forwarded-tls-client-cert"];

pub(crate) fn request_mtls_thumbprint(req: &HttpRequest, settings: &Settings) -> Option<String> {
    if !request_from_trusted_proxy(req, settings) {
        return None;
    }
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

    let mut values = Vec::new();
    for name in DIRECT_THUMBPRINT_HEADERS {
        if let Some(value) = header_str(headers, name) {
            values.push(normalize_sha256_thumbprint(value)?);
        }
    }
    for name in CERTIFICATE_HEADERS {
        if let Some(value) = header_str(headers, name) {
            values.push(certificate_pem_thumbprint(value)?);
        }
    }

    let first = values.as_slice().first()?.clone();
    values
        .iter()
        .all(|value| constant_time_eq(first.as_bytes(), value.as_bytes()))
        .then_some(first)
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
    use crate::settings::{EmailDelivery, EmailSettings, RateLimitSettings, SubjectType};
    use crate::support::{ClientIpHeaderMode, IpCidr};
    use actix_web::test::TestRequest;

    fn trusted_proxy_settings() -> Settings {
        Settings {
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://issuer.example".to_owned(),
            frontend_base_url: "https://app.example".to_owned(),
            cors_allowed_origins: vec!["https://app.example".to_owned()],
            default_audience: "resource://default".to_owned(),
            session_cookie_name: "sid".to_owned(),
            csrf_cookie_name: "csrf".to_owned(),
            cookie_secure: true,
            session_ttl_seconds: 3600,
            auth_code_ttl_seconds: 60,
            access_token_ttl_seconds: 300,
            id_token_ttl_seconds: 600,
            refresh_token_ttl_seconds: 2_592_000,
            avatar_max_bytes: 2_097_152,
            client_delivery_ttl_seconds: 86_400,
            rate_limit: RateLimitSettings {
                window_seconds: 60,
                auth_max_requests: 30,
                token_max_requests: 60,
                token_management_max_requests: 120,
            },
            email: EmailSettings {
                delivery: EmailDelivery::Disabled,
                code_ttl_seconds: 900,
                send_cooldown_seconds: 60,
                send_peer_cooldown_seconds: 5,
            },
            email_code_dev_response_enabled: false,
            avatar_storage_dir: PathBuf::from("runtime/avatars"),
            jwk_keys_dir: PathBuf::from("runtime/keys"),
            trusted_proxy_cidrs: vec![IpCidr::parse("192.0.2.0/24").unwrap()],
            client_ip_header_mode: ClientIpHeaderMode::None,
            subject_type: SubjectType::Public,
            pairwise_subject_secret: None,
            par_ttl_seconds: 90,
            require_pushed_authorization_requests: false,
        }
    }

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

    #[test]
    fn rejects_conflicting_forwarded_certificate_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("x-ssl-client-verify"),
            HeaderValue::from_static("SUCCESS"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-sha256"),
            HeaderValue::from_static("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
        );
        headers.insert(
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            HeaderValue::from_static("__________________________________________8"),
        );

        assert!(request_mtls_thumbprint_from_headers(&headers).is_none());
    }

    #[test]
    fn accepts_duplicate_matching_forwarded_certificate_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("x-ssl-client-verify"),
            HeaderValue::from_static("SUCCESS"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-sha256"),
            HeaderValue::from_static("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
        );
        headers.insert(
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            HeaderValue::from_static("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"),
        );

        assert_eq!(
            request_mtls_thumbprint_from_headers(&headers).as_deref(),
            Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8")
        );
    }

    #[test]
    fn ignores_forwarded_certificate_headers_from_untrusted_peer() {
        let settings = trusted_proxy_settings();
        let req = TestRequest::default()
            .peer_addr("198.51.100.10:443".parse().unwrap())
            .insert_header(("x-ssl-client-verify", "SUCCESS"))
            .insert_header((
                "x-forwarded-tls-client-cert-sha256",
                "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
            ))
            .to_http_request();

        assert!(request_mtls_thumbprint(&req, &settings).is_none());
    }

    #[test]
    fn accepts_forwarded_certificate_headers_from_trusted_peer() {
        let settings = trusted_proxy_settings();
        let req = TestRequest::default()
            .peer_addr("192.0.2.10:443".parse().unwrap())
            .insert_header(("x-ssl-client-verify", "SUCCESS"))
            .insert_header((
                "x-forwarded-tls-client-cert-sha256",
                "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
            ))
            .to_http_request();

        assert_eq!(
            request_mtls_thumbprint(&req, &settings).as_deref(),
            Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8")
        );
    }
}
