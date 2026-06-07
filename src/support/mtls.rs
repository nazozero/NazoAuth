//! mTLS client certificate binding helpers.
//!
//! The application only trusts certificate data from configured trusted proxy
//! peers after the proxy has verified the client certificate and forwarded
//! `X-SSL-Client-Verify: SUCCESS`.

use super::prelude::*;
use super::request_from_trusted_proxy;
use openssl::nid::Nid;
use openssl::x509::{X509, X509NameRef};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const VERIFY_HEADER: &str = "x-ssl-client-verify";
const DIRECT_THUMBPRINT_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-sha256",
    "x-ssl-client-cert-sha256",
    "x-ssl-client-fingerprint-sha256",
];
const CERTIFICATE_HEADERS: &[&str] = &["x-ssl-client-cert", "x-forwarded-tls-client-cert"];
const SUBJECT_DN_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-subject-dn",
    "x-ssl-client-subject-dn",
    "ssl-client-subject-dn",
];
const SAN_DNS_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-san-dns",
    "x-ssl-client-san-dns",
];
const SAN_URI_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-san-uri",
    "x-ssl-client-san-uri",
];
const SAN_IP_HEADERS: &[&str] = &["x-forwarded-tls-client-cert-san-ip", "x-ssl-client-san-ip"];
const SAN_EMAIL_HEADERS: &[&str] = &[
    "x-forwarded-tls-client-cert-san-email",
    "x-ssl-client-san-email",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MtlsClientCertificate {
    pub(crate) thumbprint: Option<String>,
    pub(crate) subject_dn: Option<String>,
    pub(crate) san_dns: Vec<String>,
    pub(crate) san_uri: Vec<String>,
    pub(crate) san_ip: Vec<String>,
    pub(crate) san_email: Vec<String>,
}

pub(crate) fn request_mtls_thumbprint(req: &HttpRequest, settings: &Settings) -> Option<String> {
    request_mtls_client_certificate(req, settings)?.thumbprint
}

pub(crate) fn request_mtls_client_certificate(
    req: &HttpRequest,
    settings: &Settings,
) -> Option<MtlsClientCertificate> {
    if !request_from_trusted_proxy(req, settings) {
        return None;
    }
    request_mtls_client_certificate_from_headers(req.headers())
}

pub(crate) fn request_mtls_client_certificate_from_headers(
    headers: &HeaderMap,
) -> Option<MtlsClientCertificate> {
    if !headers
        .get(VERIFY_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("SUCCESS"))
    {
        return None;
    }

    let mut certificate = MtlsClientCertificate {
        thumbprint: matching_forwarded_value(
            forwarded_values(headers, DIRECT_THUMBPRINT_HEADERS)
                .into_iter()
                .map(|value| normalize_sha256_thumbprint(&value))
                .collect::<Option<Vec<_>>>()?,
        )?,
        subject_dn: matching_forwarded_value(forwarded_values(headers, SUBJECT_DN_HEADERS))?,
        san_dns: sorted_unique(forwarded_list_values(headers, SAN_DNS_HEADERS)),
        san_uri: sorted_unique(forwarded_list_values(headers, SAN_URI_HEADERS)),
        san_ip: sorted_unique(forwarded_list_values(headers, SAN_IP_HEADERS)),
        san_email: sorted_unique(forwarded_list_values(headers, SAN_EMAIL_HEADERS)),
    };

    for pem in forwarded_values(headers, CERTIFICATE_HEADERS) {
        let parsed = certificate_pem_identity(&pem)?;
        merge_matching(&mut certificate.thumbprint, parsed.thumbprint)?;
        merge_matching(&mut certificate.subject_dn, parsed.subject_dn)?;
        merge_sorted_unique(&mut certificate.san_dns, parsed.san_dns);
        merge_sorted_unique(&mut certificate.san_uri, parsed.san_uri);
        merge_sorted_unique(&mut certificate.san_ip, parsed.san_ip);
        merge_sorted_unique(&mut certificate.san_email, parsed.san_email);
    }

    certificate.has_binding_material().then_some(certificate)
}

pub(crate) fn certificate_pem_identity(value: &str) -> Option<MtlsClientCertificate> {
    let decoded = decode_forwarded_pem(value);
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
    let x509 = X509::from_der(&der).ok()?;
    let mut certificate = MtlsClientCertificate {
        thumbprint: Some(URL_SAFE_NO_PAD.encode(Sha256::digest(&der))),
        subject_dn: Some(subject_name_to_dn(x509.subject_name())?),
        ..MtlsClientCertificate::default()
    };
    if let Some(names) = x509.subject_alt_names() {
        for name in names {
            if let Some(value) = name.dnsname() {
                certificate.san_dns.push(value.to_owned());
            }
            if let Some(value) = name.uri() {
                certificate.san_uri.push(value.to_owned());
            }
            if let Some(value) = name.email() {
                certificate.san_email.push(value.to_owned());
            }
            if let Some(value) = name.ipaddress().and_then(ipaddress_to_string) {
                certificate.san_ip.push(value);
            }
        }
    }
    certificate.san_dns = sorted_unique(certificate.san_dns);
    certificate.san_uri = sorted_unique(certificate.san_uri);
    certificate.san_ip = sorted_unique(certificate.san_ip);
    certificate.san_email = sorted_unique(certificate.san_email);
    Some(certificate)
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

pub(crate) fn client_mtls_certificate_matches(
    client: &ClientRow,
    certificate: &MtlsClientCertificate,
) -> bool {
    if client.token_endpoint_auth_method == "self_signed_tls_client_auth" {
        return certificate
            .thumbprint
            .as_deref()
            .is_some_and(|thumbprint| client_mtls_thumbprint_matches(client, thumbprint));
    }
    if certificate
        .thumbprint
        .as_deref()
        .is_some_and(|thumbprint| client_mtls_thumbprint_matches(client, thumbprint))
    {
        return true;
    }
    if let (Some(registered), Some(actual)) = (
        client.tls_client_auth_subject_dn.as_deref(),
        certificate.subject_dn.as_deref(),
    ) && constant_time_eq(registered.trim().as_bytes(), actual.trim().as_bytes())
    {
        return true;
    }
    registered_values_match(&client.tls_client_auth_san_dns, &certificate.san_dns)
        || registered_values_match(&client.tls_client_auth_san_uri, &certificate.san_uri)
        || registered_values_match(&client.tls_client_auth_san_ip, &certificate.san_ip)
        || registered_values_match(&client.tls_client_auth_san_email, &certificate.san_email)
}

impl MtlsClientCertificate {
    fn has_binding_material(&self) -> bool {
        self.thumbprint.is_some()
            || self.subject_dn.is_some()
            || !self.san_dns.is_empty()
            || !self.san_uri.is_empty()
            || !self.san_ip.is_empty()
            || !self.san_email.is_empty()
    }
}

fn forwarded_values(headers: &HeaderMap, names: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    for name in names {
        for value in headers.get_all(*name) {
            if let Ok(text) = value.to_str() {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    values.push(trimmed.to_owned());
                }
            }
        }
    }
    values
}

fn forwarded_list_values(headers: &HeaderMap, names: &[&str]) -> Vec<String> {
    forwarded_values(headers, names)
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn matching_forwarded_value(values: Vec<String>) -> Option<Option<String>> {
    let Some(first) = values.as_slice().first() else {
        return Some(None);
    };
    values
        .iter()
        .all(|value| constant_time_eq(first.as_bytes(), value.as_bytes()))
        .then_some(Some(first.clone()))
}

fn merge_matching(target: &mut Option<String>, incoming: Option<String>) -> Option<()> {
    match (target.as_ref(), incoming) {
        (_, None) => Some(()),
        (None, Some(value)) => {
            *target = Some(value);
            Some(())
        }
        (Some(current), Some(value)) if constant_time_eq(current.as_bytes(), value.as_bytes()) => {
            Some(())
        }
        _ => None,
    }
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn merge_sorted_unique(target: &mut Vec<String>, incoming: Vec<String>) {
    target.extend(incoming);
    target.sort();
    target.dedup();
}

fn decode_forwarded_pem(value: &str) -> String {
    let decoded = if value.contains('%') {
        urlencoding::decode(value)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_else(|_| value.to_owned())
    } else {
        value.to_owned()
    };
    decoded.replace("\\n", "\n")
}

fn subject_name_to_dn(name: &X509NameRef) -> Option<String> {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let short_name = nid_short_name(entry.object().nid())?;
        let value = entry.data().as_utf8().ok()?.to_string();
        parts.push(format!("{short_name}={}", escape_dn_value(&value)));
    }
    (!parts.is_empty()).then(|| parts.join(","))
}

fn nid_short_name(nid: Nid) -> Option<&'static str> {
    match nid {
        Nid::COMMONNAME => Some("CN"),
        Nid::COUNTRYNAME => Some("C"),
        Nid::STATEORPROVINCENAME => Some("ST"),
        Nid::LOCALITYNAME => Some("L"),
        Nid::ORGANIZATIONNAME => Some("O"),
        Nid::ORGANIZATIONALUNITNAME => Some("OU"),
        Nid::PKCS9_EMAILADDRESS => Some("emailAddress"),
        _ => nid.short_name().ok(),
    }
}

fn escape_dn_value(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => vec!['\\', ch],
            _ => vec![ch],
        })
        .collect()
}

fn ipaddress_to_string(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let mut segments = [0u8; 16];
            segments.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(segments)))
        }
        _ => None,
    }
    .map(|ip| ip.to_string())
}

fn registered_values_match(registered: &Value, actual: &[String]) -> bool {
    let registered = json_array_to_strings(registered);
    registered.iter().any(|registered| {
        actual
            .iter()
            .any(|actual| constant_time_eq(registered.as_bytes(), actual.as_bytes()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{
        AuthorizationServerProfile, EmailDelivery, EmailSettings, RateLimitSettings, SubjectType,
    };
    use crate::support::{ClientIpHeaderMode, IpCidr};
    use actix_web::test::TestRequest;

    fn client() -> ClientRow {
        ClientRow {
            id: Uuid::now_v7(),
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "confidential".to_owned(),
            client_secret_argon2_hash: None,
            redirect_uris: json!(["https://client.example/callback"]),
            scopes: json!(["openid"]),
            allowed_audiences: json!(["resource://default"]),
            grant_types: json!(["authorization_code"]),
            token_endpoint_auth_method: "tls_client_auth".to_owned(),
            require_dpop_bound_tokens: false,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: json!([]),
            tls_client_auth_san_uri: json!([]),
            tls_client_auth_san_ip: json!([]),
            tls_client_auth_san_email: json!([]),
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            is_active: true,
            jwks: None,
        }
    }

    fn trusted_proxy_settings() -> Settings {
        Settings {
            issuer: "https://issuer.example".to_owned(),
            mtls_endpoint_base_url: "https://issuer.example".to_owned(),
            frontend_base_url: "https://app.example".to_owned(),
            cors_allowed_origins: vec!["https://app.example".to_owned()],
            default_audience: "resource://default".to_owned(),
            authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
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

        assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
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

        assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
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
            request_mtls_client_certificate_from_headers(&headers)
                .and_then(|certificate| certificate.thumbprint)
                .as_deref(),
            Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8")
        );
    }

    #[test]
    fn client_certificate_matches_registered_subject_dn() {
        let mut client = client();
        client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
        let certificate = MtlsClientCertificate {
            subject_dn: Some("CN=client-1,O=Example".to_owned()),
            ..MtlsClientCertificate::default()
        };

        assert!(client_mtls_certificate_matches(&client, &certificate));
    }

    #[test]
    fn client_certificate_matches_registered_san_dns() {
        let mut client = client();
        client.tls_client_auth_san_dns = json!(["client.example"]);
        let certificate = MtlsClientCertificate {
            san_dns: vec!["api.client.example".to_owned(), "client.example".to_owned()],
            ..MtlsClientCertificate::default()
        };

        assert!(client_mtls_certificate_matches(&client, &certificate));
    }

    #[test]
    fn client_certificate_rejects_unregistered_subject_and_san() {
        let mut client = client();
        client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
        client.tls_client_auth_san_uri = json!(["urn:client:1"]);
        let certificate = MtlsClientCertificate {
            subject_dn: Some("CN=other,O=Example".to_owned()),
            san_uri: vec!["urn:client:2".to_owned()],
            ..MtlsClientCertificate::default()
        };

        assert!(!client_mtls_certificate_matches(&client, &certificate));
    }

    #[test]
    fn self_signed_client_certificate_matches_only_registered_thumbprint() {
        let mut client = client();
        client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
        client.tls_client_auth_subject_dn = Some("CN=client-1,O=Example".to_owned());
        let certificate = MtlsClientCertificate {
            subject_dn: Some("CN=client-1,O=Example".to_owned()),
            ..MtlsClientCertificate::default()
        };

        assert!(!client_mtls_certificate_matches(&client, &certificate));

        client.tls_client_auth_cert_sha256 =
            Some("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".to_owned());
        let certificate = MtlsClientCertificate {
            thumbprint: Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8".to_owned()),
            subject_dn: Some("CN=other,O=Example".to_owned()),
            ..MtlsClientCertificate::default()
        };

        assert!(client_mtls_certificate_matches(&client, &certificate));
    }

    #[test]
    fn rejects_conflicting_forwarded_subject_dn_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("x-ssl-client-verify"),
            HeaderValue::from_static("SUCCESS"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-subject-dn"),
            HeaderValue::from_static("CN=client-1,O=Example"),
        );
        headers.insert(
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            HeaderValue::from_static("CN=client-2,O=Example"),
        );

        assert!(request_mtls_client_certificate_from_headers(&headers).is_none());
    }

    #[test]
    fn extracts_forwarded_subject_dn_and_san_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("x-ssl-client-verify"),
            HeaderValue::from_static("SUCCESS"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-subject-dn"),
            HeaderValue::from_static("CN=client-1,O=Example"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-san-dns"),
            HeaderValue::from_static("client.example, api.client.example"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-san-uri"),
            HeaderValue::from_static("urn:client:1"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-san-ip"),
            HeaderValue::from_static("192.0.2.44"),
        );
        headers.insert(
            header::HeaderName::from_static("x-forwarded-tls-client-cert-san-email"),
            HeaderValue::from_static("client@example.com"),
        );

        let certificate =
            request_mtls_client_certificate_from_headers(&headers).expect("certificate identity");
        assert_eq!(
            certificate.subject_dn.as_deref(),
            Some("CN=client-1,O=Example")
        );
        assert_eq!(
            certificate.san_dns,
            vec!["api.client.example".to_owned(), "client.example".to_owned()]
        );
        assert_eq!(certificate.san_uri, vec!["urn:client:1".to_owned()]);
        assert_eq!(certificate.san_ip, vec!["192.0.2.44".to_owned()]);
        assert_eq!(certificate.san_email, vec!["client@example.com".to_owned()]);
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
