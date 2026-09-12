//! Certificate identity, PKI trust, and registered client matching policy.
use crate::{
    contracts::token_client_auth::ClientCertificateFacts, crypto::constant_time_eq,
    domain::rows::ClientRow,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nazo_auth::normalize_sha256_thumbprint;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use x509_parser::{
    certificate::X509Certificate,
    extensions::GeneralName,
    objects::{oid_registry, oid2sn},
    oid_registry::{
        OID_PKCS9_EMAIL_ADDRESS, OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME,
        OID_X509_LOCALITY_NAME, OID_X509_ORGANIZATION_NAME, OID_X509_ORGANIZATIONAL_UNIT,
        OID_X509_STATE_OR_PROVINCE_NAME,
    },
    parse_x509_certificate,
    x509::X509Name,
};
pub fn certificate_der_identity(der: &[u8]) -> Option<ClientCertificateFacts> {
    let x509 = parse_current_x509(der)?;
    let mut certificate = ClientCertificateFacts {
        thumbprint: Some(URL_SAFE_NO_PAD.encode(Sha256::digest(der))),
        subject_dn: Some(subject_name_to_dn(x509.subject())?),
        verified_certificate_expiry: true,
        certificate_chain_der: vec![der.to_vec()],
        ..ClientCertificateFacts::default()
    };
    if let Some(names) = x509.subject_alternative_name().ok().flatten() {
        for name in &names.value.general_names {
            match name {
                GeneralName::DNSName(value) => certificate.san_dns.push((*value).to_owned()),
                GeneralName::URI(value) => certificate.san_uri.push((*value).to_owned()),
                GeneralName::RFC822Name(value) => certificate.san_email.push((*value).to_owned()),
                GeneralName::IPAddress(value) => {
                    if let Some(value) = ipaddress_to_string(value) {
                        certificate.san_ip.push(value);
                    }
                }
                _ => {}
            }
        }
    }
    certificate.san_dns = sorted_unique(certificate.san_dns);
    certificate.san_uri = sorted_unique(certificate.san_uri);
    certificate.san_ip = sorted_unique(certificate.san_ip);
    certificate.san_email = sorted_unique(certificate.san_email);
    Some(certificate)
}

/// PKI authentication consumes the tenant's currently approved trust anchors.
/// Revocation therefore takes effect on existing TLS connections as well.
pub fn certificate_chain_trusted(certificate: &ClientCertificateFacts, anchors: &str) -> bool {
    use rustls::{
        RootCertStore,
        pki_types::{CertificateDer, pem::PemObject},
    };

    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(anchors.as_bytes()) {
        let Ok(certificate) = certificate else {
            return false;
        };
        if roots.add(certificate).is_err() {
            return false;
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let Ok(verifier) = rustls::server::WebPkiClientVerifier::builder_with_provider(
        std::sync::Arc::new(roots),
        provider,
    )
    .build() else {
        return false;
    };
    certificate_chain_verified(certificate, verifier.as_ref())
}

pub fn certificate_chain_verified(
    certificate: &ClientCertificateFacts,
    verifier: &dyn rustls::server::danger::ClientCertVerifier,
) -> bool {
    use rustls::pki_types::{CertificateDer, UnixTime};
    let chain = certificate
        .certificate_chain_der
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect::<Vec<_>>();
    let Some((leaf, intermediates)) = chain.split_first() else {
        return false;
    };
    verifier
        .verify_client_cert(leaf, intermediates, UnixTime::now())
        .is_ok()
}

pub fn certificate_x5c_thumbprint(value: &str) -> Option<String> {
    let der = STANDARD
        .decode(
            value
                .chars()
                .filter(|ch| !ch.is_ascii_whitespace())
                .collect::<String>(),
        )
        .ok()?;
    parse_current_x509(&der)?;
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(&der)))
}

pub fn client_mtls_thumbprint_matches(client: &ClientRow, thumbprint: &str) -> bool {
    client
        .tls_client_auth_cert_sha256
        .as_deref()
        .and_then(normalize_sha256_thumbprint)
        .is_some_and(|registered| constant_time_eq(registered.as_bytes(), thumbprint.as_bytes()))
}

pub fn client_mtls_certificate_matches(
    client: &ClientRow,
    certificate: &ClientCertificateFacts,
) -> bool {
    if client.token_endpoint_auth_method == "self_signed_tls_client_auth" {
        return client_self_signed_mtls_certificate_matches(client, certificate);
    }
    let selector_count = usize::from(client.tls_client_auth_subject_dn.is_some())
        + client.tls_client_auth_san_dns.len()
        + client.tls_client_auth_san_uri.len()
        + client.tls_client_auth_san_ip.len()
        + client.tls_client_auth_san_email.len();
    if selector_count != 1 {
        // RFC 8705 requires one and only one PKI subject selector. Fail closed
        // for rows missing configured identity constraints instead of widening the match.
        return false;
    }
    let standard_subject_matches = if let (Some(registered), Some(actual)) = (
        client.tls_client_auth_subject_dn.as_deref(),
        certificate.subject_dn.as_deref(),
    ) {
        nazo_key_management::rfc4514_dn_matches(registered, actual)
    } else if !client.tls_client_auth_san_dns.is_empty() {
        registered_dns_values_match(&client.tls_client_auth_san_dns, &certificate.san_dns)
    } else if !client.tls_client_auth_san_uri.is_empty() {
        registered_values_match(&client.tls_client_auth_san_uri, &certificate.san_uri)
    } else if !client.tls_client_auth_san_ip.is_empty() {
        registered_ip_values_match(&client.tls_client_auth_san_ip, &certificate.san_ip)
    } else if !client.tls_client_auth_san_email.is_empty() {
        registered_email_values_match(&client.tls_client_auth_san_email, &certificate.san_email)
    } else {
        false
    };
    if !standard_subject_matches {
        return false;
    }
    // The SHA-256 field is an administrator-only extra pin, not RFC 8705
    // registration metadata. When present it narrows the standard subject
    // match and never acts as an alternative identity selector.
    match (
        client.tls_client_auth_cert_sha256.as_deref(),
        certificate.thumbprint.as_deref(),
    ) {
        (None, _) => true,
        (Some(_), Some(thumbprint)) => client_mtls_thumbprint_matches(client, thumbprint),
        (Some(_), None) => false,
    }
}

pub fn client_self_signed_mtls_certificate_matches(
    client: &ClientRow,
    certificate: &ClientCertificateFacts,
) -> bool {
    let Some(thumbprint) = certificate.thumbprint.as_deref() else {
        return false;
    };
    if client
        .jwks
        .as_ref()
        .is_some_and(|jwks| jwks_contains_current_x5c_thumbprint(jwks, thumbprint))
    {
        return true;
    }
    false
}

pub fn jwks_contains_current_x5c_thumbprint(jwks: &Value, thumbprint: &str) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter()
                .filter_map(|key| key.get("x5c").and_then(Value::as_array))
                .filter_map(|x5c| x5c.as_slice().first().and_then(Value::as_str))
                .filter_map(certificate_x5c_thumbprint)
                .any(|registered| constant_time_eq(registered.as_bytes(), thumbprint.as_bytes()))
        })
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn x509_is_current(x509: &X509Certificate<'_>) -> Option<()> {
    x509.validity().is_valid().then_some(())
}

fn parse_current_x509(der: &[u8]) -> Option<X509Certificate<'_>> {
    let (remaining, certificate) = parse_x509_certificate(der).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    x509_is_current(&certificate)?;
    Some(certificate)
}

fn subject_name_to_dn(name: &X509Name<'_>) -> Option<String> {
    let mut parts = Vec::new();
    for entry in name.iter_attributes() {
        let oid = entry.attr_type();
        let short_name = if oid == &OID_X509_COMMON_NAME {
            "CN"
        } else if oid == &OID_X509_COUNTRY_NAME {
            "C"
        } else if oid == &OID_X509_STATE_OR_PROVINCE_NAME {
            "ST"
        } else if oid == &OID_X509_LOCALITY_NAME {
            "L"
        } else if oid == &OID_X509_ORGANIZATION_NAME {
            "O"
        } else if oid == &OID_X509_ORGANIZATIONAL_UNIT {
            "OU"
        } else if oid == &OID_PKCS9_EMAIL_ADDRESS {
            "emailAddress"
        } else {
            oid2sn(oid, oid_registry()).ok()?
        };
        let value = entry.as_str().ok()?;
        parts.push(format!("{short_name}={}", escape_dn_value(value)));
    }
    (!parts.is_empty()).then(|| parts.join(","))
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

fn registered_values_match(registered: &[String], actual: &[String]) -> bool {
    registered.iter().any(|registered| {
        actual
            .iter()
            .any(|actual| constant_time_eq(registered.as_bytes(), actual.as_bytes()))
    })
}

fn registered_dns_values_match(registered: &[String], actual: &[String]) -> bool {
    registered.iter().any(|registered| {
        actual
            .iter()
            .any(|actual| registered.eq_ignore_ascii_case(actual))
    })
}

fn registered_ip_values_match(registered: &[String], actual: &[String]) -> bool {
    registered.iter().any(|registered| {
        let Ok(registered) = registered.parse::<IpAddr>() else {
            return false;
        };
        actual
            .iter()
            .filter_map(|actual| actual.parse::<IpAddr>().ok())
            .any(|actual| actual == registered)
    })
}

fn registered_email_values_match(registered: &[String], actual: &[String]) -> bool {
    registered.iter().any(|registered| {
        let Some((registered_local, registered_domain)) = registered.rsplit_once('@') else {
            return false;
        };
        actual.iter().any(|actual| {
            let Some((actual_local, actual_domain)) = actual.rsplit_once('@') else {
                return false;
            };
            constant_time_eq(registered_local.as_bytes(), actual_local.as_bytes())
                && registered_domain.eq_ignore_ascii_case(actual_domain)
        })
    })
}

#[cfg(test)]
#[path = "../../tests/unit/security/mtls.rs"]
mod tests;
