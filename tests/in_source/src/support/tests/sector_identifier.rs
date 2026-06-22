use super::{
    SectorIdentifierError, fetch_sector_identifier_uris, is_blocked_host, is_blocked_ip,
    sector_identifier_hostname,
};
use std::net::IpAddr;

#[test]
fn block_private_ipv4() {
    assert!(is_blocked_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("172.16.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("169.254.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_loopback_ipv4() {
    assert!(is_blocked_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("127.0.0.2".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_metadata_ip() {
    assert!(is_blocked_ip("169.254.169.254".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_unspecified() {
    assert!(is_blocked_ip("0.0.0.0".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("::".parse::<IpAddr>().unwrap()));
}

#[test]
fn allow_public_ipv4() {
    assert!(!is_blocked_ip("8.8.8.8".parse::<IpAddr>().unwrap()));
    assert!(!is_blocked_ip("93.184.216.34".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_loopback_ipv6() {
    assert!(is_blocked_ip("::1".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_link_local_ipv6() {
    assert!(is_blocked_ip("fe80::1".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_unique_local_ipv6() {
    assert!(is_blocked_ip("fc00::1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("fd00::1".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_localhost_domain() {
    assert!(is_blocked_host("localhost"));
}

#[test]
fn block_127_domain() {
    assert!(is_blocked_host("127.0.0.1"));
}

#[test]
fn allow_public_domain() {
    assert!(!is_blocked_host("example.com"));
    assert!(!is_blocked_host("2001:4860:4860::8888"));
}

#[test]
fn hostname_from_uri() {
    assert_eq!(
        sector_identifier_hostname("https://example.com/.well-known/sector").unwrap(),
        "example.com"
    );
}

#[test]
fn hostname_rejects_invalid_uri() {
    assert!(sector_identifier_hostname("not-a-uri").is_err());
}

#[test]
fn hostname_from_uri_with_empty_authority() {
    assert_eq!(sector_identifier_hostname("https:///path").unwrap(), "path");
}

#[test]
fn block_ipv6_multicast_and_mapped_unspecified() {
    assert!(is_blocked_ip("ff02::1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("::ffff:0.0.0.0".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_literal_private_hosts() {
    assert!(is_blocked_host("0.0.0.0"));
    assert!(is_blocked_host("::1"));
    assert!(is_blocked_host("::"));
}

#[actix_web::test]
async fn fetch_rejects_invalid_sector_identifier_uri_before_network() {
    let err = fetch_sector_identifier_uris("not-a-uri")
        .await
        .expect_err("invalid URI must fail before DNS or HTTP");

    assert!(matches!(err, SectorIdentifierError::InvalidUri));
}

#[actix_web::test]
async fn fetch_rejects_non_https_sector_identifier_uri() {
    let err = fetch_sector_identifier_uris("http://example.com/sector.json")
        .await
        .expect_err("sector_identifier_uri must be HTTPS");

    assert!(matches!(err, SectorIdentifierError::SchemeNotHttps));
}

#[actix_web::test]
async fn fetch_rejects_loopback_sector_identifier_uri_before_dns() {
    let err = fetch_sector_identifier_uris("https://127.0.0.1/sector.json")
        .await
        .expect_err("loopback sector_identifier_uri must be blocked before DNS");

    assert!(matches!(err, SectorIdentifierError::BlockedHost));
}
