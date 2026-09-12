use super::{
    SectorIdentifierError, is_blocked_host, is_blocked_ip, parse_sector_identifier_document,
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
fn block_non_global_ipv4_destinations() {
    for address in [
        "100.64.0.1",
        "100.127.255.254",
        "198.18.0.1",
        "198.19.255.254",
        "192.0.2.1",
        "255.255.255.255",
    ] {
        assert!(
            is_blocked_ip(address.parse::<IpAddr>().unwrap()),
            "{address} must not be an outbound destination"
        );
    }
}

#[test]
fn allow_globally_reachable_special_purpose_ipv4_destinations() {
    for address in ["192.0.0.9", "192.0.0.10"] {
        assert!(
            !is_blocked_ip(address.parse::<IpAddr>().unwrap()),
            "{address} is designated globally reachable"
        );
    }
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
fn block_non_global_ipv6_destinations() {
    for address in ["100::1", "2001:db8::1"] {
        assert!(
            is_blocked_ip(address.parse::<IpAddr>().unwrap()),
            "{address} must not be an outbound destination"
        );
    }
}

#[test]
fn allow_globally_reachable_special_purpose_ipv6_destinations() {
    for address in [
        "64:ff9b::808:808",
        "2001:1::1",
        "2001:1::2",
        "2001:1::3",
        "2001:3::1",
        "2001:4:112::1",
        "2001:20::1",
        "2001:30::1",
    ] {
        assert!(
            !is_blocked_ip(address.parse::<IpAddr>().unwrap()),
            "{address} is designated globally reachable"
        );
    }
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
fn block_ipv6_multicast_and_mapped_unspecified() {
    assert!(is_blocked_ip("ff02::1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("::ffff:0.0.0.0".parse::<IpAddr>().unwrap()));
}

#[test]
fn block_ipv6_mapped_unspecified_without_ipv4_text() {
    assert!(is_blocked_ip("::ffff:0:0".parse::<IpAddr>().unwrap()));
}

#[test]
fn ipv4_mapped_ipv6_uses_the_ipv4_network_policy() {
    assert!(is_blocked_ip("::ffff:127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip("::ffff:10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_blocked_ip(
        "::ffff:169.254.169.254".parse::<IpAddr>().unwrap()
    ));
    assert!(!is_blocked_ip(
        "::ffff:93.184.216.34".parse::<IpAddr>().unwrap()
    ));
}

#[test]
fn block_literal_private_hosts() {
    assert!(is_blocked_host("0.0.0.0"));
    assert!(is_blocked_host("::1"));
    assert!(is_blocked_host("::"));
}

#[test]
fn parse_sector_identifier_document_accepts_json_content_type_with_parameters() {
    let uris = parse_sector_identifier_document(
        "application/json; charset=utf-8",
        br#"["https://client.example/callback","https://client.example/alt"]"#,
    )
    .expect("valid sector identifier document should parse");

    assert_eq!(
        uris,
        vec![
            "https://client.example/callback".to_owned(),
            "https://client.example/alt".to_owned()
        ]
    );
}

#[test]
fn parse_sector_identifier_document_rejects_non_json_content_type() {
    let err = parse_sector_identifier_document("text/plain", br#"[]"#)
        .expect_err("sector identifier document must be JSON");

    assert!(matches!(err, SectorIdentifierError::InvalidContentType));
}

#[test]
fn parse_sector_identifier_document_rejects_jsonp_content_type() {
    let err = parse_sector_identifier_document("application/jsonp", br#"[]"#)
        .expect_err("sector identifier documents must use application/json");

    assert!(matches!(err, SectorIdentifierError::InvalidContentType));
}

#[test]
fn parse_sector_identifier_document_rejects_oversized_body_before_json_parse() {
    let body = vec![b' '; 128 * 1024 + 1];
    let err = parse_sector_identifier_document("application/json", &body)
        .expect_err("oversized sector identifier document must be rejected");

    assert!(matches!(err, SectorIdentifierError::ResponseTooLarge));
}

#[test]
fn parse_sector_identifier_document_rejects_invalid_json() {
    let err = parse_sector_identifier_document("application/json", br#"{"redirect_uris":[]}"#)
        .expect_err("sector identifier document must be a JSON array");

    assert!(matches!(err, SectorIdentifierError::InvalidJson));
}

#[test]
fn parse_sector_identifier_document_rejects_invalid_uri_entry() {
    let err = parse_sector_identifier_document("application/json", br#"["not a uri"]"#)
        .expect_err("sector identifier entries must be absolute URIs");

    assert!(matches!(err, SectorIdentifierError::InvalidEntry(entry) if entry == "not a uri"));
}
