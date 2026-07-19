use actix_web::test::TestRequest;
use nazo_http_actix::{
    ClientIpConfig, ClientIpHeaderMode, IpCidr, client_ip_with_config, parse_forwarded_for_value,
    parse_trusted_proxy_cidrs, request_from_trusted_proxy_cidrs,
};

fn config(mode: ClientIpHeaderMode, trusted: &str) -> ClientIpConfig {
    let cidrs = parse_trusted_proxy_cidrs(Some(trusted.to_owned()))
        .expect("trusted proxy CIDRs should parse");
    ClientIpConfig::new(&cidrs, mode)
}

#[test]
fn cidr_matches_ipv4_and_ipv6() {
    let ipv4 = IpCidr::parse("192.0.2.0/24").unwrap();
    assert!(ipv4.contains("192.0.2.10".parse().unwrap()));
    assert!(!ipv4.contains("198.51.100.10".parse().unwrap()));

    let ipv6 = IpCidr::parse("2001:db8::/32").unwrap();
    assert!(ipv6.contains("2001:db8::1".parse().unwrap()));
    assert!(!ipv6.contains("2001:db9::1".parse().unwrap()));
}

#[test]
fn client_ip_configuration_rejects_unknown_modes_and_invalid_cidrs() {
    assert_eq!(
        ClientIpHeaderMode::parse(" none ").unwrap(),
        ClientIpHeaderMode::None
    );
    assert_eq!(
        ClientIpHeaderMode::parse("FORWARDED").unwrap(),
        ClientIpHeaderMode::Forwarded
    );
    assert_eq!(
        ClientIpHeaderMode::parse("x-forwarded-for").unwrap(),
        ClientIpHeaderMode::XForwardedFor
    );
    assert!(ClientIpHeaderMode::parse("x-real-ip").is_err());
    for value in [
        "192.0.2.0",
        "not-an-ip/24",
        "192.0.2.0/not-a-prefix",
        "192.0.2.0/33",
        "2001:db8::/129",
    ] {
        assert!(IpCidr::parse(value).is_err(), "{value} must be rejected");
    }
}

#[test]
fn forwarded_header_parser_accepts_ip_literals_with_ports() {
    assert_eq!(
        parse_forwarded_for_value(r#""[2001:db8::1]:443""#),
        Some("2001:db8::1".parse().unwrap())
    );
    assert_eq!(
        parse_forwarded_for_value("203.0.113.7:1234"),
        Some("203.0.113.7".parse().unwrap())
    );
}

#[test]
fn forwarded_headers_are_ignored_until_the_socket_peer_is_trusted() {
    let config = config(ClientIpHeaderMode::Forwarded, "192.0.2.0/24");
    let request = TestRequest::default()
        .peer_addr("198.51.100.10:49152".parse().unwrap())
        .insert_header(("forwarded", "for=203.0.113.7"))
        .to_http_request();

    assert_eq!(client_ip_with_config(&request, &config), "198.51.100.10");
    assert!(!request_from_trusted_proxy_cidrs(
        &request,
        &[IpCidr::parse("192.0.2.0/24").unwrap()]
    ));
}

#[test]
fn forwarded_header_uses_the_nearest_untrusted_hop() {
    let config = config(ClientIpHeaderMode::Forwarded, "192.0.2.0/24");
    let request = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header((
            "forwarded",
            "for=198.51.100.77, for=203.0.113.8;proto=https, for=192.0.2.11",
        ))
        .to_http_request();

    assert_eq!(client_ip_with_config(&request, &config), "203.0.113.8");
}

#[test]
fn x_forwarded_for_uses_the_nearest_untrusted_hop() {
    let config = config(
        ClientIpHeaderMode::XForwardedFor,
        "192.0.2.0/24,2001:db8::/32",
    );
    let request = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header((
            "x-forwarded-for",
            "198.51.100.77, 203.0.113.8, 192.0.2.11, 2001:db8::1",
        ))
        .to_http_request();

    assert_eq!(client_ip_with_config(&request, &config), "203.0.113.8");
}

#[test]
fn malformed_proxy_chains_fail_closed_to_the_socket_peer() {
    let xff = config(ClientIpHeaderMode::XForwardedFor, "192.0.2.0/24");
    let request = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("x-forwarded-for", "203.0.113.8, not-an-ip, 192.0.2.11"))
        .to_http_request();
    assert_eq!(client_ip_with_config(&request, &xff), "192.0.2.10");

    let forwarded = config(ClientIpHeaderMode::Forwarded, "192.0.2.0/24");
    let request = TestRequest::default()
        .peer_addr("192.0.2.10:49152".parse().unwrap())
        .insert_header(("forwarded", "for=203.0.113.8, for=_hidden, for=192.0.2.11"))
        .to_http_request();
    assert_eq!(client_ip_with_config(&request, &forwarded), "192.0.2.10");
}

#[test]
fn missing_peer_address_is_unknown() {
    let config = config(ClientIpHeaderMode::XForwardedFor, "192.0.2.0/24");
    let request = TestRequest::default().to_http_request();
    assert_eq!(client_ip_with_config(&request, &config), "unknown");
}

#[test]
fn prefix_zero_cidrs_match_only_their_ip_family() {
    let ipv4 = IpCidr::parse("0.0.0.0/0").unwrap();
    assert!(ipv4.contains("203.0.113.8".parse().unwrap()));
    assert!(!ipv4.contains("2001:db8::1".parse().unwrap()));

    let ipv6 = IpCidr::parse("::/0").unwrap();
    assert!(ipv6.contains("2001:db8::1".parse().unwrap()));
    assert!(!ipv6.contains("203.0.113.8".parse().unwrap()));
}
