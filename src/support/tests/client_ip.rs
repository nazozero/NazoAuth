use super::*;

#[test]
fn cidr_matches_ipv4_and_ipv6() {
    let cidr = IpCidr::parse("192.0.2.0/24").unwrap();
    assert!(cidr.contains("192.0.2.10".parse().unwrap()));
    assert!(!cidr.contains("198.51.100.10".parse().unwrap()));

    let cidr = IpCidr::parse("2001:db8::/32").unwrap();
    assert!(cidr.contains("2001:db8::1".parse().unwrap()));
    assert!(!cidr.contains("2001:db9::1".parse().unwrap()));
}

#[test]
fn forwarded_header_parses_basic_rfc7239_values() {
    assert_eq!(
        parse_forwarded_for_value(r#""[2001:db8::1]:443""#),
        Some("2001:db8::1".parse().unwrap())
    );
    assert_eq!(
        parse_forwarded_for_value("203.0.113.7:1234"),
        Some("203.0.113.7".parse().unwrap())
    );
}
