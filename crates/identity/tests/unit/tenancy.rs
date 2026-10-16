use super::{canonical_tenant_host, tenant_host_from_issuer};

#[test]
fn tenant_host_has_one_canonical_form() {
    assert_eq!(
        canonical_tenant_host(" Auth.Example. ").expect("DNS host should canonicalize"),
        "auth.example"
    );
    assert_eq!(
        canonical_tenant_host("[2001:db8::1]").expect("IPv6 host should canonicalize"),
        "[2001:db8::1]"
    );
    assert!(canonical_tenant_host("auth.example:443").is_err());
    assert!(canonical_tenant_host("https://auth.example").is_err());
}

#[test]
fn tenant_host_matches_the_validated_issuer_host_for_dns_and_ip_addresses() {
    for (host, expected) in [
        ("Auth.Example.", "auth.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("127.0.0.1", "127.0.0.1"),
        ("[2001:0DB8:0:0:0:0:0:1]", "[2001:db8::1]"),
    ] {
        let issuer = url::Url::parse(&format!("https://{host}:8443/issuer")).unwrap();
        assert_eq!(canonical_tenant_host(host).unwrap(), expected);
        assert_eq!(tenant_host_from_issuer(&issuer).unwrap(), expected);
    }
}

#[test]
fn tenant_host_rejects_url_components_and_empty_domains() {
    for host in [
        "",
        " ",
        ".",
        "...",
        "auth.example:443",
        "[::1]:443",
        "user@auth.example",
        "auth.example/path",
        "auth.example?query",
        "auth.example#fragment",
        "auth.example\\path",
        "auth\t.example",
    ] {
        assert!(canonical_tenant_host(host).is_err(), "accepted {host:?}");
    }
    assert_eq!(
        canonical_tenant_host("auth.example\t").unwrap(),
        "auth.example"
    );
    assert!(tenant_host_from_issuer(&url::Url::parse("https://.").unwrap()).is_err());
}
