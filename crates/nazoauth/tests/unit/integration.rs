use super::{request_authority, valid_host_header};
use http::{Request, Version, header::HOST};

#[test]
fn http2_compares_optional_host_after_normalization_and_retains_original_authority() {
    for (target, host, accepted) in [
        ("https://issuer.example/token", None, true),
        ("https://issuer.example/token", Some("issuer.example"), true),
        ("https://ISSUER.example/token", Some("issuer.example"), true),
        (
            "https://issuer.example/token",
            Some("issuer.example:443"),
            true,
        ),
        (
            "https://issuer.example:443/token",
            Some("issuer.example"),
            true,
        ),
        (
            "https://issuer.example/token",
            Some("issuer.example:"),
            true,
        ),
        (
            "http://issuer.example/token",
            Some("issuer.example:80"),
            true,
        ),
        (
            "https://issuer.example/token",
            Some("%69ssuer.example:443"),
            true,
        ),
        (
            "https://[2001:db8::1]/token",
            Some("[2001:0db8:0:0:0:0:0:1]:443"),
            true,
        ),
        ("https://issuer.example/token", Some("other.example"), false),
        (
            "https://issuer.example/token",
            Some("issuer.example:8443"),
            false,
        ),
        (
            "https://issuer.example:8443/token",
            Some("issuer.example"),
            false,
        ),
        (
            "https://issuer.example/token",
            Some("issuer.example:80"),
            false,
        ),
        (
            "https://issuer.example/token",
            Some("user@issuer.example"),
            false,
        ),
        ("https://issuer.example/token", Some(""), false),
        ("/token", Some("issuer.example"), false),
        ("https://:443/token", None, false),
    ] {
        let mut builder = Request::builder().version(Version::HTTP_2).uri(target);
        if let Some(host) = host {
            builder = builder.header(HOST, host);
        }
        let request = builder.body(()).unwrap();
        let actual = request_authority(&request);
        assert_eq!(actual.is_some(), accepted, "{target}, Host={host:?}");
        if accepted {
            let original = request.uri().authority().unwrap().as_str();
            assert_eq!(actual.unwrap().as_ptr(), original.as_ptr());
        }
    }
}

#[test]
fn http3_allows_host_only_and_requires_identical_values_when_both_are_present() {
    for (target, host, expected) in [
        ("/token", Some("issuer.example"), Some("issuer.example")),
        ("/token", None, None),
        ("/token", Some(""), None),
        ("/token", Some(":443"), None),
        ("/token", Some("issuer.example:bad"), None),
        ("https://issuer.example/token", None, Some("issuer.example")),
        (
            "https://issuer.example/token",
            Some("issuer.example"),
            Some("issuer.example"),
        ),
        ("https://issuer.example/token", Some("other.example"), None),
        ("https://issuer.example/token", Some("ISSUER.example"), None),
        (
            "https://issuer.example/token",
            Some("issuer.example:443"),
            None,
        ),
        (
            "https://issuer.example/token",
            Some("issuer.example:8443"),
            None,
        ),
        ("https://issuer.example/token", Some(""), None),
    ] {
        let mut builder = Request::builder().version(Version::HTTP_3).uri(target);
        if let Some(host) = host {
            builder = builder.header(HOST, host);
        }
        let request = builder.body(()).unwrap();
        assert_eq!(
            request_authority(&request),
            expected,
            "{target}, Host={host:?}"
        );
    }
    for version in [Version::HTTP_2, Version::HTTP_3] {
        let request = Request::builder()
            .version(version)
            .uri("https://issuer.example/token")
            .header(HOST, "issuer.example")
            .header(HOST, "issuer.example")
            .body(())
            .unwrap();
        assert_eq!(request_authority(&request), None);
    }
}

#[test]
fn host_header_grammar_accepts_uri_hosts_without_dns_normalization() {
    for value in [
        "",
        "issuer.example",
        "Tenant-A.Example.:443",
        "issuer.example:",
        "127.0.0.1:8000",
        "[2001:db8::1]:8443",
        "[::1]:",
        "[v1.future:host]:443",
        "uri%2Dname.example",
        "reg_name!$&'()*+,;=.example",
    ] {
        assert!(valid_host_header(value), "rejected valid Host {value:?}");
    }
    for value in [
        "issuer.example:abc",
        "issuer.example:80:90",
        "user@issuer.example",
        "issuer.example/path",
        "issuer.example?query",
        "issuer.example#fragment",
        "issuer.example\\path",
        "issuer.example other.example",
        "issuer.example\t",
        "名.example",
        "bad%.example",
        "bad%0.example",
        "bad%2x.example",
        "::1",
        "[::1",
        "[::1]suffix",
        "[invalid]:443",
        "[v.future]:443",
        "[v1.]:443",
        "[v1.bad%20host]:443",
    ] {
        assert!(!valid_host_header(value), "accepted invalid Host {value:?}");
    }
}
