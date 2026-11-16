use super::*;
use actix_web::{http::header, test};

#[actix_web::test]
async fn request_host_uses_the_directory_host_canonicalization() {
    for (authority, expected) in [
        ("Tenant-A.Example.:443", "tenant-a.example"),
        ("[2001:0db8::1]:8443", "[2001:db8::1]"),
    ] {
        let request = test::TestRequest::default()
            .insert_header((header::HOST, authority))
            .to_srv_request();
        assert_eq!(
            canonical_request_host(request.head()).as_deref(),
            Some(expected)
        );
    }

    let http2 = test::TestRequest::default()
        .version(actix_web::http::Version::HTTP_2)
        .uri("https://Tenant-B.Example.:8443/token")
        .insert_header((header::HOST, "ignored.example"))
        .to_srv_request();
    assert_eq!(
        canonical_request_host(http2.head()).as_deref(),
        Some("tenant-b.example")
    );

    let userinfo = test::TestRequest::default()
        .insert_header((header::HOST, "ignored@tenant-a.example"))
        .to_srv_request();
    assert_eq!(canonical_request_host(userinfo.head()), None);
}
