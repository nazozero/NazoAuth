from pathlib import Path


def replace(path, old, new):
    p = Path(path)
    source = p.read_text()
    assert source.count(old) == 1, (path, old)
    p.write_text(source.replace(old, new))


replace('crates/server/src/bootstrap/startup/services/factory.rs',
        'use actix_web::{App, Error, HttpResponse, HttpServer, web};',
        'use actix_web::{App, Error, HttpServer, web};')
replace('crates/server/tests/unit/bootstrap/startup/services/factory.rs',
        'assert_eq!(response.headers().get(name), Some(value));',
        'assert_eq!(response.headers().get(name.as_str()).map(|value| value.as_bytes()), Some(value.as_bytes()));')
replace('crates/server/tests/unit/bootstrap.rs',
        'assert_eq!(headers.get(name), Some(value));',
        'assert_eq!(headers.get(name.as_str()).map(|value| value.as_bytes()), Some(value.as_bytes()));')

# A pure conversion test covers every version independently of listener features.
p = Path('crates/http-actix/tests/unit/transport.rs')
p.write_text(p.read_text() + '''

#[test]
fn metadata_version_conversion_preserves_all_supported_versions() {
    use actix_web::http::Version;
    for (native, standard) in [
        (Version::HTTP_09, http::Version::HTTP_09),
        (Version::HTTP_10, http::Version::HTTP_10),
        (Version::HTTP_11, http::Version::HTTP_11),
        (Version::HTTP_2, http::Version::HTTP_2),
        (Version::HTTP_3, http::Version::HTTP_3),
    ] {
        let request = awtest::TestRequest::default().version(native).to_http_request();
        assert_eq!(forward_request(&request, Bytes::new()).version(), standard);
    }
}
''')
