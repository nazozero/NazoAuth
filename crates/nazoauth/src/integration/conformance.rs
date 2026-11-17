//! Reusable adapter checks over production NazoAuth routing and presentation.
//!
//! Enable the `conformance` feature in the adapter's development dependency.
//! Transport checks need only the adapter's ordinary conversion functions. The
//! end-to-end check accepts an already-built fixture and a framework test client.
use std::{collections::BTreeMap, future::Future};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};

use super::{ConnectionFacts, Route, routes};
use crate::NazoAuth;

/// One request and its expected resource for every registered method and path,
/// including captures and catch-all tails. Check the canonical lookup against
/// the supplied route and send each request through the production forwarder.
pub fn registration_requests() -> Vec<(&'static Route, Request<Bytes>)> {
    routes()
        .iter()
        .flat_map(|route| {
            let mut path = String::with_capacity(route.path.len());
            let mut tail = route.path;
            while let Some((prefix, capture)) = tail.split_once('{') {
                path.push_str(prefix);
                let (name, remaining) = capture.split_once('}').expect("canonical capture");
                path.push_str(if name.starts_with('*') {
                    "resource/child"
                } else {
                    "00000000-0000-0000-0000-000000000001"
                });
                tail = remaining;
            }
            path.push_str(tail);
            route.methods.iter().map(move |method| {
                (
                    route,
                    Request::builder()
                        .method(method.method.clone())
                        .uri(&path)
                        .body(Bytes::new())
                        .expect("canonical registration request"),
                )
            })
        })
        .collect()
}

/// Inputs whose bytes and repeated values must survive framework conversion.
pub fn transport_requests() -> Vec<Request<Bytes>> {
    let mut raw = Request::builder()
        .method(Method::POST)
        .uri("https://issuer.example/%74oken?state=a%2Fb&state=%252F")
        .header(header::HOST, "issuer.example")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, "Bearer first")
        .header(header::AUTHORIZATION, "Bearer second")
        .header("dpop", "first-proof")
        .header("dpop", "second-proof")
        .body(Bytes::from_static(
            b"grant_type=code&grant_type=refresh_token&value=%2f+%00",
        ))
        .unwrap();
    raw.extensions_mut().insert(ConnectionFacts {
        peer_addr: Some("192.0.2.20:43125".parse().unwrap()),
        ..ConnectionFacts::default()
    });
    vec![
        raw,
        Request::builder()
            .method(Method::PUT)
            .uri("/register/client%2Fone?state=%FF")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Bytes::from_static(b"\0\xff\r\n{\"original\": true }\n"))
            .unwrap(),
    ]
}

/// Actual production presenters generate these responses; the adapter never
/// needs to reconstruct challenges, cache policy, nonce or replay semantics.
pub fn response_cases() -> Vec<(&'static str, Response<Bytes>)> {
    use nazo_auth::DpopError;
    use nazo_oauth_server::contracts::{
        oauth_error::OAuthEndpointError, request_facts::DpopErrorContext,
    };
    use nazo_openid4vci::application::{
        CredentialEndpointResponse, CredentialResponseBody, CredentialResponseStatus,
    };
    let credential = |body| {
        crate::openid4vc::credential_success(CredentialEndpointResponse {
            body,
            status: CredentialResponseStatus::Issued,
            dpop_nonce: Some("fixture-credential-nonce".to_owned()),
        })
    };
    vec![
        (
            "redirect-found",
            crate::http::redirect_found(
                "https://client.example/cb?code=a%2Fb&state=first&state=second".to_owned(),
            ),
        ),
        (
            "redirect-see-other",
            crate::http::redirect_see_other("/ui/profile?completed=true".to_owned()),
        ),
        (
            "basic-challenge",
            crate::http::oauth_endpoint_error_response(OAuthEndpointError::invalid_client(
                "Client authentication failed.",
                true,
            )),
        ),
        (
            "bearer-challenge",
            crate::http::oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Access token expired.",
            ),
        ),
        (
            "dpop-nonce",
            crate::http::oauth_endpoint_error_response(OAuthEndpointError::Dpop {
                error: DpopError::UseNonce("fixture-dpop-nonce".to_owned()),
                context: DpopErrorContext::TokenEndpoint,
            }),
        ),
        (
            "authorization-error",
            crate::http::authorization_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Request is invalid.",
            ),
        ),
        (
            "credential-json-replay",
            credential(CredentialResponseBody::Json(Bytes::from_static(
                b"{\n  \"credentials\" : [ {\"credential\":\"original.bytes\"} ]\n}\n",
            ))),
        ),
        (
            "credential-jwt-replay",
            credential(CredentialResponseBody::Jwt(Bytes::from_static(
                b"original.encrypted.credential.bytes",
            ))),
        ),
        (
            "session-cookies",
            crate::http::with_cookie_headers(
                crate::http::empty_response_no_store(StatusCode::NO_CONTENT),
                &[
                    crate::http::clear_cookie("nazo_session", true),
                    crate::http::clear_cookie("nazo_csrf", true),
                ],
            ),
        ),
    ]
}

/// Assert raw request and transport-fact preservation after framework extraction.
pub fn assert_request(expected: &Request<Bytes>, actual: &Request<Bytes>) {
    assert_eq!(actual.method(), expected.method(), "request method changed");
    assert_eq!(actual.uri(), expected.uri(), "raw request target changed");
    assert_eq!(
        actual.version(),
        expected.version(),
        "request HTTP version changed"
    );
    assert_eq!(
        header_values(actual.headers(), false),
        header_values(expected.headers(), false),
        "request headers changed"
    );
    assert_eq!(actual.body(), expected.body(), "request body bytes changed");
    assert_eq!(
        actual
            .extensions()
            .get::<ConnectionFacts>()
            .cloned()
            .unwrap_or_default(),
        expected
            .extensions()
            .get::<ConnectionFacts>()
            .cloned()
            .unwrap_or_default(),
        "connection facts changed",
    );
}

/// Assert response semantics and original body bytes. Wire-generated Date,
/// Content-Length and Transfer-Encoding may differ; product headers may not.
pub fn assert_response(expected: &Response<Bytes>, actual: &Response<Bytes>) {
    assert_eq!(
        actual.status(),
        expected.status(),
        "response status changed"
    );
    assert_eq!(
        header_values(actual.headers(), true),
        header_values(expected.headers(), true),
        "response headers changed"
    );
    assert_eq!(
        actual.body(),
        expected.body(),
        "response body bytes changed"
    );
}

fn header_values(headers: &HeaderMap, wire: bool) -> BTreeMap<&str, Vec<&[u8]>> {
    let mut values = BTreeMap::<&str, Vec<&[u8]>>::new();
    for (name, value) in headers {
        if wire
            && matches!(
                name.as_str(),
                "date" | "content-length" | "transfer-encoding"
            )
        {
            continue;
        }
        values
            .entry(name.as_str())
            .or_default()
            .push(value.as_bytes());
    }
    values
}

/// Compare an adapter with the real facade using deterministic no-authentication
/// requests. Run with both enabled and disabled optional-module fixtures. A
/// fresh fixture avoids unrelated rate-limit history changing request outcomes.
///
/// The callback sends a standard request through the framework's production
/// registration and returns its response as standard HTTP values.
pub async fn assert_adapter<F, Fut>(application: &NazoAuth, mut send: F)
where
    F: FnMut(Request<Bytes>) -> Fut,
    Fut: Future<Output = Response<Bytes>>,
{
    let mut cases = registration_requests()
        .into_iter()
        .map(|(_, request)| request)
        .collect::<Vec<_>>();
    // Invalid methods exercise every path and guard without running mutations,
    // issuing random challenges or changing a protocol's stored state.
    for request in &mut cases {
        *request.method_mut() = Method::TRACE;
    }
    for (method, target, content_type, body) in [
        (Method::GET, "/not-a-nazoauth-route", "", ""),
        (Method::GET, "/bootstrap-admin", "", ""),
        (Method::OPTIONS, "/auth/mfa/verify", "", ""),
        (
            Method::POST,
            "/token",
            "application/x-www-form-urlencoded",
            "grant_type=code&grant_type=refresh_token",
        ),
        (Method::POST, "/token", "application/json", "{}"),
        (
            Method::POST,
            "/introspect",
            "application/x-www-form-urlencoded",
            "token=first&token=second",
        ),
        (
            Method::POST,
            "/revoke",
            "application/x-www-form-urlencoded",
            "token=first&token=second",
        ),
        (Method::GET, "/userinfo", "", ""),
        (Method::GET, "/.well-known/openid-configuration", "", ""),
        (
            Method::GET,
            "/openid4vci/offers/00000000-0000-0000-0000-000000000001",
            "",
            "",
        ),
        (
            Method::GET,
            "/openid4vp/result/00000000-0000-0000-0000-000000000001",
            "",
            "",
        ),
        (
            Method::POST,
            "/%74oken",
            "application/x-www-form-urlencoded",
            "grant_type=code&grant_type=refresh_token",
        ),
    ] {
        let mut request = Request::builder().method(method).uri(target);
        if !content_type.is_empty() {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        cases.push(request.body(Bytes::from_static(body.as_bytes())).unwrap());
    }
    // Compare the complete input with adapters that use the declared metadata
    // head projection, including repeated CORS fields and rejected methods.
    for target in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/",
        "/.well-known/oauth-protected-resource/api/child",
        "/jwks.json",
    ] {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::POST] {
            for origin in [
                None,
                Some("https://browser.example"),
                Some("https://unregistered.example"),
            ] {
                let mut request = Request::builder()
                    .method(method.clone())
                    .uri(target)
                    .header(header::HOST, "issuer.example")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header("forwarded", "for=192.0.2.10;host=untrusted.example")
                    .header("client-cert", "untrusted")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "HEAD")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "accept")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization");
                if let Some(origin) = origin {
                    request = request
                        .header(header::ORIGIN, origin)
                        .header(header::ORIGIN, "https://second.example");
                }
                cases.push(
                    request
                        .body(Bytes::from_static(b"ignored metadata body"))
                        .unwrap(),
                );
            }
        }
    }
    for mut request in cases {
        request.extensions_mut().insert(ConnectionFacts {
            peer_addr: Some("192.0.2.20:43125".parse().unwrap()),
            ..ConnectionFacts::default()
        });
        let expected = application.handle(request.clone()).await;
        let actual = send(request).await;
        assert_response(&expected, &actual);
    }
}
