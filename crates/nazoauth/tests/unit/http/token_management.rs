use crate::http::Request;
use bytes::Bytes;
use http::{StatusCode, header};
use serde_json::Value;
use std::{future::Future, pin::Pin, sync::Arc};

use nazo_auth::TokenInspection;
use nazo_oauth_server::contracts::{
    token_client_auth::TokenClientAuthTransportFacts,
    token_forms::TokenOnlyForm,
    token_management::{
        TokenIntrospectionRepresentation, TokenManagementError, TokenManagementFuture,
        TokenManagementOperations, TokenManagementRateLimitError, TokenManagementRequestFacts,
        TokenManagementRequestGuard,
    },
};

use super::*;

#[derive(Clone, Copy)]
struct FakeRequestFacts;

impl TokenManagementRequestFactsExtractor for FakeRequestFacts {
    fn extract(&self, request: &Request) -> TokenManagementRequestFacts {
        TokenManagementRequestFacts {
            source_ip: "127.0.0.1".to_owned(),
            endpoint_path: request.uri().path().to_owned(),
            client_certificate: None,
        }
    }
}

#[derive(Clone, Copy)]
struct PanicCertificateFacts;

impl TokenManagementRequestFactsExtractor for PanicCertificateFacts {
    fn extract(&self, request: &Request) -> TokenManagementRequestFacts {
        FakeRequestFacts.extract(request)
    }

    fn extract_client_certificate(&self, _request: &Request) -> Option<ClientCertificateFacts> {
        panic!("certificate parsing must not run before cheap request rejection")
    }
}

#[derive(Clone, Copy)]
struct FakeGuard(Result<(), TokenManagementRateLimitError>);

impl TokenManagementRequestGuard for FakeGuard {
    fn enforce<'a>(
        &'a self,
        _request: &'a TokenManagementRequestFacts,
    ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>> {
        let result = self.0;
        Box::pin(async move { result })
    }
}

#[derive(Clone)]
struct FakeOperations {
    introspection: Result<TokenIntrospectionRepresentation, TokenManagementError>,
    revocation: Result<(), TokenManagementError>,
}

impl TokenManagementOperations for FakeOperations {
    fn introspect<'a>(
        &'a self,
        _request: TokenManagementRequestFacts,
        _client_auth: TokenClientAuthTransportFacts,
        _form: TokenOnlyForm,
        _signed_response_requested: bool,
    ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation> {
        let result = self.introspection.clone();
        Box::pin(async move { result })
    }

    fn revoke<'a>(
        &'a self,
        _request: TokenManagementRequestFacts,
        _client_auth: TokenClientAuthTransportFacts,
        _form: TokenOnlyForm,
    ) -> TokenManagementFuture<'a, ()> {
        let result = self.revocation;
        Box::pin(async move { result })
    }
}

fn endpoint(
    guard: Result<(), TokenManagementRateLimitError>,
    introspection: Result<TokenIntrospectionRepresentation, TokenManagementError>,
    revocation: Result<(), TokenManagementError>,
) -> TokenManagementEndpoint {
    endpoint_with_request_facts(Arc::new(FakeRequestFacts), guard, introspection, revocation)
}

fn endpoint_with_request_facts(
    request_facts: Arc<dyn TokenManagementRequestFactsExtractor>,
    guard: Result<(), TokenManagementRateLimitError>,
    introspection: Result<TokenIntrospectionRepresentation, TokenManagementError>,
    revocation: Result<(), TokenManagementError>,
) -> TokenManagementEndpoint {
    TokenManagementEndpoint::new(
        request_facts,
        Arc::new(FakeGuard(guard)),
        Arc::new(FakeOperations {
            introspection,
            revocation,
        }),
    )
}

#[test]
fn expensive_certificate_parsing_happens_after_rate_and_form_rejection() {
    futures_executor::block_on(async {
        let limited = endpoint_with_request_facts(
            Arc::new(PanicCertificateFacts),
            Err(TokenManagementRateLimitError::Limited {
                retry_after_seconds: 30,
            }),
            Ok(TokenIntrospectionRepresentation::Inspection(
                TokenInspection::Inactive,
            )),
            Ok(()),
        );
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/introspect")
                .body(Bytes::from("not-a-form"))
                .unwrap();
            introspect(&limited, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let malformed = endpoint_with_request_facts(
            Arc::new(PanicCertificateFacts),
            Ok(()),
            Ok(TokenIntrospectionRepresentation::Inspection(
                TokenInspection::Inactive,
            )),
            Ok(()),
        );
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/introspect")
                .body(Bytes::from("not-a-form"))
                .unwrap();
            introspect(&malformed, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    });
}

fn form_request(method: &'static str, path: &'static str) -> http::request::Builder {
    let request = match method {
        "POST" => http::Request::builder().method("POST"),
        _ => unreachable!("only POST is used"),
    };
    request
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
}

fn assert_security_headers(headers: &header::HeaderMap) {
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("permissions-policy").unwrap(),
        "interest-cohort=()"
    );
    assert_eq!(
        headers.get("strict-transport-security").unwrap(),
        "max-age=31536000"
    );
    assert_eq!(
        headers.get("content-security-policy").unwrap(),
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    );
}

#[test]
fn revocation_route_locks_post_get_options_cors_and_security_contracts() {
    futures_executor::block_on(async {
        let allowed_origin = "https://client.example";
        let service = endpoint(
            Ok(()),
            Ok(TokenIntrospectionRepresentation::Inspection(
                TokenInspection::Inactive,
            )),
            Ok(()),
        );

        let post = {
            let request = form_request("POST", "/revoke")
                .header(header::ORIGIN, allowed_origin)
                .body(Bytes::from_static(b"token=opaque&client_id=client"))
                .unwrap();
            let mut response = revoke(&service, &request, request.body()).await;
            crate::http::apply_cors_headers(
                crate::http::CorsPolicy::BrowserTokenManagement,
                &request,
                &[allowed_origin.to_owned()],
                response.headers_mut(),
            );
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(post.status(), StatusCode::OK);
        assert_eq!(
            post.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(post.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            post.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            allowed_origin
        );
        assert!(post.headers().get(header::CONTENT_TYPE).is_none());
        assert_security_headers(post.headers());
        assert!(post.into_body().is_empty());

        let get = {
            let request = http::Request::builder()
                .uri("/revoke")
                .body(Bytes::new())
                .unwrap();
            let mut response =
                crate::routes::resolve(request.method(), request.uri().path()).unwrap_err();
            crate::http::apply_cors_headers(
                crate::http::CorsPolicy::BrowserTokenManagement,
                &request,
                &[allowed_origin.to_owned()],
                response.headers_mut(),
            );
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(get.headers().get(header::CONTENT_TYPE).is_none());
        assert_security_headers(get.headers());
        assert!(get.into_body().is_empty());

        let options = {
            let request = http::Request::builder()
                .method(http::Method::OPTIONS)
                .uri("/revoke")
                .header(header::ORIGIN, allowed_origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization, content-type, dpop",
                )
                .body(Bytes::new())
                .unwrap();
            let mut response = crate::http::cors_preflight(
                crate::http::CorsPolicy::BrowserTokenManagement,
                &request,
                &[allowed_origin.to_owned()],
            )
            .unwrap();
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(options.status(), StatusCode::OK);
        assert_eq!(
            options
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            allowed_origin
        );
        let methods = options
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(methods.split(',').any(|method| method.trim() == "POST"));
        assert!(options.headers().get(header::CONTENT_TYPE).is_none());
        assert_security_headers(options.headers());
        assert!(options.into_body().is_empty());
    });
}

#[test]
fn introspection_route_has_no_browser_cors_and_rejects_get_and_options() {
    futures_executor::block_on(async {
        for request in [
            http::Request::builder()
                .uri("/introspect")
                .body(Bytes::new())
                .unwrap(),
            http::Request::builder()
                .method(http::Method::OPTIONS)
                .uri("/introspect")
                .header(header::ORIGIN, "https://client.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Bytes::new())
                .unwrap(),
        ] {
            let response = {
                let request = request;
                let mut response =
                    crate::routes::resolve(request.method(), request.uri().path()).unwrap_err();
                crate::http::apply_security_headers(response.headers_mut(), false);
                response
            };
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers().get(header::ALLOW).unwrap(), "POST");
            assert!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none()
            );
            assert!(response.headers().get(header::CONTENT_TYPE).is_none());
            assert_security_headers(response.headers());
            assert!(response.into_body().is_empty());
        }
    });
}

#[test]
fn rate_limit_runs_before_form_parsing_and_keeps_retry_contract() {
    futures_executor::block_on(async {
        let service = endpoint(
            Err(TokenManagementRateLimitError::Limited {
                retry_after_seconds: 30,
            }),
            Ok(TokenIntrospectionRepresentation::Inspection(
                TokenInspection::Inactive,
            )),
            Ok(()),
        );
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/introspect")
                .body(Bytes::from("not-a-form"))
                .unwrap();
            introspect(&service, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "30");
        let body: serde_json::Value = serde_json::from_slice::<Value>(response.body()).unwrap();
        assert_eq!(body["error"], "temporarily_unavailable");
    });
}

#[test]
fn inactive_introspection_is_exact_rfc7662_no_store_json() {
    futures_executor::block_on(async {
        let service = endpoint(
            Ok(()),
            Ok(TokenIntrospectionRepresentation::Inspection(
                TokenInspection::Inactive,
            )),
            Ok(()),
        );
        let response = {
            let request = form_request("POST", "/introspect")
                .body(Bytes::from_static(b"token=opaque&client_id=client"))
                .unwrap();
            introspect(&service, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body: serde_json::Value = serde_json::from_slice::<Value>(response.body()).unwrap();
        assert_eq!(body, serde_json::json!({"active": false}));
    });
}

#[test]
fn signed_introspection_keeps_media_type_and_cache_headers() {
    futures_executor::block_on(async {
        let service = endpoint(
            Ok(()),
            Ok(TokenIntrospectionRepresentation::Jwt(
                "signed.jwt".to_owned(),
            )),
            Ok(()),
        );
        let response = {
            let request = form_request("POST", "/introspect")
                .header(header::ACCEPT, TOKEN_INTROSPECTION_JWT_MEDIA_TYPE)
                .body(Bytes::from_static(b"token=opaque&client_id=client"))
                .unwrap();
            introspect(&service, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            TOKEN_INTROSPECTION_JWT_MEDIA_TYPE
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.into_body(), "signed.jwt");
    });
}

#[test]
fn basic_invalid_client_keeps_challenge_and_oauth_error() {
    futures_executor::block_on(async {
        let service = endpoint(
            Ok(()),
            Err(TokenManagementError::InvalidClient {
                basic_challenge: true,
            }),
            Ok(()),
        );
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, "Basic Y2xpZW50OnNlY3JldA==")
                .body(Bytes::from("token=opaque"))
                .unwrap();
            introspect(&service, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Basic realm=\"nazo-oauth\""
        );
        let body: serde_json::Value = serde_json::from_slice::<Value>(response.body()).unwrap();
        assert_eq!(body["error"], "invalid_client");
    });
}

#[test]
fn revocation_success_is_empty_and_non_cacheable() {
    futures_executor::block_on(async {
        let service = endpoint(
            Ok(()),
            Ok(TokenIntrospectionRepresentation::Inspection(
                TokenInspection::Inactive,
            )),
            Ok(()),
        );
        let response = {
            let request = form_request("POST", "/revoke")
                .body(Bytes::from_static(b"token=opaque&client_id=client"))
                .unwrap();
            revoke(&service, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert!(response.into_body().is_empty());
    });
}
