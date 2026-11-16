use super::*;
use crate::http::{
    ProfileAccountEndpoint, SessionCookieConfig, apply_security_headers, parse_json,
    profile_applications, profile_me, profile_update,
};
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use nazo_identity::{
    AccountProfileView, AuthorizedApplicationView, AuthorizedApplicationsView, ProfilePatch,
    SessionId,
};
use nazo_oauth_server::contracts::profile_account::{
    ProfileAccountFuture, ProfileAccountOperations, ProfileMe,
};
use std::sync::Arc;
struct ContractProfileOperations;

impl ProfileAccountOperations for ContractProfileOperations {
    fn me(&self, _session_id: SessionId) -> ProfileAccountFuture<'_, ProfileMe> {
        Box::pin(async { Ok(ProfileMe::Active(Box::new(contract_profile()))) })
    }

    fn update(
        &self,
        _session_id: SessionId,
        _patch: ProfilePatch,
    ) -> ProfileAccountFuture<'_, AccountProfileView> {
        Box::pin(async { Ok(contract_profile()) })
    }

    fn applications(
        &self,
        _session_id: SessionId,
    ) -> ProfileAccountFuture<'_, AuthorizedApplicationsView> {
        Box::pin(async {
            Ok(AuthorizedApplicationsView {
                total: 1,
                items: vec![AuthorizedApplicationView {
                    client_id: "contract-client".to_owned(),
                    client_name: "Contract Client".to_owned(),
                    last_scopes: vec!["openid".to_owned()],
                    last_authorized_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
                    authorization_count: 1,
                }],
            })
        })
    }
}

fn contract_profile() -> AccountProfileView {
    AccountProfileView {
        id: uuid::Uuid::from_u128(1),
        email: "alice@example.test".to_owned(),
        display_name: Some("Alice".to_owned()),
        avatar_url: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile_url: None,
        website_url: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
        mfa_enabled: false,
        role: "user",
        admin_level: 0,
        authorized_app_count: 1,
    }
}

fn assert_profile_security_headers(headers: &header::HeaderMap) {
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(
        headers.get("content-security-policy").unwrap(),
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    );
}

#[test]
fn browser_token_management_cors_allows_post_dpop_without_credentials() {
    let origins = ["https://app.example".to_owned()];

    let allowed = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/token")
        .header(header::ORIGIN, "https://app.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type, dpop")
        .body(Bytes::new())
        .unwrap();
    let response = cors_preflight(CorsPolicy::BrowserTokenManagement, &allowed, &origins).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "browser token management must NOT allow credentials (no cookies)"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("dpop"),
        "DPoP proofs must be explicitly allowed for browser token requests"
    );

    let denied = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/token")
        .header(header::ORIGIN, "https://attacker.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(Bytes::new())
        .unwrap();
    let response = cors_preflight(CorsPolicy::BrowserTokenManagement, &denied, &origins).unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "unregistered browser origins must not receive CORS authorization"
    );
}

#[test]
fn browser_userinfo_cors_allows_get_and_post_bearer_or_dpop() {
    let origins = ["https://app.example".to_owned()];
    for method in ["GET", "POST"] {
        let request = http::Request::builder()
            .method(http::Method::OPTIONS)
            .uri("/userinfo")
            .header(header::ORIGIN, "https://app.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
            .header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization, dpop",
            )
            .body(Bytes::new())
            .unwrap();
        let response = cors_preflight(CorsPolicy::BrowserUserinfo, &request, &origins).unwrap();
        assert_eq!(response.status(), StatusCode::OK, "method={method}");
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }
}

#[test]
fn authorization_endpoint_is_not_cors_enabled() {
    let origins = ["https://app.example".to_owned()];

    let request = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/authorize")
        .header(header::ORIGIN, "https://app.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Bytes::new())
        .unwrap();
    assert!(
        cors_preflight(
            crate::integration::match_path(request.uri().path())
                .map_or(CorsPolicy::None, |(route, _)| route.cors),
            &request,
            &origins
        )
        .is_none()
    );
    let response = crate::routes::resolve(request.method(), request.uri().path()).unwrap_err();

    assert_ne!(
        response.status(),
        StatusCode::OK,
        "authorization endpoint must not answer browser CORS preflight"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "authorization endpoint must not expose itself to browser XHR through CORS"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "authorization endpoint must not allow credentialed CORS"
    );
}

#[test]
fn openid_federation_route_is_not_registered() {
    let origins = ["https://app.example".to_owned()];

    let request = http::Request::builder()
        .method("GET")
        .uri("/.well-known/openid-federation")
        .body(Bytes::new())
        .unwrap();
    assert!(
        cors_preflight(
            crate::integration::match_path(request.uri().path())
                .map_or(CorsPolicy::None, |(route, _)| route.cors),
            &request,
            &origins
        )
        .is_none()
    );
    let response = crate::routes::resolve(request.method(), request.uri().path()).unwrap_err();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "OpenID Federation is not part of the product surface"
    );
}

#[test]
fn cors_actual_response_exposes_oauth_challenge_nonce_and_retry_headers() {
    let origins = ["https://app.example".to_owned()];

    let request = http::Request::builder()
        .method("GET")
        .uri("/resource")
        .header(header::ORIGIN, "https://app.example")
        .body(Bytes::new())
        .unwrap();
    let mut response = finish(
        http::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "DPoP error=\"use_dpop_nonce\"")
            .header("dpop-nonce", "nonce-1")
            .header(header::RETRY_AFTER, "5"),
        Bytes::new(),
    );
    apply_cors_headers(
        CorsPolicy::BrowserUserinfo,
        &request,
        &origins,
        response.headers_mut(),
    );

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let expose = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(expose.contains("www-authenticate"));
    assert!(expose.contains("dpop-nonce"));
    assert!(expose.contains("retry-after"));
}

#[test]
fn cors_well_known_allows_get_and_head_only() {
    let origins = ["https://app.example".to_owned()];

    let allowed = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/.well-known/openid-configuration")
        .header(header::ORIGIN, "https://app.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Bytes::new())
        .unwrap();
    let response = cors_preflight(CorsPolicy::WellKnown, &allowed, &origins).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "cors_well_known must NOT allow credentials"
    );
}

#[test]
fn cors_admin_allows_csrf_header_for_credentialed_write_requests() {
    let origins = ["https://admin.example".to_owned()];

    let request = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/admin/clients")
        .header(header::ORIGIN, "https://admin.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        )
        .body(Bytes::new())
        .unwrap();
    let response = cors_preflight(CorsPolicy::Admin, &request, &origins).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("x-csrf-token")
    );
}

#[test]
fn cors_auth_api_credentials_are_limited_to_configured_origins_and_csrf_headers() {
    let origins = ["https://app.example".to_owned()];

    let allowed = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/auth/me")
        .header(header::ORIGIN, "https://app.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        )
        .body(Bytes::new())
        .unwrap();
    let response = cors_preflight(CorsPolicy::AuthApi, &allowed, &origins).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example"
    );
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("x-csrf-token"),
        "credentialed auth API writes must allow only explicit CSRF-bearing CORS requests"
    );

    let denied = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/auth/me")
        .header(header::ORIGIN, "https://attacker.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        )
        .body(Bytes::new())
        .unwrap();
    let response = cors_preflight(CorsPolicy::AuthApi, &denied, &origins).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "credentialed auth API CORS must not authorize unregistered browser origins"
    );
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "credentialed auth API CORS must not expose cookies to unregistered origins"
    );
}

#[test]
fn production_profile_routes_keep_method_cors_cache_and_security_contracts() {
    futures_executor::block_on(async {
        let origins = ["https://app.example".to_owned()];
        let endpoint = ProfileAccountEndpoint::new(
            Arc::new(ContractProfileOperations),
            SessionCookieConfig::new("session", "csrf", true),
        );

        let get = http::Request::builder()
            .method("GET")
            .uri("/auth/me")
            .header(header::ORIGIN, "https://app.example")
            .header(header::COOKIE, "session=sid")
            .body(Bytes::new())
            .unwrap();
        let get = {
            let request = get;
            let mut response = profile_me(&endpoint, &request).await;
            apply_cors_headers(
                crate::integration::match_path(request.uri().path())
                    .unwrap()
                    .0
                    .cors,
                &request,
                &origins,
                response.headers_mut(),
            );
            apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(
            get.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            get.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(get.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            get.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example"
        );
        assert_eq!(
            get.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );
        assert_profile_security_headers(get.headers());
        let get_body: serde_json::Value = serde_json::from_slice(get.body()).unwrap();
        assert_eq!(get_body["email"], "alice@example.test");
        assert_eq!(get_body["mfa_required"], false);
        assert!(get_body.get("csrf_token").is_none());

        let patch = http::Request::builder()
            .method("PATCH")
            .uri("/auth/me")
            .header(header::ORIGIN, "https://app.example")
            .header("x-csrf-token", "csrf-token")
            .header(header::COOKIE, "session=sid")
            .header(header::COOKIE, "csrf=csrf-token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(
                serde_json::to_vec(&serde_json::json!({"display_name": "Alice"})).unwrap(),
            ))
            .unwrap();
        let patch = {
            let request = patch;
            let mut response =
                profile_update(&endpoint, &request, parse_json(&request).unwrap()).await;
            apply_cors_headers(
                crate::integration::match_path(request.uri().path())
                    .unwrap()
                    .0
                    .cors,
                &request,
                &origins,
                response.headers_mut(),
            );
            apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(patch.status(), StatusCode::OK);
        assert_eq!(
            patch.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            patch.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(patch.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            patch
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example"
        );
        assert_profile_security_headers(patch.headers());
        let patch_body: serde_json::Value = serde_json::from_slice(patch.body()).unwrap();
        assert_eq!(patch_body["display_name"], "Alice");
        assert!(patch_body.get("mfa_required").is_none());

        let applications = http::Request::builder()
            .method("GET")
            .uri("/auth/me/applications")
            .header(header::ORIGIN, "https://app.example")
            .header(header::COOKIE, "session=sid")
            .body(Bytes::new())
            .unwrap();
        let applications = {
            let request = applications;
            let mut response = profile_applications(&endpoint, &request).await;
            apply_cors_headers(
                crate::integration::match_path(request.uri().path())
                    .unwrap()
                    .0
                    .cors,
                &request,
                &origins,
                response.headers_mut(),
            );
            apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(applications.status(), StatusCode::OK);
        assert_eq!(
            applications.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            applications.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            applications
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example"
        );
        assert_profile_security_headers(applications.headers());
        let applications_body: serde_json::Value =
            serde_json::from_slice(applications.body()).unwrap();
        assert_eq!(applications_body["total"], 1);
        assert_eq!(
            applications_body["items"][0]["client_id"],
            "contract-client"
        );

        let post = http::Request::builder()
            .method("POST")
            .uri("/auth/me")
            .header(header::ORIGIN, "https://app.example")
            .body(Bytes::new())
            .unwrap();
        let post = {
            let request = post;
            let mut response =
                crate::routes::resolve(request.method(), request.uri().path()).unwrap_err();
            apply_cors_headers(
                crate::integration::match_path(request.uri().path())
                    .unwrap()
                    .0
                    .cors,
                &request,
                &origins,
                response.headers_mut(),
            );
            apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
        let allowed = post.headers().get(header::ALLOW).unwrap().to_str().unwrap();
        assert!(allowed.split(',').any(|method| method.trim() == "GET"));
        assert!(allowed.split(',').any(|method| method.trim() == "PATCH"));
        assert!(post.headers().get(header::CONTENT_TYPE).is_none());
        assert!(post.headers().get(header::CACHE_CONTROL).is_none());
        assert_eq!(
            post.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example"
        );
        assert_profile_security_headers(post.headers());
        assert!(post.body().is_empty());

        for method in ["GET", "PATCH"] {
            let options = http::Request::builder()
                .method(http::Method::OPTIONS)
                .uri("/auth/me")
                .header(header::ORIGIN, "https://app.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "x-csrf-token, content-type",
                )
                .body(Bytes::new())
                .unwrap();
            let options = {
                let request = options;
                let mut response = cors_preflight(
                    crate::integration::match_path(request.uri().path())
                        .unwrap()
                        .0
                        .cors,
                    &request,
                    &origins,
                )
                .unwrap();
                apply_security_headers(response.headers_mut(), false);
                response
            };
            assert_eq!(options.status(), StatusCode::OK, "method={method}");
            assert!(options.headers().get(header::CONTENT_TYPE).is_none());
            assert!(options.headers().get(header::CACHE_CONTROL).is_none());
            assert_eq!(
                options
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .unwrap(),
                "https://app.example"
            );
            assert_eq!(
                options
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .unwrap(),
                "true"
            );
            assert_profile_security_headers(options.headers());
            assert!(options.body().is_empty());
        }
    });
}

#[test]
fn cors_scim_allows_put_without_browser_credentials() {
    let origins = ["https://scim-admin.example".to_owned()];

    let request = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri("/scim/v2/Users/user-1")
        .header(header::ORIGIN, "https://scim-admin.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization, content-type",
        )
        .body(Bytes::new())
        .unwrap();
    let response = cors_preflight(CorsPolicy::Scim, &request, &origins).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "SCIM uses bearer authentication and must not authorize browser credentials"
    );
}

#[test]
fn production_token_route_rejects_get_csrf_and_unknown_origins() {
    let origins = ["https://spa.example".to_owned()];

    for (origin, method, headers) in [
        ("https://spa.example", "GET", "content-type"),
        ("https://spa.example", "POST", "x-csrf-token"),
        ("https://attacker.example", "POST", "content-type"),
    ] {
        let request = http::Request::builder()
            .method(http::Method::OPTIONS)
            .uri("/token")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, headers)
            .body(Bytes::new())
            .unwrap();
        let response = cors_preflight(
            crate::integration::match_path(request.uri().path())
                .unwrap()
                .0
                .cors,
            &request,
            &origins,
        )
        .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "token preflight must reject origin={origin}, method={method}, headers={headers}"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "rejected token preflight must not authorize its origin"
        );
    }
}

#[test]
fn production_browser_oauth_routes_expose_only_required_cors() {
    let origins = ["https://spa.example".to_owned()];

    for (path, method, headers) in [
        ("/token", "POST", "content-type, dpop"),
        ("/revoke", "POST", "content-type, authorization, dpop"),
        ("/userinfo", "GET", "authorization, dpop"),
        ("/userinfo", "POST", "authorization, content-type, dpop"),
    ] {
        let request = http::Request::builder()
            .method(http::Method::OPTIONS)
            .uri(path)
            .header(header::ORIGIN, "https://spa.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, headers)
            .body(Bytes::new())
            .unwrap();
        let response = cors_preflight(
            crate::integration::match_path(request.uri().path())
                .unwrap()
                .0
                .cors,
            &request,
            &origins,
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path} {method}");
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "public browser OAuth routes must not authorize cookies"
        );
    }
}

#[test]
fn dynamic_cors_policy_is_bound_to_one_immutable_request_snapshot() {
    let registry = arc_swap::ArcSwap::from_pointee(vec!["https://first.example".to_owned()]);
    let selected = registry.load_full();
    let first = http::Request::builder()
        .header(header::ORIGIN, "https://first.example")
        .body(Bytes::new())
        .unwrap();
    let second = http::Request::builder()
        .header(header::ORIGIN, "https://second.example")
        .body(Bytes::new())
        .unwrap();
    assert!(
        allowed_origin(&first, &[]).is_none(),
        "missing selection fails closed"
    );
    registry.store(Arc::new(vec!["https://second.example".to_owned()]));
    assert!(allowed_origin(&first, &selected).is_some());
    assert!(allowed_origin(&second, &selected).is_none());
    let next_request = registry.load_full();
    assert!(allowed_origin(&first, &next_request).is_none());
    assert!(allowed_origin(&second, &next_request).is_some());
    assert!(allowed_origin(&second, &[]).is_none());
}

#[test]
fn dynamic_cors_request_scopes_are_isolated_when_futures_interleave() {
    futures_executor::block_on(async {
        let one = ["https://one.example".to_owned()];
        let two = ["https://two.example".to_owned()];
        let first = http::Request::builder()
            .header(header::ORIGIN, "https://one.example")
            .body(Bytes::new())
            .unwrap();
        let second = http::Request::builder()
            .header(header::ORIGIN, "https://two.example")
            .body(Bytes::new())
            .unwrap();
        async fn yield_once() {
            let mut pending = true;
            std::future::poll_fn(|cx| {
                if std::mem::take(&mut pending) {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            })
            .await;
        }
        futures_util::join!(
            async {
                yield_once().await;
                assert!(allowed_origin(&first, &one).is_some());
                assert!(allowed_origin(&second, &one).is_none());
            },
            async {
                yield_once().await;
                assert!(allowed_origin(&second, &two).is_some());
                assert!(allowed_origin(&first, &two).is_none());
            }
        );
    });
}

#[test]
fn dynamic_cors_preflight_uses_selected_policy_and_missing_context_rejects() {
    let origins = ["https://selected.example".to_owned()];
    for scoped in [false, true] {
        let request = http::Request::builder()
            .method(Method::OPTIONS)
            .uri("/auth/me")
            .header(header::ORIGIN, "https://selected.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(Bytes::new())
            .unwrap();
        let selected = if scoped { origins.as_slice() } else { &[] };
        let response = cors_preflight(CorsPolicy::AuthApi, &request, selected).unwrap();
        if scoped {
            assert!(response.status().is_success());
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .unwrap(),
                "https://selected.example"
            );
        } else {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
