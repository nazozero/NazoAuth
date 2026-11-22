use super::*;
use bytes::Bytes;
use nazoauth::test_support::endpoints::auth::federation as rp_http;
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct Issuer(Mutex<BTreeMap<&'static str, Value>>);

#[actix_web::test]
async fn discovery_transport_rejects_loopback_before_connecting() {
    use rp_http::FederationHttpClient as _;
    let client = federation_http_client().unwrap();
    for host in ["127.0.0.1", "[::1]"] {
        let request = http::Request::get(format!("https://{host}/token"))
            .body(Bytes::new())
            .unwrap();
        let error = client.send_discovered(request, 1024).await.unwrap_err();
        assert!(error.to_string().contains("blocked network"));
    }
}

impl rp_http::FederationHttpClient for Issuer {
    fn send_discovered(&self, _: http::Request<Bytes>, _: usize) -> rp_http::FederationHttpFuture<'_> {
        panic!("the configured issuer's own origin already has operator authorization");
    }

    fn send(
        &self,
        request: http::Request<Bytes>,
        limit: usize,
    ) -> rp_http::FederationHttpFuture<'_> {
        assert_eq!(request.uri().host(), Some("issuer.example"));
        assert_eq!(limit, MAX_FEDERATION_PROVIDER_RESPONSE_BYTES);
        let path = request.uri().path();
        let reply = self
            .0
            .lock()
            .unwrap()
            .remove(path)
            .unwrap_or_else(|| panic!("unexpected OIDC request to {path}"));
        if path == "/token" {
            assert_eq!(request.method(), http::Method::POST);
            assert!(
                request.headers()[http::header::AUTHORIZATION]
                    .to_str()
                    .unwrap()
                    .starts_with("Basic ")
            );
        } else {
            assert_eq!(request.method(), http::Method::GET);
        }
        Box::pin(async move { Ok(http::Response::new(Bytes::from(reply.to_string()))) })
    }
}

#[actix_web::test]
async fn discovered_login_keeps_its_endpoints_and_accepts_backchannel_logout() {
    for by_sid in [false, true] {
        discovered_login_and_logout(by_sid).await;
    }
}

async fn discovered_login_and_logout(by_sid: bool) {
    let mut provider = oidc_provider();
    provider.discovery = true;
    provider.backchannel_logout = true;
    let Some(fixture) = LiveFederationFixture::new(Some(provider.clone()), None).await else {
        return;
    };
    let issuer = Arc::new(Issuer::default());
    let metadata_path = "/.well-known/openid-configuration";
    let metadata = json!({
        "issuer": provider.issuer,
        "authorization_endpoint": provider.authorization_endpoint,
        "token_endpoint": provider.token_endpoint,
        "jwks_uri": provider.jwks_url,
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });
    issuer
        .0
        .lock()
        .unwrap()
        .insert(metadata_path, metadata.clone());
    let state = &fixture.state;
    let mut config = crate::test_support::federation_http_config(state)
        .get_ref()
        .clone();
    config.client = issuer.clone();
    let service = crate::test_support::federation_service(state);
    let client_ip = crate::test_support::client_ip_config(state);
    let limiter = crate::test_support::auth_request_limiter(state);
    let browser = http::Request::builder()
        .header(
            http::header::COOKIE,
            format!(
                "__Host-nazo_federation_binding={}",
                URL_SAFE_NO_PAD.encode(test_browser_binding_seed()),
            ),
        )
        .body(Bytes::new())
        .unwrap();
    let start = rp_http::federation_provider_start(
        &limiter,
        &client_ip,
        &service,
        &config,
        &browser,
        TEST_OIDC_PROVIDER_ID.into(),
    )
    .await;
    assert_eq!(start.status(), http::StatusCode::FOUND);
    let url = url::Url::parse(start.headers()[http::header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(url.path(), "/authorize");
    let params = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    let key = client_signing_fixture(Algorithm::RS256);
    let jwks = json!({ "keys": [key.public_jwk("oidc-kid")] });
    let suffix = Uuid::now_v7().simple().to_string();
    let subject = format!("discovered-{suffix}");
    let sid = format!("upstream-{suffix}");
    let id_token = signed_oidc_token(
        &provider,
        "oidc-kid",
        &key,
        &params["nonce"],
        json!({
            "sub": subject,
            "sid": sid,
            // Both tokens are valid even when the OP's signing nodes disagree
            // within the accepted clock skew. Logout must still end the session.
            "iat": jiff::Timestamp::now().as_second() + 30,
            "email": format!("discovered-{suffix}@example.com"),
        }),
    );
    issuer.0.lock().unwrap().extend([
        (
            "/token",
            json!({ "id_token": id_token, "access_token": "access", "token_type": "Bearer" }),
        ),
        ("/jwks", jwks.clone()),
    ]);
    let response = rp_http::federation_provider_callback(
        &limiter,
        &client_ip,
        &service,
        &config,
        &crate::test_support::profile_sessions(state),
        &browser,
        TEST_OIDC_PROVIDER_ID.into(),
        OidcCallbackQuery {
            code: Some("auth-code".into()),
            state: Some(params["state"].to_string()),
            error: None,
        },
    )
    .await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let response = nazo_http_actix::forward_response(response);
    let cookie = cookie_value_from_response(&response, &config.session_cookie_name).unwrap();
    let sessions = nazo_valkey::SessionStore::new(&state.valkey_connection());
    assert!(sessions.load(&cookie).await.unwrap().is_some());
    assert!(issuer.0.lock().unwrap().is_empty());

    let now = jiff::Timestamp::now().as_second();
    let mut logout_header = Header::new(Algorithm::RS256);
    logout_header.kid = Some("oidc-kid".into());
    logout_header.typ = Some("logout+jwt".into());
    let mut claims = json!({
        "iss": provider.issuer,
        "aud": provider.client_id,
        "sub": subject,
        "sid": sid,
        "iat": now,
        "exp": now + 60,
        "jti": suffix,
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    if !by_sid {
        claims.as_object_mut().unwrap().remove("sid");
    }
    for valid in [false, true, true] {
        claims["aud"] = json!(if valid {
            provider.client_id.as_str()
        } else {
            "wrong-client"
        });
        issuer
            .0
            .lock()
            .unwrap()
            .extend([(metadata_path, metadata.clone()), ("/jwks", jwks.clone())]);
        let token = key.encode_jwt(&logout_header, &claims);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("logout_token", &token)
            .finish();
        let request = http::Request::post(format!(
            "/auth/federation/{TEST_OIDC_PROVIDER_ID}/backchannel-logout"
        ))
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(Bytes::from(body))
        .unwrap();
        let response = rp_http::federation_provider_backchannel_logout(
            &limiter,
            &client_ip,
            &service,
            &config,
            &request,
            TEST_OIDC_PROVIDER_ID.into(),
        )
        .await;
        if valid {
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
        } else {
            assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
        }
        assert_eq!(sessions.load(&cookie).await.unwrap().is_none(), valid);
        assert!(issuer.0.lock().unwrap().is_empty());
    }

    // Discovery and key-fetch failures follow the same Back-Channel response
    // contract as token or session-revocation failures.
    for failed_metadata in [true, false] {
        let mut document = metadata.clone();
        if failed_metadata {
            document["issuer"] = json!("https://other.example");
        }
        issuer.0.lock().unwrap().insert(metadata_path, document);
        if !failed_metadata {
            issuer.0.lock().unwrap().insert("/jwks", json!({}));
        }
        let token = key.encode_jwt(&logout_header, &claims);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("logout_token", &token)
            .finish();
        let request = http::Request::post("/backchannel-logout")
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Bytes::from(body))
            .unwrap();
        let response = rp_http::federation_provider_backchannel_logout(
            &limiter,
            &client_ip,
            &service,
            &config,
            &request,
            TEST_OIDC_PROVIDER_ID.into(),
        )
        .await;
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
        assert!(issuer.0.lock().unwrap().is_empty());
    }
}
