use super::*;
use nazoauth::config::OidcFederationSettings;
use serde_json::json;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn provider() -> OidcFederationSettings {
    OidcFederationSettings {
        discovery: false,
        backchannel_logout: false,
        provider_id: "test-oidc".to_owned(),
        issuer: "https://issuer.example".to_owned(),
        authorization_endpoint: "https://issuer.example/authorize".to_owned(),
        token_endpoint: "https://issuer.example/token".to_owned(),
        jwks_url: "https://issuer.example/jwks".to_owned(),
        userinfo_endpoint: None,
        client_id: "client-1".to_owned(),
        client_secret: "secret".to_owned(),
        redirect_uri: "https://auth.example/federation/test-oidc/callback".to_owned(),
        scopes: "openid email".to_owned(),
    }
}

#[actix_web::test]
async fn upstream_basic_auth_form_encodes_each_credential_without_trimming() {
    use base64::Engine as _;
    let (endpoint, request) = one_shot_json_server("200 OK", json!({"id_token":"token"})).await;
    let mut provider = provider();
    provider.token_endpoint = endpoint;
    provider.client_id = "client:+%".into();
    provider.client_secret = " +secret:% ".into();
    exchange_oidc_code(
        &super::super::federation_http_client().unwrap(),
        &provider,
        "code",
        "verifier",
    )
    .await
    .unwrap();
    let request = request.await.unwrap();
    let basic = raw_header_value(&request, "authorization")
        .unwrap()
        .strip_prefix("Basic ")
        .unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(basic)
        .unwrap();
    assert_eq!(decoded, b"client%3A%2B%25:+%2Bsecret%3A%25+");
}

async fn one_shot_json_server(
    status: &'static str,
    body: Value,
) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test server should bind");
    let addr: SocketAddr = listener.local_addr().expect("test server address");
    let handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
        let (mut stream, _) = listener.accept().await.expect("test request should arrive");
        let request = crate::test_support::read_http_test_request(&mut stream).await;
        let response_body = body.to_string();
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response should write");
        request
        }).await.expect("fixture HTTP exchange exceeded total deadline")
    });
    (format!("http://{addr}"), handle)
}

fn raw_header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn form_body_value(request: &str, key: &str) -> Option<String> {
    let body = request.split("\r\n\r\n").nth(1)?;
    url::form_urlencoded::parse(body.as_bytes())
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

#[actix_web::test]
async fn exchange_oidc_code_posts_basic_authenticated_authorization_code_request() {
    let (endpoint, request) =
        one_shot_json_server("200 OK", json!({"id_token": "signed-id-token"})).await;
    let mut provider = provider();
    provider.token_endpoint = endpoint;

    let token = exchange_oidc_code(
        &super::super::federation_http_client().unwrap(),
        &provider,
        " code-1 +% ",
        "verifier-1",
    )
    .await
    .expect("valid token response should parse");
    let request = request.await.expect("test server should finish");

    assert_eq!(token.id_token, "signed-id-token");
    assert!(request.starts_with("POST / HTTP/1.1"));
    assert!(
        request.contains("authorization: Basic Y2xpZW50LTE6c2VjcmV0")
            || request.contains("Authorization: Basic Y2xpZW50LTE6c2VjcmV0")
    );
    assert_eq!(
        raw_header_value(&request, "content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        form_body_value(&request, "grant_type").as_deref(),
        Some("authorization_code")
    );
    assert_eq!(
        form_body_value(&request, "code").as_deref(),
        Some(" code-1 +% ")
    );
    assert_eq!(
        form_body_value(&request, "redirect_uri").as_deref(),
        Some("https://auth.example/federation/test-oidc/callback")
    );
    assert_eq!(
        form_body_value(&request, "code_verifier").as_deref(),
        Some("verifier-1")
    );
}

#[actix_web::test]
async fn fetch_oidc_jwks_requires_keys_array_from_provider_response() {
    let (valid_endpoint, valid_request) = one_shot_json_server("200 OK", json!({"keys": []})).await;
    let mut provider = provider();
    provider.jwks_url = valid_endpoint;

    assert_eq!(
        fetch_oidc_jwks(&super::super::federation_http_client().unwrap(), &provider)
            .await
            .expect("keys array should be accepted"),
        json!({"keys": []})
    );
    let valid_request = valid_request.await.expect("test server should finish");
    assert!(valid_request.starts_with("GET / HTTP/1.1"));

    let (invalid_endpoint, invalid_request) =
        one_shot_json_server("200 OK", json!({"not_keys": []})).await;
    provider.jwks_url = invalid_endpoint;

    assert!(
        fetch_oidc_jwks(&super::super::federation_http_client().unwrap(), &provider)
            .await
            .is_err(),
        "JWKS responses without a keys array must fail closed"
    );
    invalid_request
        .await
        .expect("invalid JWKS request should finish");
}

#[actix_web::test]
async fn userinfo_uses_bearer_authorization_and_requires_a_subject() {
    let token = serde_json::from_value(json!({
        "id_token": "signed-id-token",
        "access_token": "upstream-access-token",
        "token_type": "Bearer",
    }))
    .unwrap();
    let client = super::super::federation_http_client().unwrap();
    for (body, expected_success) in [
        (
            json!({"sub": "subject-1", "email": "user@example.com", "email_verified": true}),
            true,
        ),
        (
            json!({"email": "user@example.com", "email_verified": true}),
            false,
        ),
    ] {
        let (endpoint, request) = one_shot_json_server("200 OK", body).await;
        assert_eq!(
            fetch_oidc_userinfo(&client, &endpoint, &token, false)
                .await
                .is_ok(),
            expected_success
        );
        let request = request.await.unwrap();
        assert!(request.starts_with("GET / HTTP/1.1"));
        assert_eq!(
            raw_header_value(&request, "authorization"),
            Some("Bearer upstream-access-token")
        );
        assert_eq!(
            raw_header_value(&request, "accept"),
            Some("application/json")
        );
        assert!(
            !request
                .split("\r\n")
                .next()
                .unwrap()
                .contains("upstream-access-token")
        );
    }
}

#[actix_web::test]
async fn federation_configuration_reuses_connection_for_successive_provider_requests() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            // A second request must arrive on this same connection. If the
            // caller rebuilds its client, this read cannot complete.
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..2 {
                let request = crate::test_support::read_http_test_request(&mut stream).await;
                assert!(request.starts_with("GET / HTTP/1.1"));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\n{\"keys\":[]}")
                    .await
                    .unwrap();
            }
        });
        let config = super::super::FederationHttpConfig::new(
            &nazoauth::config::FederationSettings {
                providers: nazoauth::config::FederationProviderRegistry::default(),
                saml_gateway: None,
            },
            std::sync::Arc::new(super::super::federation_http_client().unwrap()),
            &nazoauth::config::SessionSettings {
                session_cookie_name: "session".into(),
                csrf_cookie_name: "csrf".into(),
                session_ttl_seconds: 300,
                pending_mfa_session_ttl_seconds: 120,
                cookie_secure: true,
            },
        );
        let mut provider = provider();
        provider.jwks_url = endpoint;
        assert_eq!(
            fetch_oidc_jwks(config.client.as_ref(), &provider)
                .await
                .unwrap(),
            json!({"keys": []})
        );
        let shared_config = config.clone();
        assert_eq!(
            fetch_oidc_jwks(shared_config.client.as_ref(), &provider)
                .await
                .unwrap(),
            json!({"keys": []})
        );
        server.await.unwrap();
    })
    .await
    .expect("shared federation client should reuse its established connection");
}
