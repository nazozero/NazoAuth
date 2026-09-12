use nazo_oauth_server as app;
#[path = "../../../../../authorization-server/tests/support/authorization.rs"]
mod authorization_fixture;
use super::*;
use actix_web::body::to_bytes;
use actix_web::http::header;
use nazo_oauth_server::domain::rows::ClientRow;
use serde_json::{Value, json};
use uuid::Uuid;

use nazo_identity::DEFAULT_ORGANIZATION_ID;
use nazo_identity::DEFAULT_REALM_ID;
use nazo_identity::DEFAULT_TENANT_ID;

fn presentation_client(active: bool) -> ClientRow {
    let mut client = client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "presentation-client".to_owned(),
        client_name: "Presentation Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!([]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "none".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        is_active: active,
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    };
    client.presentation = nazo_auth::ClientPresentationMetadata {
        logo_uri: Some("https://client.example/logo.svg".to_owned()),
        policy_uri: Some("https://client.example/privacy".to_owned()),
        tos_uri: Some("https://client.example/terms".to_owned()),
    };
    client
}

async fn response_json(response: HttpResponse) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap()
}

#[actix_web::test]
async fn active_client_exposes_only_registered_display_metadata_without_caching() {
    let client = presentation_client(true);
    let response = client_presentation_response(Ok(ClientPresentation {
        client_name: client.client_name.clone(),
        logo_uri: client.presentation.logo_uri.clone(),
        policy_uri: client.presentation.policy_uri.clone(),
        tos_uri: client.presentation.tos_uri.clone(),
    }));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let body = response_json(response).await;
    assert_eq!(
        body,
        json!({
            "client_name": "Presentation Client",
            "logo_uri": "https://client.example/logo.svg",
            "policy_uri": "https://client.example/privacy",
            "tos_uri": "https://client.example/terms"
        })
    );
    for forbidden in ["client_id", "client_secret", "jwks", "redirect_uris"] {
        assert!(body.get(forbidden).is_none());
    }
}

#[actix_web::test]
async fn missing_and_inactive_clients_have_the_same_non_enumerating_shape() {
    let mut responses = Vec::new();
    for client in [None, Some(authorization_fixture::client(false))] {
        let fixture = authorization_fixture::Fixture::new(Ok(client), Ok(None));
        let endpoint = AuthorizationEndpoint::new(
            std::sync::Arc::new(fixture.make_application()),
            nazo_http_actix::ClientIpConfig::new(&[], nazo_http_actix::ClientIpHeaderMode::None),
            crate::http::sessions::SessionHttpConfig::new("session", "csrf", false),
        );
        let request = actix_web::test::TestRequest::get()
            .uri("/authorize/client?client_id=client-1")
            .to_http_request();
        let response = authorize_client_presentation(Data::new(endpoint), request).await;
        assert_eq!(fixture.ports.calls(), ["client"]);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let status = response.status();
        let mut headers: Vec<_> = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        headers.sort();
        let body = to_bytes(response.into_body()).await.unwrap();
        assert_eq!(body.as_ref(), br#"{"error":"not_found"}"#);
        responses.push((status, headers, body));
    }
    assert_eq!(responses[0], responses[1]);
}

#[actix_web::test]
async fn unavailable_client_lookup_has_only_error_json() {
    let response = client_presentation_response(Err(ClientPresentationError::Unavailable));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_json(response).await,
        json!({ "error": "server_error" })
    );
}

#[test]
fn presentation_lookup_accepts_exactly_one_visible_ascii_client_id() {
    assert_eq!(
        presentation_client_id("client_id=client-1"),
        Some("client-1".to_owned())
    );
    for query in [
        "",
        "other=client-1",
        "client_id=",
        "client_id=first&client_id=second",
        "client_id=client-1&extra=value",
        "client_id=%20client-1",
        "client_id=client%0Aid",
        "client_id=%E5%AE%A2%E6%88%B7%E7%AB%AF",
    ] {
        assert_eq!(presentation_client_id(query), None, "{query}");
    }
}
