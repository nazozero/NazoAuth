use super::live_transport_state;
use crate::http::authorization::AuthorizationEndpoint;
use crate::test_support::TestInfrastructure;
use actix_web::{
    body::to_bytes,
    http::{StatusCode, header},
    test::TestRequest,
    web::{Bytes, Data},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::sql_query;
use diesel::sql_types::{Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use nazo_valkey::test_support::KeysInterface;
use serde_json::{Value, json};

const CALLBACK: &str = "https://client.example/callback";

fn endpoint(state: &TestInfrastructure) -> Data<AuthorizationEndpoint> {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(state);
    Data::new(dependencies.endpoint())
}
async fn client(
    state: &TestInfrastructure,
    jwks: Option<Value>,
) -> (nazo_auth::OAuthClient, String) {
    let request = serde_json::from_value(json!({
        "client_name": format!("T00 authorization {}", uuid::Uuid::now_v7()),
        "client_type": "confidential", "redirect_uris": [CALLBACK],
        "scopes": ["openid"], "allowed_audiences": ["resource://one", "resource://two"],
        "grant_types": ["authorization_code"], "token_endpoint_auth_method": "client_secret_post",
        "jwks": jwks
    }))
    .expect("registration request");
    let resolver = crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
        .expect("resolver");
    let prepared = nazo_auth::prepare_client_registration(
        request,
        &nazo_auth::AdminClientPolicy {
            tenant: state.settings.tenant.context,
            pairwise_subject_secret: None,
            client_secret_pepper: state.settings.protocol.client_secret_pepper.clone(),
        },
        &resolver,
        &nazo_key_management::ClientRegistrationCrypto::new(state.keyset.clone()),
    )
    .await
    .expect("prepare real registration");
    let secret = prepared
        .issued_secret
        .clone()
        .expect("confidential client secret");
    let client = nazo_auth::insert_prepared_client(
        &nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
        &prepared,
    )
    .await
    .expect("persist client");
    (client, secret)
}

async fn authorized_response(
    state: &TestInfrastructure,
    client: &nazo_auth::OAuthClient,
    response_mode: &str,
    state_value: &str,
) -> actix_web::HttpResponse {
    let user_id = uuid::Uuid::now_v7();
    let sid = format!("t00-auth-{user_id}");
    let now = chrono::Utc::now().timestamp();
    let mut connection = nazo_postgres::get_conn(&state.diesel_db)
        .await
        .expect("authorization fixture DB connection");
    sql_query(
        "INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, \
         password_hash, is_active, mfa_enabled, email_verified, role, admin_level) \
         VALUES ($1, $2, $3, $4, $5, $6, 't00-auth-fixture', TRUE, FALSE, TRUE, 'user', 0)",
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(nazo_identity::DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(nazo_identity::DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(nazo_identity::DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("t00-auth-{user_id}"))
    .bind::<Text, _>(format!("t00-auth-{user_id}@example.test"))
    .execute(&mut connection)
    .await
    .expect("authorization fixture user insert");
    sql_query(
        "INSERT INTO user_client_grants (tenant_id, user_id, client_id, first_authorized_at, \
         last_authorized_at, last_scopes, last_authorization_details, authorization_count) \
         VALUES ($1, $2, $3, now(), now(), '[\"openid\"]'::jsonb, '[]'::jsonb, 1)",
    )
    .bind::<SqlUuid, _>(nazo_identity::DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(client.id)
    .execute(&mut connection)
    .await
    .expect("authorization fixture grant insert");
    drop(connection);
    let payload = nazo_oauth_server::sessions::SessionPayload {
        user_id,
        auth_time: now,
        amr: vec!["pwd".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(format!("oidc-{sid}")),
    };
    crate::test_support::valkey::valkey_set_ex(
        &state.valkey,
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}")),
        serde_json::to_string(&payload).expect("session serializes"),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .expect("authorization fixture session insert");
    let challenge = "A".repeat(43);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("client_id", client.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", CALLBACK),
            ("scope", "openid"),
            ("state", state_value),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("prompt", "none"),
            ("response_mode", response_mode),
        ])
        .finish();
    crate::http::authorization::request::authorize_get(
        endpoint(state),
        TestRequest::get()
            .uri(&format!("/oauth/authorize?{query}"))
            .cookie(actix_web::cookie::Cookie::new(
                state.settings.session.session_cookie_name.clone(),
                sid,
            ))
            .to_http_request(),
    )
    .await
}

#[actix_web::test]
async fn t00_par_repeated_resources_ignore_repeated_extensions_and_persist_exact_fields() {
    let state = live_transport_state().await;
    let (client, secret) = client(&state, None).await;
    let endpoint = endpoint(&state);
    let challenge = "A".repeat(43);
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("client_id", client.client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("response_type", "code"),
            ("redirect_uri", CALLBACK),
            ("scope", "openid"),
            ("state", "state<&\""),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", "resource://one"),
            ("resource", "resource://two"),
            ("unknown_extension", "first"),
            ("unknown_extension", "second"),
        ])
        .finish();
    let before = chrono::Utc::now();
    let response = crate::http::authorization::par::par(
        endpoint,
        TestRequest::post()
            .uri("/oauth/par")
            .peer_addr("198.51.100.201:21001".parse().unwrap())
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request(),
        Bytes::from(form),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let bytes = to_bytes(response.into_body()).await.unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let uri = value["request_uri"].as_str().unwrap();
    let token = uri
        .strip_prefix("urn:ietf:params:oauth:request_uri:")
        .expect("PAR URI namespace");
    assert!(URL_SAFE_NO_PAD.decode(token).unwrap().len() >= 32);
    let ttl = state.settings.protocol.par_ttl_seconds;
    assert_eq!(
        bytes.as_ref(),
        format!("{{\"expires_in\":{ttl},\"request_uri\":\"{uri}\"}}").as_bytes()
    );
    let key = nazo_valkey::test_support::par_storage_key(uri);
    let raw: String = state.valkey.get(&key).await.expect("persisted raw PAR");
    let stored: Value = serde_json::from_str(&raw).unwrap();
    let issued: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(stored["issued_at"].clone()).unwrap();
    let expires: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(stored["expires_at"].clone()).unwrap();
    assert!(issued >= before && issued <= chrono::Utc::now());
    assert_eq!(expires - issued, chrono::Duration::seconds(ttl as i64));
    assert_eq!(
        stored,
        json!({"client_id": client.client_id, "params": {
        "client_id": client.client_id, "response_type": "code", "redirect_uri": CALLBACK,
        "scope": "openid", "state": "state<&\"", "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": "nazo-internal-resource-set:[\"resource://one\",\"resource://two\"]"
    }, "issued_at": issued, "expires_at": expires})
    );
    let remaining: i64 = state.valkey.ttl(&key).await.unwrap();
    assert!(remaining > 0 && remaining <= ttl as i64);
}

#[actix_web::test]
async fn t00_par_duplicate_body_is_rejected_before_unknown_client_lookup() {
    let state = live_transport_state().await;
    let rate_key = nazo_valkey::test_support::state_storage_key(format!(
        "oauth:rate:token_management:{}",
        nazo_oauth_server::crypto::blake3_hex("198.51.100.202")
    ));
    let previous: Option<u64> = state.valkey.get(&rate_key).await.unwrap();
    let response = crate::http::authorization::par::par(
        endpoint(&state),
        TestRequest::post()
            .peer_addr("198.51.100.202:21002".parse().unwrap())
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request(),
        Bytes::from_static(b"client_id=not-registered&client_id=not-registered"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::LOCATION));
    assert_eq!(
        to_bytes(response.into_body()).await.unwrap().as_ref(),
        "{\"error\":\"invalid_request\",\"error_description\":\"Request failed.\"}".as_bytes()
    );
    let current: u64 = state.valkey.get(&rate_key).await.unwrap();
    assert_eq!(current, previous.unwrap_or_default() + 1);
    let rate_ttl: i64 = state.valkey.ttl(&rate_key).await.unwrap();
    assert!(rate_ttl > 0 && rate_ttl <= state.settings.identity.rate_limit.window_seconds as i64);
}

#[actix_web::test]
async fn t00_jar_invalid_unsigned_and_tampered_objects_never_redirect_to_attacker() {
    let state = live_transport_state().await;
    let signer = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let (client, _) = client(
        &state,
        Some(json!({"keys": [signer.public_jwk("t00-jar")]})),
    )
    .await;
    let endpoint = endpoint(&state);
    let now = chrono::Utc::now().timestamp();
    let claims = json!({"iss": client.client_id, "client_id": client.client_id, "aud": "https://issuer.example",
        "iat": now, "exp": now + 90, "jti": uuid::Uuid::now_v7(), "response_type": "code",
        "redirect_uri": "https://attacker.example/steal", "scope": "openid"});
    let unsigned = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut signing_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    signing_header.kid = Some("t00-jar".to_owned());
    let mut original = claims.clone();
    original["redirect_uri"] = json!(CALLBACK);
    let signed = signer.encode_jwt(&signing_header, &original);
    let parts: Vec<_> = signed.split('.').collect();
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
        parts[2]
    );
    for object in ["not-a-jwt".to_owned(), unsigned, tampered] {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", client.client_id.as_str()),
                ("request", object.as_str()),
                ("response_type", "code"),
                ("redirect_uri", CALLBACK),
            ])
            .finish();
        let response = crate::http::authorization::request::authorize_get(
            endpoint.clone(),
            TestRequest::get()
                .uri(&format!("/oauth/authorize?{query}"))
                .to_http_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://client.example/callback?error=invalid_request_object&iss=https%3A%2F%2Fissuer.example"
        );
        assert!(to_bytes(response.into_body()).await.unwrap().is_empty());
    }
}

#[actix_web::test]
async fn t00_jarm_signature_and_all_claims_are_bound_to_database_client() {
    let state = live_transport_state().await;
    let (client, _) = client(&state, None).await;
    let before = chrono::Utc::now().timestamp();
    let response = authorized_response(&state, &client, "jwt", "golden-state").await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = url::Url::parse(
        response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        location.origin().ascii_serialization(),
        "https://client.example"
    );
    assert_eq!(location.path(), "/callback");
    let pairs: Vec<_> = location.query_pairs().collect();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "response");
    let token = pairs[0].1.as_ref();
    let header = jsonwebtoken::decode_header(token).unwrap();
    assert_eq!(header.alg, state.keyset.snapshot().active_alg);
    assert_eq!(header.typ.as_deref(), Some("oauth-authz-resp+jwt"));
    let jwks: jsonwebtoken::jwk::JwkSet =
        serde_json::from_value(state.keyset.snapshot().jwks()).unwrap();
    let key = jwks
        .find(header.kid.as_deref().expect("signing kid"))
        .expect("published verification key");
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_issuer(&["https://issuer.example"]);
    validation.set_audience(&[&client.client_id]);
    validation.validate_nbf = true;
    validation.leeway = 0;
    let decoded = jsonwebtoken::decode::<Value>(
        token,
        &jsonwebtoken::DecodingKey::from_jwk(key).unwrap(),
        &validation,
    )
    .expect("real JARM signature and claims");
    let claims = decoded.claims;
    let code = claims["code"].as_str().expect("real authorization code");
    assert!(!code.is_empty());
    let issued = claims["iat"].as_i64().unwrap();
    assert!(issued >= before && issued <= chrono::Utc::now().timestamp());
    let jti = claims["jti"].as_str().unwrap();
    assert_eq!(uuid::Uuid::parse_str(jti).unwrap().get_version_num(), 7);
    assert_eq!(
        claims,
        json!({"iss": "https://issuer.example", "aud": client.client_id,
        "iat": issued, "nbf": issued, "exp": issued + state.settings.protocol.auth_code_ttl_seconds as i64,
        "jti": jti, "code": code, "state": "golden-state"})
    );
    assert!(to_bytes(response.into_body()).await.unwrap().is_empty());
}

#[actix_web::test]
async fn t00_form_post_exact_document_and_security_headers_bind_observed_nonce() {
    let state = live_transport_state().await;
    let (client, _) = client(&state, None).await;
    let response = authorized_response(&state, &client, "form_post", "state<&\"'").await;
    assert_eq!(response.status(), StatusCode::OK);
    for (name, value) in [
        ("content-type", "text/html; charset=utf-8"),
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
    ] {
        assert_eq!(response.headers().get(name).unwrap(), value);
    }
    assert!(!response.headers().contains_key(header::LOCATION));
    let csp = response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let nonce = csp.strip_prefix("default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action https://client.example; script-src 'nonce-")
        .and_then(|tail| tail.strip_suffix('\'')).expect("exact CSP structure");
    assert!(URL_SAFE_NO_PAD.decode(nonce).unwrap().len() >= 32);
    let body = to_bytes(response.into_body()).await.unwrap();
    let document = std::str::from_utf8(&body).expect("form_post is UTF-8");
    let code = document
        .split("name=\"code\" value=\"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("real authorization code input");
    assert!(!code.is_empty());
    let expected = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Continue</title></head><body><form method=\"post\" action=\"https://client.example/callback\">\n<input type=\"hidden\" name=\"code\" value=\"{code}\">\n<input type=\"hidden\" name=\"state\" value=\"state&lt;&amp;&quot;&#x27;\">\n<input type=\"hidden\" name=\"iss\" value=\"https://issuer.example\">\n<noscript><button type=\"submit\">Continue</button></noscript></form><script nonce=\"{nonce}\">document.forms[0].submit();</script></body></html>"
    );
    assert_eq!(body.as_ref(), expected.as_bytes());

    let escaped = nazo_http_actix::form_post_authorization_response(
        CALLBACK,
        &[
            ("code".to_owned(), "code<&\"'".to_owned()),
            ("state".to_owned(), "state<&\"'".to_owned()),
            ("iss".to_owned(), "https://issuer.example".to_owned()),
        ],
        None,
        nonce,
    );
    let escaped_body = to_bytes(escaped.into_body()).await.unwrap();
    let escaped_expected = expected.replace(
        &format!("name=\"code\" value=\"{code}\""),
        "name=\"code\" value=\"code&lt;&amp;&quot;&#x27;\"",
    );
    assert_eq!(escaped_body.as_ref(), escaped_expected.as_bytes());
}
