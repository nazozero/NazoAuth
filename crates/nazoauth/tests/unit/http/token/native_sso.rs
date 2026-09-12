use crate::test_support::token_response_body as response_body;
use response_body::oauth_error_code;

use actix_web::http::StatusCode;
use chrono::Utc;
use nazo_oauth_server::contracts::token_forms::TokenForm;
use nazo_oauth_server::crypto::blake3_hex;
use nazo_oauth_server::domain::rows::ClientRow;
use nazo_oauth_server::services::ServerTokenService;
use nazo_oauth_server::token::issue::TokenIssuanceContext;
use nazo_oauth_server::token::native_sso::DEVICE_SSO_SCOPE;
use nazo_oauth_server::token::native_sso::NATIVE_SSO_DEVICE_SECRET_TYPE;
use nazo_oauth_server::token::native_sso::NATIVE_SSO_ID_TOKEN_TYPE;
use nazo_oauth_server::token::native_sso::decode_native_sso_id_token_with_service;
use nazo_oauth_server::token::native_sso::native_sso_client_authorized;
use nazo_oauth_server::token::native_sso::native_sso_device_secret_hash;
use nazo_oauth_server::token::native_sso::native_sso_issue_binding;
use nazo_oauth_server::token::native_sso::native_sso_profile_requested;
use nazo_oauth_server::token::native_sso::native_sso_requested;
use nazo_oauth_server::token::native_sso::native_sso_requested_scopes;
use nazo_oauth_server::token::native_sso::native_sso_subject_for_client;
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

pub(crate) fn native_sso_device_secret_key(device_secret: &str) -> String {
    format!(
        "oauth:native_sso:device_secret:{}",
        blake3_hex(device_secret)
    )
}

use crate::config::ConfigSource;
use crate::settings::Settings;
use crate::test_support::TestInfrastructure;
use nazo_postgres::create_pool;

use std::sync::Arc;

fn native_sso_state_with_signing_key() -> TestInfrastructure {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();

    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_native_sso_test_invalid:nazo_native_sso_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager_with_algorithm(
            jsonwebtoken::Algorithm::PS256,
        ),
    }
}

async fn signed_native_sso_id_token_with_claims(
    state: &TestInfrastructure,
    issuer: &str,
    auth_time: Option<Value>,
    amr: Option<Value>,
) -> String {
    let now = Utc::now().timestamp();
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
    let mut claims = json!({
        "iss": issuer,
        "sub": "subject-1",
        "aud": "source-client",
        "ds_hash": native_sso_device_secret_hash("device-secret"),
        "sid": "sid-1",
        "iat": now,
        "exp": now + 120
    });
    let object = claims
        .as_object_mut()
        .expect("Native SSO test claims should be an object");
    if let Some(auth_time) = auth_time {
        object.insert("auth_time".to_owned(), auth_time);
    }
    if let Some(amr) = amr {
        object.insert("amr".to_owned(), amr);
    }
    state
        .keyset
        .encode_jwt(nazo_auth::SigningPurpose::IdToken, &header, &claims)
        .await
        .expect("Native SSO id_token should sign")
}

async fn signed_native_sso_id_token(state: &TestInfrastructure, issuer: &str) -> String {
    let auth_time = Utc::now().timestamp() - 1;
    signed_native_sso_id_token_with_claims(
        state,
        issuer,
        Some(json!(auth_time)),
        Some(json!(["pwd"])),
    )
    .await
}

fn token_form() -> TokenForm {
    TokenForm {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: Some("id-token".to_owned()),
        subject_token_type: Some(NATIVE_SSO_ID_TOKEN_TYPE.to_owned()),
        actor_token: Some("device-secret".to_owned()),
        actor_token_type: Some(NATIVE_SSO_DEVICE_SECRET_TYPE.to_owned()),
        audiences: Vec::new(),
        has_audience_param: false,
    }
}

fn native_sso_client(scopes: Value) -> ClientRow {
    client_row! {
        id: Uuid::now_v7(),
        tenant_id: nazo_identity::DEFAULT_TENANT_ID,
        realm_id: nazo_identity::DEFAULT_REALM_ID,
        organization_id: nazo_identity::DEFAULT_ORGANIZATION_ID,
        client_id: "native-client".to_owned(),
        client_name: "Native client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://native.example/callback"]),
        scopes: scopes,
        allowed_audiences: json!(["https://issuer.example"]),
        grant_types: json!(["urn:ietf:params:oauth:grant-type:token-exchange"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
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
        is_active: true,
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
    }
}

#[actix_web::test]
async fn native_sso_issue_binding_enforces_client_sender_policy() {
    let state = native_sso_state_with_signing_key();
    let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = crate::http::token::issue::test_support::test_authorization_service(&state);
    let issuance = TokenIssuanceContext {
        config: &config,
        modules: &modules,
        authorization: &authorization,
        security_audit: crate::http::authorization::test_support::test_security_audit(),
        remote_client_documents: crate::test_support::test_remote_client_documents(),
    };
    let request = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let client = native_sso_client(json!(["openid"]));
    assert_eq!(
        native_sso_issue_binding(
            &issuance,
            &crate::http::token::issue::test_support::token_request_facts(
                &request,
                state.settings.as_ref()
            ),
            &client
        )
        .await
        .map_err(nazo_http_actix::oauth_endpoint_error_response)
        .expect("a client without sender constraints may issue an unbound token"),
        (None, None)
    );

    let mut dpop_client = native_sso_client(json!(["openid"]));
    dpop_client.require_dpop_bound_tokens = true;
    let response = native_sso_issue_binding(
        &issuance,
        &crate::http::token::issue::test_support::token_request_facts(
            &request,
            state.settings.as_ref(),
        ),
        &dpop_client,
    )
    .await
    .map_err(nazo_http_actix::oauth_endpoint_error_response)
    .expect_err("a DPoP-required client must present proof");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut mtls_client = native_sso_client(json!(["openid"]));
    mtls_client.require_mtls_bound_tokens = true;
    let response = native_sso_issue_binding(
        &issuance,
        &crate::http::token::issue::test_support::token_request_facts(
            &request,
            state.settings.as_ref(),
        ),
        &mtls_client,
    )
    .await
    .map_err(nazo_http_actix::oauth_endpoint_error_response)
    .expect_err("an mTLS-required client must present a verified certificate");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("invalid_grant")
    );
}

#[test]
fn native_sso_device_secret_key_does_not_embed_raw_secret() {
    let key = native_sso_device_secret_key("raw-device-secret");

    assert!(key.starts_with("oauth:native_sso:device_secret:"));
    assert!(!key.contains("raw-device-secret"));
}

#[test]
fn native_sso_profile_requires_id_token_and_device_secret_token_types() {
    let mut form = token_form();
    assert!(native_sso_profile_requested(&form));

    form.actor_token_type = Some("urn:ietf:params:oauth:token-type:access_token".to_owned());
    assert!(!native_sso_profile_requested(&form));

    let mut wrong_grant = token_form();
    wrong_grant.grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned();
    assert!(!native_sso_profile_requested(&wrong_grant));

    let mut wrong_subject_type = token_form();
    wrong_subject_type.subject_token_type = Some(NATIVE_SSO_DEVICE_SECRET_TYPE.to_owned());
    assert!(!native_sso_profile_requested(&wrong_subject_type));
}

#[test]
fn native_sso_scope_and_client_admission_are_fail_closed() {
    assert!(!native_sso_requested(&["openid".to_owned()]));
    assert!(native_sso_requested(&[
        "openid".to_owned(),
        DEVICE_SSO_SCOPE.to_owned()
    ]));

    let authorized = native_sso_client(json!(["openid", "offline_access", "device_sso"]));
    assert!(native_sso_client_authorized(&authorized));
    let unauthorized = native_sso_client(json!(["openid", "offline_access"]));
    assert!(!native_sso_client_authorized(&unauthorized));

    let defaults = native_sso_requested_scopes(&authorized, None)
        .expect("the documented Native SSO default scope set should be accepted");
    assert_eq!(
        defaults,
        vec![
            "openid".to_owned(),
            "offline_access".to_owned(),
            "device_sso".to_owned()
        ]
    );

    for invalid in [
        Some("offline_access device_sso"),
        Some("openid offline_access"),
    ] {
        assert!(native_sso_requested_scopes(&authorized, invalid).is_err());
    }
    assert!(native_sso_requested_scopes(&authorized, Some("openid device_sso admin")).is_err());
}

#[test]
fn native_sso_subject_policy_uses_client_specific_subject_mapping() {
    let state = native_sso_state_with_signing_key();
    let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
    let client = native_sso_client(json!(["openid", "offline_access", "device_sso"]));
    let subject = native_sso_subject_for_client(&config, Uuid::now_v7(), &client)
        .expect("configured public subject policy should map the user");
    assert!(!subject.is_empty());
}

#[tokio::test]
async fn native_sso_id_token_decoder_accepts_configured_issuer() {
    let state = native_sso_state_with_signing_key();
    let token = signed_native_sso_id_token(&state, state.settings.endpoint.issuer.as_str()).await;
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );

    let claims = decode_native_sso_id_token_with_service(
        &service,
        state.settings.endpoint.issuer.as_str(),
        &token,
    )
    .await
    .expect("token verification should remain available")
    .expect("configured issuer should decode");

    assert_eq!(claims.iss, state.settings.endpoint.issuer.as_str());
    assert_eq!(claims.sub, "subject-1");
    assert_eq!(claims.sid, "sid-1");
}

#[tokio::test]
async fn native_sso_id_token_decoder_rejects_wrong_issuer() {
    let state = native_sso_state_with_signing_key();
    let token = signed_native_sso_id_token(&state, "https://attacker.example").await;
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );

    assert!(
        decode_native_sso_id_token_with_service(
            &service,
            state.settings.endpoint.issuer.as_str(),
            &token,
        )
        .await
        .expect("token verification should remain available")
        .is_none()
    );
}

#[tokio::test]
async fn native_sso_id_token_decoder_rejects_missing_authentication_context_claims() {
    let state = native_sso_state_with_signing_key();
    let token = signed_native_sso_id_token_with_claims(
        &state,
        state.settings.endpoint.issuer.as_str(),
        None,
        Some(json!(["pwd"])),
    )
    .await;
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );

    assert!(matches!(
        decode_native_sso_id_token_with_service(
            &service,
            state.settings.endpoint.issuer.as_str(),
            &token,
        )
        .await,
        Err(nazo_auth::TokenPortError::CorruptData)
    ));
}

#[tokio::test]
async fn native_sso_id_token_decoder_rejects_invalid_authentication_context_claims() {
    let state = native_sso_state_with_signing_key();
    let token = signed_native_sso_id_token_with_claims(
        &state,
        state.settings.endpoint.issuer.as_str(),
        Some(json!("not-a-timestamp")),
        Some(json!("pwd")),
    )
    .await;
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );

    assert!(matches!(
        decode_native_sso_id_token_with_service(
            &service,
            state.settings.endpoint.issuer.as_str(),
            &token,
        )
        .await,
        Err(nazo_auth::TokenPortError::CorruptData)
    ));
}

#[tokio::test]
async fn native_sso_exchange_rejects_unbound_inputs_before_secret_store_access() {
    let state = native_sso_state_with_signing_key();
    let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
    let authorization = crate::http::token::issue::test_support::test_authorization_service(&state);
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    let valid_id_token = signed_native_sso_id_token(&state, &state.settings.endpoint.issuer).await;
    for case in 0..7 {
        let mut modules = state.active_module_snapshot();
        if case != 0 {
            modules
                .accepting
                .insert(nazo_runtime_modules::ModuleId::NativeSso);
        }
        let issuance = TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
            security_audit: crate::http::authorization::test_support::test_security_audit(),
            remote_client_documents: crate::test_support::test_remote_client_documents(),
        };
        let mut client = native_sso_client(json!(["openid", "offline_access", "device_sso"]));
        let mut form = token_form();
        form.audiences = vec![state.settings.endpoint.issuer.clone()];
        form.subject_token = Some(valid_id_token.clone());
        form.actor_token = Some("wrong-device-secret".into());
        let expected = match case {
            0 => "unsupported_grant_type",
            1 => {
                client.scopes.clear();
                "unauthorized_client"
            }
            2 => {
                form.audiences.clear();
                "invalid_target"
            }
            3 => {
                form.subject_token = None;
                "invalid_request"
            }
            4 => {
                form.actor_token = None;
                "invalid_request"
            }
            5 => {
                form.subject_token = Some("invalid-id-token".into());
                "invalid_grant"
            }
            _ => "invalid_grant",
        };
        let request = actix_web::test::TestRequest::post()
            .uri("/token")
            .to_http_request();
        let result = nazo_oauth_server::token::native_sso::token_native_sso_exchange(
            &service,
            &issuance,
            &crate::http::token::issue::test_support::token_request_facts(
                &request,
                state.settings.as_ref(),
            ),
            &client,
            &form,
            None,
        )
        .await;
        let error = result.expect_err("unbound input must be rejected");
        let response = nazo_http_actix::oauth_endpoint_error_response(error);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "case {case}");
        assert_eq!(oauth_error_code(response).await, expected, "case {case}");
    }
}
