use super::*;
use crate::test_support::{UnknownAttestationAck, client_signing_fixture};
use nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator;
use nazo_auth::AuthorizationStateStorePort;
use std::collections::HashMap;

fn signed_attestation(client_id: &str) -> (Openid4vcClientAttestationValidator, String, String, String) {
    signed_attestation_at(client_id, Utc::now().timestamp() + 60)
}

fn signed_attestation_at(client_id: &str, issued_at: i64) -> (Openid4vcClientAttestationValidator, String, String, String) {
    let attester = client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let instance = client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("oauth-client-attestation+jwt".to_owned());
    header.kid = Some("attester".to_owned());
    let now = Utc::now().timestamp();
    let attestation = attester.encode_jwt(&header, &json!({
        "iss":"https://attester.example", "sub":client_id, "exp":now+600,
        "cnf":{"jwk":instance.public_jwk("instance")},
    }));
    header.typ = Some("oauth-client-attestation-pop+jwt".to_owned());
    header.kid = None;
    let jti = Uuid::now_v7().to_string();
    let proof = instance.encode_jwt(&header, &json!({
        "iss":client_id, "aud":"https://issuer.example", "iat":issued_at, "jti":jti,
    }));
    let validator = Openid4vcClientAttestationValidator::new(
        "https://attester.example", json!({"keys":[attester.public_jwk("attester")]}),
    ).unwrap();
    (validator, attestation, proof, jti)
}

async fn par_with_state(
    state: &TestInfrastructure,
    replay: Arc<dyn AuthorizationStateStorePort>,
    client_id: &str,
    validator: &Openid4vcClientAttestationValidator,
    attestation: &str,
    proof: &str,
) -> HttpResponse {
    let dependencies = crate::test_support::TestAuthorizationDependencies::new(state);
    let original = &dependencies.fixture;
    let fixture = crate::test_support::AuthorizationTestFixture::new(
        ServerAuthorizationService::from_port(
            Arc::new(nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID)),
            replay, state.keyset.clone(),
        ),
        original.config.clone(), original.client_ip.clone(), original.sessions.clone(),
        original.session_http.clone(), original.enabled_modules.clone(),
        state.keyset.clone(), DEFAULT_TENANT_ID,
    );
    let application = fixture.application();
    let transport = nazo_oauth_server::contracts::token_client_auth::TokenClientAuthTransportFacts::from_parts(
        nazo_oauth_server::contracts::token_client_auth::BasicAuthorizationCredentials::Absent,
        Some(client_id.to_owned()), None, None, None,
    );
    let params = HashMap::from([
        ("client_id".to_owned(), client_id.to_owned()),
        ("response_type".to_owned(), "code".to_owned()),
        ("redirect_uri".to_owned(), "https://client.example/callback".to_owned()),
        ("scope".to_owned(), "openid".to_owned()),
        ("code_challenge".to_owned(), nazo_oauth_server::crypto::pkce_s256(&"a".repeat(43))),
        ("code_challenge_method".to_owned(), "S256".to_owned()),
    ]);
    let result = async {
        application.begin_par("127.0.0.1").await?
            .prepare_parameters(params, false, Some((attestation, proof)))?
            .prepare_client(&transport, false, true).await?
            .par(nazo_oauth_server::authorization::par::ParRequestFacts {
                client_auth: nazo_oauth_server::token::client_auth::ClientAuthRequestFacts::new("/par", None),
                dpop: nazo_oauth_server::contracts::request_facts::DpopRequestFacts {
                    method: http::Method::POST, path: "/par", proof: Ok(None), proof_present: false,
                },
                mtls_thumbprint: None, attestation: Some((attestation, proof)),
            }, Some(validator)).await
    }.await;
    match result {
        Ok(body) => HttpResponse::Ok().json(body),
        Err(error) => nazo_http_actix::oauth_endpoint_error_response(error),
    }
}

#[actix_web::test]
async fn client_attestation_post_nx_unknown_fails_closed_in_token_and_par_with_real_marker() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    for start_with_par in [false, true] {
        let client_id = format!("attestation-unknown-{}", Uuid::now_v7());
        insert_token_client(&state, &client_id, "confidential", "attest_jwt_client_auth", None,
            vec!["authorization_code", "client_credentials"], false, false, true).await;
        let (validator, attestation, proof, jti) = signed_attestation(&client_id);
        let validator = Arc::new(validator);
        let real: Arc<dyn AuthorizationStateStorePort> = Arc::new(nazo_valkey::AuthorizationStateAdapter::new(&state.valkey_connection()));
        let replay: Arc<dyn AuthorizationStateStorePort> = Arc::new(UnknownAttestationAck::new(real));
        let token = |replay: Arc<dyn AuthorizationStateStorePort>| {
            let req = actix_web::test::TestRequest::post().uri("/token")
                .insert_header(("content-type", "application/x-www-form-urlencoded"))
                .insert_header(("OAuth-Client-Attestation", attestation.as_str()))
                .insert_header(("OAuth-Client-Attestation-PoP", proof.as_str()))
                .to_http_request();
            token_with_port_repositories_and_state(
                state.clone(), Arc::new(crate::test_support::token_issuance_repository(state.diesel_db.clone())),
                Arc::new(nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID)),
                replay,
                Arc::new(crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[]).unwrap()),
                Openid4vcTokenHandles { credential_issuer: None, client_attestation: Some(validator.clone()) },
                req, Bytes::from(format!("grant_type=client_credentials&client_id={client_id}&scope=accounts")),
            )
        };
        let response = if start_with_par {
            par_with_state(&state, replay.clone(), &client_id, &validator, &attestation, &proof).await
        } else {
            token(replay.clone()).await
        };
        let (status, body) = token_json_body(response).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "server_error");
        assert!(body.get("access_token").is_none() && body.get("request_uri").is_none());
        let key = nazo_valkey::test_support::client_attestation_replay_storage_key(&client_id, &jti);
        assert_eq!(crate::test_support::valkey::valkey_get(&state.valkey, &key).await.unwrap().as_deref(), Some("1"));
        let response = if start_with_par {
            token(replay.clone()).await
        } else {
            par_with_state(&state, replay.clone(), &client_id, &validator, &attestation, &proof).await
        };
        let (status, body) = token_json_body(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client_attestation");
        assert!(body.get("access_token").is_none() && body.get("request_uri").is_none());
    }
}


async fn owner_time(state: &TestInfrastructure) -> i64 {
    crate::test_support::valkey::valkey_eval_string(
        &state.valkey, "return redis.call('TIME')[1]", Vec::new(), Vec::new(),
    ).await.unwrap().parse().unwrap()
}

#[actix_web::test]
async fn signed_attestation_slow_node_cannot_reinsert_after_real_owner_expiry() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let now = owner_time(&state).await;
    let client_id = format!("attestation-clock-{}", Uuid::now_v7());
    let (validator, attestation, proof, jti) = signed_attestation_at(&client_id, now - 298);
    let fast = validator.validate(&attestation, &proof, "https://issuer.example", now + 1).unwrap();
    let slow = validator.validate(&attestation, &proof, "https://issuer.example", now).unwrap();
    assert_eq!(fast.replay_window, slow.replay_window);
    let owner = nazo_valkey::AuthorizationStateAdapter::new(&state.valkey_connection());
    assert!(owner.consume_client_attestation_proof(&client_id, &jti, fast.replay_window).await.unwrap());
    tokio::time::timeout(StdDuration::from_secs(5), async {
        while owner_time(&state).await < fast.replay_window.expires_at() {
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
    }).await.expect("the real replay owner reaches the marker expiry");
    let key = nazo_valkey::test_support::client_attestation_replay_storage_key(&client_id, &jti);
    assert!(crate::test_support::valkey::valkey_get(&state.valkey, &key).await.unwrap().is_none());
    // The same signed proof still passes a node one second behind the owner.
    let slow = validator.validate(&attestation, &proof, "https://issuer.example", fast.replay_window.expires_at() - 1).unwrap();
    assert_eq!(slow.replay_window, fast.replay_window);
    assert!(!owner.consume_client_attestation_proof(&client_id, &jti, slow.replay_window).await.unwrap());
    assert!(crate::test_support::valkey::valkey_get(&state.valkey, &key).await.unwrap().is_none());
}
