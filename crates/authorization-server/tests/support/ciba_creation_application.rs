use super::*;
use app::token::client_auth::ClientAuthRequestFacts;
fn client() -> nazo_auth::OAuthClient {
    let mut client = authorization_fixture::client(true);
    client
        .grant_types
        .push("urn:openid:params:grant-type:ciba".into());
    client.security_policy.allow_cross_device_flows = true;
    client
}
fn form() -> BackchannelAuthenticationForm {
    BackchannelAuthenticationForm {
        client_id: Some("client-1".into()),
        client_secret: Some("test-secret".into()),
        scope: Some("openid".into()),
        login_hint: Some("alice@example.test".into()),
        ..Default::default()
    }
}
fn creation_fixture(
    failure: AuditFailure,
    client: nazo_auth::OAuthClient,
) -> (
    CibaApplication,
    Arc<Ports>,
    CurrentSession,
    authorization_fixture::Fixture,
) {
    let fixture = fixture_with_client(failure, client, true);
    *fixture.1.account.lock().unwrap() = Some(Ok(Some(fixture.2.user.clone())));
    let salt = app::crypto::random_urlsafe_token();
    *fixture.3.ports.client_secret.lock().unwrap() = Some((
        salt.clone(),
        app::crypto::client_secret_digest(
            "test-secret",
            &fixture.3.config.client_secret_pepper,
            &salt,
        ),
    ));
    fixture
}
async fn create(
    application: &CibaApplication,
    form: BackchannelAuthenticationForm,
) -> Result<app::contracts::ciba::CibaCreationResponse, OAuthEndpointError> {
    let transport = TokenClientAuthTransportFacts::from_parts(
        BasicAuthorizationCredentials::Absent,
        form.client_id.clone(),
        form.client_secret.clone(),
        form.client_assertion.clone(),
        form.client_assertion_type.clone(),
    );
    let prepared = application
        .prepare_client(prepare_ciba_creation(form, false)?, &transport, false)
        .await?;
    application
        .create(
            prepared,
            ClientAuthRequestFacts::new("/oauth/backchannel-authentication", None),
            "192.0.2.1",
        )
        .await
}
#[test]
fn creation_persists_pending_state_and_audit_before_returning_poll_or_ping_handle() {
    block_on(async {
        for ping in [false, true] {
            let mut client = client();
            let mut request = form();
            request.requested_expiry_seconds = Some(30);
            request.binding_message = Some("1234".into());
            if ping {
                client.backchannel_token_delivery_mode = "ping".into();
                client.backchannel_client_notification_endpoint =
                    Some("https://client.example/notify".into());
                request.client_notification_token = Some("notification-token-128-bits".into());
            }
            let (application, ports, session, _) = creation_fixture(AuditFailure::None, client);
            let response = create(&application, request).await.unwrap();
            assert!(!response.auth_req_id.is_empty());
            assert_eq!((response.expires_in, response.interval), (30, 5));
            assert_eq!(
                ports.calls(),
                [
                    "account",
                    "audit_dynamic_readiness",
                    "audit_intent",
                    "create",
                    "audit_result"
                ]
            );
            let state = ports.state.lock().unwrap();
            assert_eq!(state.user_id, session.user.id());
            assert_eq!(state.status, CibaStatus::Pending);
            assert_eq!(state.expires_at - state.issued_at, 30);
            assert_eq!(state.scopes, ["openid"]);
            assert_eq!(state.ping_notification.is_some(), ping);
            let intents = ports.intents.lock().unwrap();
            assert_eq!(
                intents[0]["source_ip_hash"],
                app::crypto::blake3_hex("192.0.2.1")
            );
            assert!(
                !serde_json::to_string(&intents[0])
                    .unwrap()
                    .contains("192.0.2.1")
            );
        }
    });
}
#[test]
fn invalid_creation_is_rejected_before_audit_and_state_mutation() {
    block_on(async {
        for case in 0..8 {
            let mut client = client();
            let mut request = form();
            let expected = match case {
                0 => {
                    client.grant_types.clear();
                    "unauthorized_client"
                }
                1 => {
                    client.security_policy.allow_cross_device_flows = false;
                    "unauthorized_client"
                }
                2 => {
                    request.scope = Some("profile".into());
                    "invalid_scope"
                }
                3 => {
                    request.login_hint = None;
                    "invalid_request"
                }
                4 => {
                    request.login_hint = Some("   ".into());
                    "invalid_request"
                }
                5 => {
                    request.acr_values = Some("unsupported-acr".into());
                    "invalid_request"
                }
                6 => {
                    request.client_secret = Some("incorrect-secret".into());
                    "invalid_client"
                }
                _ => {
                    client.require_par_request_object = true;
                    "invalid_request"
                }
            };
            let (application, ports, _, _) = creation_fixture(AuditFailure::None, client);
            let error = create(&application, request)
                .await
                .err()
                .expect("invalid creation must fail");
            assert_eq!(fields(&error).error, expected, "case {case}");
            assert!(!ports.calls().contains(&"create"));
            assert!(ports.intents.lock().unwrap().is_empty());
        }
    });
}
#[test]
fn creation_requires_active_user_and_durable_audit_and_reports_state_failure() {
    block_on(async {
        for failure in [
            AuditFailure::Preflight,
            AuditFailure::Intent,
            AuditFailure::Create,
        ] {
            let (application, ports, _, _) = creation_fixture(failure, client());
            let error = create(&application, form())
                .await
                .err()
                .expect("failure must propagate");
            assert_eq!(fields(&error).status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(!ports.calls().contains(&"audit_result"));
            if !matches!(failure, AuditFailure::Create) {
                assert!(!ports.calls().contains(&"create"));
            }
        }
        for inactive in [false, true] {
            let (application, ports, mut session, _) =
                creation_fixture(AuditFailure::None, client());
            session.user.principal.active = false;
            *ports.account.lock().unwrap() =
                Some(Ok(if inactive { Some(session.user) } else { None }));
            let error = create(&application, form())
                .await
                .err()
                .expect("unknown user must fail");
            assert_eq!(fields(&error).error, "unknown_user_id");
            assert_eq!(ports.calls(), ["account"]);
        }
    });
}

#[test]
fn ciba_creation_rejects_inactive_client_and_reports_account_repository_failure() {
    block_on(async {
        let mut inactive = client();
        inactive.is_active = false;
        let (application, ports, _, _) = creation_fixture(AuditFailure::None, inactive);
        let error = create(&application, form())
            .await
            .err()
            .expect("inactive client must fail");
        assert_eq!(fields(&error).error, "invalid_client");
        assert!(ports.calls().is_empty());
        let (application, ports, _, _) = creation_fixture(AuditFailure::None, client());
        *ports.account.lock().unwrap() = Some(Err(RepositoryError::Unavailable));
        let error = create(&application, form())
            .await
            .err()
            .expect("account store failure must propagate");
        assert_eq!(fields(&error).status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(ports.calls(), ["account"]);
    });
}

#[test]
fn short_creation_validity_starts_after_required_audit_and_request_replay_complete() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    block_on(async {
        let keys = nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::PS256);
        let mut client = client();
        client.jwks = Some(keys.snapshot().jwks());
        client.backchannel_authentication_request_signing_alg = Some("PS256".to_owned());
        let kid = keys.snapshot().verification_keys[0].kid.clone();
        let now = chrono::Utc::now().timestamp();
        let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg":"PS256","kid":kid,"typ":"oauth-authz-req+jwt"})).unwrap()), URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"client-1","aud":"https://issuer.example","iat":now,"exp":now+60,"jti":Uuid::now_v7().to_string()})).unwrap()));
        let signature = nazo_auth::Signer::sign(
            &keys,
            nazo_auth::SignRequest {
                purpose: nazo_auth::SigningPurpose::IdToken,
                algorithm: "PS256",
                signing_input: input.as_bytes(),
            },
        )
        .await
        .unwrap();
        let mut request = form();
        request.requested_expiry_seconds = Some(1);
        request.request = Some(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_bytes())
        ));
        let (application, ports, _, authorization) = creation_fixture(AuditFailure::None, client);
        ports.audit_delay_ms.store(1_100, Ordering::Relaxed);
        authorization
            .ports
            .ciba_replay_delay_ms
            .store(1_100, Ordering::Relaxed);
        *authorization.ports.ciba_request_replay.lock().unwrap() = Some(Ok(true));
        let started = std::time::Instant::now();
        let response = create(&application, request).await.unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(2_200));
        assert_eq!(response.expires_in, 1);
        let now = chrono::Utc::now().timestamp();
        let state = ports.state.lock().unwrap();
        assert_eq!(state.issued_at, now);
        assert_eq!(state.expires_at, now + 1);
        assert_eq!(
            *ports.create_deadlines.lock().unwrap(),
            [Some(state.expires_at)]
        );
        assert!(ports.calls().contains(&"audit_result"));
        assert!(
            authorization
                .ports
                .calls()
                .contains(&"ciba_request_object_replay")
        );
    });
}

#[test]
fn delayed_create_crossing_authorization_expiry_cannot_report_success_while_retention_is_live() {
    block_on(async {
        let (application, ports, _, _) = creation_fixture(AuditFailure::None, client());
        ports.create_delay_ms.store(1_100, Ordering::Relaxed);
        let mut request = form();
        request.requested_expiry_seconds = Some(1);
        let error = create(&application, request)
            .await
            .err()
            .expect("atomic authorization deadline must reject delayed creation");
        assert_eq!(fields(&error).status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!ports.calls().contains(&"create"));
        assert!(!ports.calls().contains(&"audit_result"));
        assert_eq!(
            ports.create_deadlines.lock().unwrap().len(),
            1,
            "deadline failure must not generate a new handle or retry"
        );
    });
}
