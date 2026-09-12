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
                    "audit_preflight",
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
