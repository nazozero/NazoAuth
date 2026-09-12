use app::{
    authorization::{
        AuthorizationApplication, AuthorizationRequestFacts, presentation::ClientPresentationError,
    },
    contracts::oauth_error::{OAuthEndpointError, OAuthErrorFields},
};
use futures_executor::block_on;
use http::StatusCode;
use nazo_auth::{AuthorizationPortError, OAuthClient};
use nazo_identity::{SessionId, ports::RepositoryError, session::SessionSnapshot};
use nazo_oauth_server as app;
use std::{collections::HashMap, sync::Arc};
#[path = "support/authorization.rs"]
mod authorization_fixture;
use authorization_fixture::{Fixture, Ports, client, session};

#[path = "support/par_application.rs"]
mod par_application;

fn application(
    client: Result<Option<OAuthClient>, AuthorizationPortError>,
    session: Result<Option<SessionSnapshot>, RepositoryError>,
) -> (AuthorizationApplication, Arc<Ports>) {
    let fixture = Fixture::new(client, session);
    (fixture.make_application(), fixture.ports)
}
fn assert_json_error(error: OAuthEndpointError, status: StatusCode, code: &str) {
    let OAuthEndpointError::Json(OAuthErrorFields {
        status: actual,
        error,
        ..
    }) = error
    else {
        panic!("expected JSON endpoint error")
    };
    assert_eq!(actual, status);
    assert_eq!(error, code);
}

#[test]
fn authorize_unverified_client_never_returns_redirect() {
    block_on(async {
        for (client, status, code) in [
            (Ok(None), StatusCode::UNAUTHORIZED, "unauthorized_client"),
            (
                Ok(Some(client(false))),
                StatusCode::UNAUTHORIZED,
                "unauthorized_client",
            ),
            (
                Err(AuthorizationPortError::Unavailable),
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
            ),
        ] {
            let (app, ports) = application(client, Ok(None));
            let mut parameters = HashMap::from([
                ("client_id".into(), "client-1".into()),
                (
                    "redirect_uri".into(),
                    "https://attacker.example/callback".into(),
                ),
                ("response_type".into(), "code".into()),
            ]);
            let facts = AuthorizationRequestFacts {
                source_ip: "192.0.2.1",
                session_id: None,
                user_agent: None,
            };
            let Err(error) = app.authorize(&facts, &mut parameters).await else {
                panic!("unverified client cannot yield an authorization outcome")
            };
            assert_json_error(error, status, code);
            assert_eq!(ports.calls(), ["client"]);
        }
    });
}

#[test]
fn authorize_unregistered_redirect_fails_before_session_or_state_access() {
    block_on(async {
        let (app, ports) = application(Ok(Some(client(true))), Ok(Some(session())));
        let sid = SessionId::new("active");
        let facts = AuthorizationRequestFacts {
            source_ip: "192.0.2.1",
            session_id: Some(&sid),
            user_agent: None,
        };
        let mut parameters = HashMap::from([
            ("client_id".into(), "client-1".into()),
            (
                "redirect_uri".into(),
                "https://attacker.example/callback".into(),
            ),
            ("response_type".into(), "code".into()),
        ]);
        let Err(OAuthEndpointError::Authorization(fields)) =
            app.authorize(&facts, &mut parameters).await
        else {
            panic!("unregistered redirect cannot yield an authorization outcome")
        };
        assert_eq!(fields.status, StatusCode::BAD_REQUEST);
        assert_eq!(fields.error, "invalid_request");
        assert_eq!(
            fields.description,
            "redirect_uri is not registered for this client."
        );
        assert_eq!(ports.calls(), ["client"]);
    });
}

#[test]
fn client_presentation_distinguishes_absence_and_repository_failure() {
    block_on(async {
        for (client, expected) in [
            (Ok(None), ClientPresentationError::NotFound),
            (Ok(Some(client(false))), ClientPresentationError::NotFound),
            (
                Err(AuthorizationPortError::Unavailable),
                ClientPresentationError::Unavailable,
            ),
        ] {
            let (app, ports) = application(client, Ok(None));
            assert_eq!(app.client_presentation("client-1").await, Err(expected));
            assert_eq!(ports.calls(), ["client"]);
        }
    });
}

#[test]
fn consent_checks_session_before_missing_request_id() {
    block_on(async {
        let (app, ports) = application(Ok(None), Ok(None));
        let Err(error) = app.consent(None, None).await else {
            panic!("missing session must fail")
        };
        assert_json_error(error, StatusCode::UNAUTHORIZED, "login_required");
        assert!(ports.calls().is_empty());
        let sid = SessionId::new("session");
        for (session, status, code, calls) in [
            (
                Ok(None),
                StatusCode::UNAUTHORIZED,
                "login_required",
                vec!["session"],
            ),
            (
                Err(RepositoryError::Unavailable),
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                vec!["session"],
            ),
            (
                Ok(Some(session())),
                StatusCode::BAD_REQUEST,
                "invalid_request",
                vec!["session", "account"],
            ),
        ] {
            let (app, ports) = application(Ok(None), session);
            let Err(error) = app.consent(Some(&sid), None).await else {
                panic!("missing request id must fail")
            };
            assert_json_error(error, status, code);
            assert_eq!(ports.calls(), calls);
        }
    });
}

#[test]
fn consent_reads_request_only_after_valid_session() {
    block_on(async {
        let (app, ports) = application(Ok(None), Ok(Some(session())));
        let sid = SessionId::new("active");
        let Err(error) = app.consent(Some(&sid), Some("missing-request")).await else {
            panic!("missing consent must fail")
        };
        assert_json_error(error, StatusCode::BAD_REQUEST, "invalid_request");
        assert_eq!(ports.calls(), ["session", "account", "consent"]);
    });
}
