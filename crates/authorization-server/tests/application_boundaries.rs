//! Public application calls executed without a web server or task scheduler.
use futures_executor::block_on;
use nazo_oauth_server as app;
#[path = "support/authorization.rs"]
mod authorization_fixture;
use app::{
    authorization::presentation::ClientPresentation, contracts::oauth_error::OAuthEndpointError,
};
use authorization_fixture::{Fixture, client, session};
use nazo_identity::SessionId;

#[test]
fn client_display_projects_only_registered_public_metadata() {
    let mut registered = client(true);
    registered.registration.client_name = "External consumer client".into();
    registered.registration.presentation.logo_uri = Some("https://client.example/logo.svg".into());
    let fixture = Fixture::new(Ok(Some(registered)), Ok(None));
    let output = block_on(fixture.make_application().client_presentation("client-1")).unwrap();
    assert_eq!(
        output,
        ClientPresentation {
            client_name: "External consumer client".into(),
            logo_uri: Some("https://client.example/logo.svg".into()),
            policy_uri: None,
            tos_uri: None,
        }
    );
    assert_eq!(fixture.ports.calls(), ["client"]);
}

#[test]
fn consent_loads_authenticated_account_before_request_state() {
    let fixture = Fixture::new(Ok(None), Ok(Some(session())));
    let application = fixture.make_application();
    let session_id = SessionId::new("external-consumer-session");
    let result = block_on(application.consent(Some(&session_id), Some("missing-request")));
    let Err(OAuthEndpointError::Json(fields)) = result else {
        panic!("missing consent request must return a typed JSON error")
    };
    assert_eq!(fields.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(fields.error, "invalid_request");
    assert_eq!(fixture.ports.calls(), ["session", "account", "consent"]);
}
