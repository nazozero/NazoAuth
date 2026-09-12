use super::*;
use crate::contracts::oauth_error::OAuthErrorFields;
use crate::domain::oauth::RefreshTokenPolicy;
use crate::test_support::authorization as authorization_fixture;
use http::StatusCode;
use nazo_auth::CibaStatus;
fn fields(error: &OAuthEndpointError) -> &OAuthErrorFields {
    let OAuthEndpointError::Token {
        fields,
        basic_challenge,
    } = error
    else {
        panic!("expected token error")
    };
    assert!(!basic_challenge);
    fields
}
#[test]
fn ciba_poll_storage_failure_returns_503_and_never_protocol_progress() {
    let error = ciba_poll_failure_error(CibaPollFailure::Storage(
        nazo_auth::CibaStatePortError::CorruptData,
    ));
    assert_eq!(fields(&error).status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fields(&error).error, "server_error");
}
#[test]
fn ciba_poll_failures_preserve_invalid_grant_and_contention_boundaries() {
    for (failure, status, code) in [
        (
            CibaPollFailure::Missing,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            CibaPollFailure::ClientMismatch,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            CibaPollFailure::Contended,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        ),
    ] {
        let error = ciba_poll_failure_error(failure);
        assert_eq!(fields(&error).status, status);
        assert_eq!(fields(&error).error, code);
    }
}
#[test]
fn ciba_token_grant_state_rejects_other_client_auth_req_id_as_invalid_grant() {
    let mut ciba = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: None,
        authentication_context: None,
        binding_message: None,
        issued_at: Utc::now().timestamp(),
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: Utc::now().timestamp() + 600,
        retention_expires_at: Utc::now().timestamp() + 720,
        last_poll_at: None,
        ping_notification: None,
    };
    let mut client = authorization_fixture::client(true);
    client.client_id = "client-2".to_owned();

    let error = ciba_auth_req_id_client_error(&ciba, &client)
        .expect("auth_req_id issued to another client must be rejected");
    let response = fields(&error);

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(Some(response.error.as_str()), Some("invalid_grant"));

    ciba.client_id = client.client_id.clone();
    assert!(ciba_auth_req_id_client_error(&ciba, &client).is_none());
}
#[test]
fn ciba_token_issue_allows_refresh_and_binds_refresh_sender_constraint() {
    let authentication_context = CibaAuthenticationContext {
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-approved".to_owned()),
    };
    let ciba = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: Some("1".to_owned()),
        authentication_context: None,
        binding_message: None,
        issued_at: Utc::now().timestamp(),
        status: CibaStatus::Approved,
        interval_seconds: 5,
        expires_at: Utc::now().timestamp() + 600,
        retention_expires_at: Utc::now().timestamp() + 720,
        last_poll_at: None,
        ping_notification: None,
    };

    let issue = ciba_token_issue(
        ciba.user_id,
        "subject-1".to_owned(),
        ciba,
        authentication_context,
        Some("dpop-jkt".to_owned()),
        None,
    );

    assert!(issue.include_refresh);
    assert_eq!(issue.refresh_token_policy, RefreshTokenPolicy::IssueNew);
    assert_eq!(issue.dpop_jkt.as_deref(), Some("dpop-jkt"));
    assert_eq!(issue.refresh_token_dpop_jkt.as_deref(), Some("dpop-jkt"));
    assert_eq!(issue.scopes, vec!["openid", "offline_access"]);
}
#[test]
fn ciba_token_issue_transfers_approved_authentication_context() {
    let user_id = Uuid::now_v7();
    let authentication_context = CibaAuthenticationContext {
        auth_time: 1_700_000_000,
        amr: vec!["pwd".to_owned(), "otp".to_owned()],
        oidc_sid: Some("sid-approved".to_owned()),
    };
    let ciba = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id,
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: Some("1".to_owned()),
        authentication_context: None,
        binding_message: None,
        issued_at: 1_700_000_100,
        status: CibaStatus::Approved,
        interval_seconds: 5,
        expires_at: 1_700_000_600,
        retention_expires_at: 1_700_000_720,
        last_poll_at: None,
        ping_notification: None,
    };

    let issue = ciba_token_issue(
        user_id,
        "subject-1".to_owned(),
        ciba,
        authentication_context,
        None,
        None,
    );

    assert_eq!(issue.auth_time, Some(1_700_000_000));
    assert_eq!(issue.amr, vec!["pwd", "otp"]);
    assert_eq!(issue.oidc_sid.as_deref(), Some("sid-approved"));
}
