use super::ConsentPayload;
use chrono::{Duration, Utc};
use nazo_auth::parse_scope;
use serde_json::{Value, json};
use uuid::Uuid;
pub(super) fn stored_grant_covers_requested_authorization(
    stored_scopes: &Value,
    stored_resource_indicators: &Value,
    stored_authorization_details: &Value,
    requested_scopes: &[String],
    requested_resource_indicators: &[String],
    requested_authorization_details: &Value,
) -> bool {
    nazo_auth::stored_grant_covers_requested_authorization(
        &nazo_auth::StoredAuthorizationGrant {
            scopes: stored_scopes.clone(),
            resource_indicators: stored_resource_indicators.clone(),
            authorization_details: stored_authorization_details.clone(),
        },
        requested_scopes,
        requested_resource_indicators,
        requested_authorization_details,
    )
}

#[test]
fn stored_grant_covers_prompt_none_request_when_scope_is_subset() {
    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "profile", "email"]),
        &json!([]),
        &json!([]),
        &parse_scope("openid email"),
        &[],
        &json!([]),
    ));
}

#[test]
fn stored_grant_does_not_cover_new_or_malformed_scope_sets() {
    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "profile"]),
        &json!([]),
        &json!([]),
        &parse_scope("openid email"),
        &[],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &json!({"scope": "openid"}),
        &json!([]),
        &json!([]),
        &parse_scope("openid"),
        &[],
        &json!([]),
    ));
}

#[test]
fn stored_grant_does_not_cover_new_resource_indicators() {
    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "email"]),
        &json!([
            "https://api.example/accounts",
            "https://api.example/profile"
        ]),
        &json!([]),
        &parse_scope("openid"),
        &[String::from("https://api.example/accounts")],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "email"]),
        &json!(["https://api.example/accounts"]),
        &json!([]),
        &parse_scope("openid"),
        &[String::from("https://api.example/payments")],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "email"]),
        &json!({"resource": "https://api.example/accounts"}),
        &json!([]),
        &parse_scope("openid"),
        &[String::from("https://api.example/accounts")],
        &json!([]),
    ));
}

#[test]
fn stored_grant_treats_empty_requested_authorization_details_as_already_covered() {
    let stored_high_risk_details = json!([{
        "type": "payment_initiation",
        "actions": ["write"],
        "instructedAmount": {"currency": "USD", "amount": "10.00"}
    }]);

    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "payments"]),
        &json!([]),
        &stored_high_risk_details,
        &parse_scope("openid"),
        &[],
        &json!([]),
    ));
}

#[test]
fn stored_grant_requires_exact_authorization_details_binding() {
    let scopes = json!(["openid", "payments"]);
    let read_details = json!([{"type":"account_information","actions":["read"]}]);
    let different_read_details =
        json!([{"type":"account_information","actions":["read"],"locations":["acct-2"]}]);

    assert!(stored_grant_covers_requested_authorization(
        &scopes,
        &json!([]),
        &read_details,
        &parse_scope("openid payments"),
        &[],
        &read_details,
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &scopes,
        &json!([]),
        &read_details,
        &parse_scope("openid payments"),
        &[],
        &different_read_details,
    ));
}

#[test]
fn stored_grant_never_silently_reuses_high_risk_authorization_details() {
    let payment_details = json!([{
        "type": "payment_initiation",
        "actions": ["write"],
        "instructedAmount": {"currency": "USD", "amount": "10.00"}
    }]);

    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "payments"]),
        &json!([]),
        &payment_details,
        &parse_scope("openid payments"),
        &[],
        &payment_details,
    ));
}

fn prompt_none_payload() -> ConsentPayload {
    let now = Utc::now();
    ConsentPayload {
        request_id: format!("request-{}", Uuid::now_v7()),
        user_id: crate::test_support::authorization::account().id(),
        client_id: "client-prompt-none".to_owned(),
        client_name: "Prompt None Client".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        state: Some("opaque-state".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("oidc-session".to_owned()),
        acr: None,
        userinfo_claim_requests: ((vec!["email".to_owned()])
            .into_iter()
            .map(nazo_auth::OidcClaimRequest::named)
            .collect::<Vec<_>>())
        .into(),
        id_token_claim_requests: ((vec!["sid".to_owned()])
            .into_iter()
            .map(nazo_auth::OidcClaimRequest::named)
            .collect::<Vec<_>>())
        .into(),
        pkce: (Some(crate::crypto::pkce_s256(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )))
        .into(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        pushed_request_digest: None,
        signed_authorization_response_required: Some(false),
        session_management_allowed: Some(false),
        authorization_code_ttl_seconds: Some(60),
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    }
}

#[test]
fn prompt_none_preserves_original_private_payload_claims_when_storing_code() {
    use super::issue_authorization_code_without_interaction_with_context;
    use crate::authorization::{AuthorizationOutcome, AuthorizationRequestFacts};
    use crate::test_support::authorization::Fixture;
    use std::sync::atomic::Ordering;
    let fixture = Fixture::new(
        Err(nazo_auth::AuthorizationPortError::Unavailable),
        Ok(Some(crate::test_support::authorization::session())),
    );
    fixture
        .ports
        .record_code_writes
        .store(true, Ordering::SeqCst);
    fixture.ports.decisions.lock().unwrap().outcome =
        Some(Ok(nazo_auth::AuthorizationDecisionCommitResult::Committed));
    let application = fixture.make_application();
    let payload = prompt_none_payload();
    let session_id = nazo_identity::SessionId::new("session-1");
    let facts = AuthorizationRequestFacts {
        source_ip: "192.0.2.10",
        session_id: Some(&session_id),
        user_agent: None,
    };
    let result =
        futures_executor::block_on(issue_authorization_code_without_interaction_with_context(
            &application.context(),
            &facts,
            payload.clone(),
            None,
            None,
        ))
        .expect("the normalized private payload issues a code");
    let AuthorizationOutcome::Redirect { location } = result else {
        panic!("query response must redirect")
    };
    let location = url::Url::parse(&location).unwrap();
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    let code = query.get("code").expect("redirect carries issued code");
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        query.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(!query.contains_key("error"));
    let writes = fixture.ports.stored_codes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].hash, crate::crypto::blake3_hex(code));
    assert_eq!(writes[0].ttl_seconds, 60);
    let nazo_auth::AuthorizationCodeState::Pending { payload: stored } = &writes[0].state else {
        panic!("new code must be pending")
    };
    assert_eq!(stored.user_id, payload.user_id);
    assert_eq!(stored.client_id, payload.client_id);
    assert_eq!(stored.scopes, payload.scopes);
    assert_eq!(stored.nonce, payload.nonce);
    assert_eq!(stored.oidc_sid, payload.oidc_sid);
    assert_eq!(stored.id_token_claim_requests.names(), vec!["sid"]);
    assert_eq!(
        stored.id_token_claim_requests.names(),
        payload.id_token_claim_requests.names()
    );
    assert_eq!(
        stored.userinfo_claim_requests.names(),
        payload.userinfo_claim_requests.names()
    );
    assert_eq!((stored.expires_at - stored.issued_at).num_seconds(), 60);
    assert_eq!(
        fixture.ports.calls(),
        [
            "audit_transactional_ready",
            "commit_decision",
            "store_authorization_code",
            "session",
            "session_compare_and_set",
        ]
    );
    let decisions = fixture.ports.decisions.lock().unwrap();
    assert_eq!(decisions.facts.len(), 1);
    assert_eq!(decisions.explicit_grant_writes, 0);
    assert_eq!(decisions.facts[0].audit_fields["code_hash"], writes[0].hash);
}

fn pushed_prompt_none_fixture() -> (
    crate::test_support::authorization::Fixture,
    ConsentPayload,
    String,
    chrono::DateTime<Utc>,
) {
    let fixture = crate::test_support::authorization::Fixture::new(
        Err(nazo_auth::AuthorizationPortError::Unavailable),
        Ok(Some(crate::test_support::authorization::session())),
    );
    fixture
        .ports
        .record_code_writes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    fixture.ports.decisions.lock().unwrap().outcome =
        Some(Ok(nazo_auth::AuthorizationDecisionCommitResult::Committed));
    let mut payload = prompt_none_payload();
    let uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    let par_expires_at = payload.expires_at + Duration::minutes(5);
    let pushed = nazo_auth::PushedAuthorizationRequest {
        client_id: payload.client_id.clone(),
        params: std::collections::HashMap::from([("state".into(), "original-state".into())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: payload.issued_at,
        expires_at: par_expires_at,
    };
    payload.pushed_request_uri = Some(uri.clone());
    payload.pushed_request_digest =
        Some(nazo_auth::pushed_authorization_request_digest(&pushed).unwrap());
    fixture
        .ports
        .stored_par
        .lock()
        .unwrap()
        .push((uri.clone(), pushed, 60));
    let version = futures_executor::block_on(fixture.service.load_par(&uri))
        .unwrap()
        .unwrap()
        .version;
    (fixture, payload, version, par_expires_at)
}

#[test]
fn prompt_none_commit_preserves_original_expiry_and_changed_cleanup_snapshot() {
    let (fixture, payload, version, par_expires_at) = pushed_prompt_none_fixture();
    fixture.ports.stored_par.lock().unwrap()[0]
        .1
        .params
        .insert("state".into(), "replacement-state".into());
    let application = fixture.make_application();
    let session_id = nazo_identity::SessionId::new("session-1");
    let facts = crate::authorization::AuthorizationRequestFacts {
        source_ip: "192.0.2.10",
        session_id: Some(&session_id),
        user_agent: None,
    };
    let outcome = futures_executor::block_on(
        super::issue_authorization_code_without_interaction_with_context(
            &application.context(),
            &facts,
            payload.clone(),
            Some(par_expires_at),
            Some(&version),
        ),
    )
    .unwrap();
    let crate::authorization::AuthorizationOutcome::Redirect { location } = outcome else {
        panic!("query response must redirect")
    };
    let location = url::Url::parse(&location).unwrap();
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert!(query.contains_key("code"));
    assert!(!query.contains_key("error"));
    assert_eq!(fixture.ports.stored_codes.lock().unwrap().len(), 1);
    let decisions = fixture.ports.decisions.lock().unwrap();
    assert_eq!(decisions.facts[0].valid_until, payload.expires_at);
    assert_eq!(decisions.facts[0].retain_until, par_expires_at);
    drop(decisions);
    assert_eq!(
        fixture.ports.stored_par.lock().unwrap()[0].1.params["state"],
        "replacement-state"
    );
}

#[test]
fn competing_prompt_none_requests_with_one_par_snapshot_write_one_code() {
    let (fixture, payload, version, par_expires_at) = pushed_prompt_none_fixture();
    let application = fixture.make_application();
    let context = application.context();
    let session_id = nazo_identity::SessionId::new("session-1");
    let facts = crate::authorization::AuthorizationRequestFacts {
        source_ip: "192.0.2.10",
        session_id: Some(&session_id),
        user_agent: None,
    };
    let (first, second) = futures_executor::block_on(async {
        futures_util::join!(
            super::issue_authorization_code_without_interaction_with_context(
                &context,
                &facts,
                payload.clone(),
                Some(par_expires_at),
                Some(&version)
            ),
            super::issue_authorization_code_without_interaction_with_context(
                &context,
                &facts,
                payload.clone(),
                Some(par_expires_at),
                Some(&version)
            ),
        )
    });
    let queries = [first, second]
        .into_iter()
        .map(|outcome| {
            let crate::authorization::AuthorizationOutcome::Redirect { location } =
                outcome.unwrap()
            else {
                panic!("query response must redirect")
            };
            url::Url::parse(&location)
                .unwrap()
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        queries
            .iter()
            .filter(|query| query.contains_key("code"))
            .count(),
        1
    );
    assert_eq!(
        queries
            .iter()
            .filter(|query| query.get("error").map(String::as_str) == Some("invalid_request_uri"))
            .count(),
        1
    );
    assert_eq!(fixture.ports.stored_codes.lock().unwrap().len(), 1);
    assert!(
        fixture.ports.stored_par.lock().unwrap().is_empty(),
        "preparation is removed; the durable PAR fence still permits one code"
    );
}

fn ready_prompt_none_fixture(
    stored: Result<Option<nazo_identity::SessionSnapshot>, nazo_identity::ports::RepositoryError>,
) -> (crate::test_support::authorization::Fixture, ConsentPayload) {
    let fixture = crate::test_support::authorization::Fixture::new(
        Err(nazo_auth::AuthorizationPortError::Unavailable),
        stored,
    );
    fixture
        .ports
        .record_code_writes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    fixture.ports.decisions.lock().unwrap().outcome =
        Some(Ok(nazo_auth::AuthorizationDecisionCommitResult::Committed));
    (fixture, prompt_none_payload())
}

fn issue_prompt_none_for_session(
    fixture: &crate::test_support::authorization::Fixture,
    payload: ConsentPayload,
    session_id: &nazo_identity::SessionId,
) -> Result<
    crate::authorization::AuthorizationOutcome,
    crate::contracts::oauth_error::OAuthEndpointError,
> {
    let application = fixture.make_application();
    let facts = crate::authorization::AuthorizationRequestFacts {
        source_ip: "192.0.2.10",
        session_id: Some(session_id),
        user_agent: None,
    };
    futures_executor::block_on(
        super::issue_authorization_code_without_interaction_with_context(
            &application.context(),
            &facts,
            payload,
            None,
            None,
        ),
    )
}

fn assert_prompt_none_error(
    error: crate::contracts::oauth_error::OAuthEndpointError,
    status: http::StatusCode,
    code: &str,
) {
    use crate::contracts::oauth_error::OAuthEndpointError;
    let fields = match error {
        OAuthEndpointError::Json(fields) | OAuthEndpointError::Authorization(fields) => fields,
        other => panic!("unexpected prompt-none error: {other:?}"),
    };
    assert_eq!(fields.status, status);
    assert_eq!(fields.error, code);
}

fn assert_prompt_none_returns_code(outcome: crate::authorization::AuthorizationOutcome) {
    let crate::authorization::AuthorizationOutcome::Redirect { location } = outcome else {
        panic!("plain prompt-none response must redirect")
    };
    let location = url::Url::parse(&location).unwrap();
    assert!(
        location
            .query_pairs()
            .any(|(name, value)| name == "code" && !value.is_empty())
    );
    assert!(!location.query_pairs().any(|(name, _)| name == "error"));
}

#[test]
fn prompt_none_required_audit_failure_prevents_decision_code_and_session_mutation() {
    let fixture = crate::test_support::authorization::Fixture::new(
        Err(nazo_auth::AuthorizationPortError::Unavailable),
        Err(nazo_identity::ports::RepositoryError::Unavailable),
    );
    fixture
        .ports
        .audit_transactional_unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    // Neither commit admission nor code writes are configured: accidentally
    // reaching either port must fail the test before returning a response.
    let error = issue_prompt_none_for_session(
        &fixture,
        prompt_none_payload(),
        &nazo_identity::SessionId::new("session-1"),
    )
    .expect_err("required audit failure must not return an authorization code");
    assert_prompt_none_error(error, http::StatusCode::SERVICE_UNAVAILABLE, "server_error");
    assert_eq!(fixture.ports.calls(), ["audit_transactional_ready"]);
    assert!(fixture.ports.decisions.lock().unwrap().facts.is_empty());
    assert!(fixture.ports.stored_codes.lock().unwrap().is_empty());
}

#[test]
fn prompt_none_success_binds_rp_in_persisted_session_after_durable_decision() {
    let initial = crate::test_support::authorization::session();
    let mut record = initial.record().clone();
    record.add_logged_in_client("existing-rp");
    let initial = nazo_identity::SessionSnapshot::new(record, initial.version().clone());
    let (fixture, payload) = ready_prompt_none_fixture(Ok(Some(initial.clone())));
    let session_id = nazo_identity::SessionId::new("session-1");
    assert_prompt_none_returns_code(
        issue_prompt_none_for_session(&fixture, payload.clone(), &session_id).unwrap(),
    );
    assert_eq!(
        fixture.ports.calls(),
        [
            "audit_transactional_ready",
            "commit_decision",
            "store_authorization_code",
            "session",
            "session_compare_and_set",
        ]
    );
    let stored = fixture
        .ports
        .session
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .unwrap();
    assert_ne!(stored.version(), initial.version());
    let mut expected = initial.record().clone();
    expected.add_logged_in_client(&payload.client_id);
    assert_eq!(stored.record(), &expected);
    let current =
        futures_executor::block_on(fixture.sessions.current_session_by_id(session_id.as_str()))
            .unwrap()
            .unwrap();
    assert_eq!(
        current.logged_in_client_ids,
        ["existing-rp", payload.client_id.as_str()]
    );
    assert_eq!(current.oidc_sid, "oidc-session");
    assert_eq!(fixture.ports.decisions.lock().unwrap().facts.len(), 1);
    assert_eq!(fixture.ports.stored_codes.lock().unwrap().len(), 1);
}

#[test]
fn prompt_none_binding_conflict_reloads_and_preserves_another_rp() {
    let initial = crate::test_support::authorization::session();
    let mut concurrent = initial.record().clone();
    concurrent.add_logged_in_client("concurrent-rp");
    let (fixture, payload) = ready_prompt_none_fixture(Ok(Some(initial)));
    *fixture.ports.session_cas_conflict.lock().unwrap() =
        Some(nazo_identity::SessionSnapshot::new(
            concurrent,
            nazo_identity::SessionVersion::from_storage(
                b"concurrent-version".to_vec().into_boxed_slice(),
            ),
        ));
    assert_prompt_none_returns_code(
        issue_prompt_none_for_session(
            &fixture,
            payload.clone(),
            &nazo_identity::SessionId::new("session-1"),
        )
        .unwrap(),
    );
    let stored = fixture
        .ports
        .session
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.record().logged_in_client_ids(),
        ["concurrent-rp", payload.client_id.as_str()]
    );
    assert_eq!(
        fixture.ports.calls(),
        [
            "audit_transactional_ready",
            "commit_decision",
            "store_authorization_code",
            "session",
            "session_compare_and_set",
            "session",
            "session_compare_and_set",
        ]
    );
}

#[test]
fn prompt_none_session_binding_failure_never_returns_a_code_or_compensates_the_decision() {
    for fail_on_load in [false, true] {
        let stored = if fail_on_load {
            Err(nazo_identity::ports::RepositoryError::Unavailable)
        } else {
            Ok(Some(crate::test_support::authorization::session()))
        };
        let (fixture, payload) = ready_prompt_none_fixture(stored);
        fixture
            .ports
            .session_update_unavailable
            .store(!fail_on_load, std::sync::atomic::Ordering::SeqCst);
        let before = fixture.ports.session.lock().unwrap().clone();
        let error = issue_prompt_none_for_session(
            &fixture,
            payload,
            &nazo_identity::SessionId::new("session-1"),
        )
        .expect_err("binding failure must not expose the issued code in a response");
        assert_prompt_none_error(error, http::StatusCode::SERVICE_UNAVAILABLE, "server_error");
        assert_eq!(fixture.ports.decisions.lock().unwrap().facts.len(), 1);
        assert_eq!(fixture.ports.stored_codes.lock().unwrap().len(), 1);
        assert_eq!(*fixture.ports.session.lock().unwrap(), before);
        assert!(!fixture.ports.calls().contains(&"delete_session"));
        assert_eq!(
            fixture.ports.calls().contains(&"session_compare_and_set"),
            !fail_on_load
        );
    }
}

#[test]
fn prompt_none_logout_between_resolution_and_binding_prevents_code_response_and_session_revival() {
    let (fixture, payload) =
        ready_prompt_none_fixture(Ok(Some(crate::test_support::authorization::session())));
    let session_id = nazo_identity::SessionId::new("session-1");
    assert!(
        futures_executor::block_on(fixture.sessions.current_session_by_id(session_id.as_str()))
            .unwrap()
            .is_some()
    );
    futures_executor::block_on(fixture.sessions.delete_session(session_id.as_str())).unwrap();
    let outcome = issue_prompt_none_for_session(&fixture, payload, &session_id)
        .expect("lost session should return a protocol error redirect");
    assert_prompt_none_returns_login_required(outcome);
    assert!(
        fixture
            .ports
            .session
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .is_none()
    );
    assert!(!fixture.ports.calls().contains(&"session_compare_and_set"));
    assert_eq!(fixture.ports.decisions.lock().unwrap().facts.len(), 1);
    assert_eq!(fixture.ports.stored_codes.lock().unwrap().len(), 1);
    assert!(
        futures_executor::block_on(fixture.sessions.current_session_by_id(session_id.as_str()))
            .unwrap()
            .is_none()
    );
}

#[test]
fn prompt_none_non_oidc_authorization_does_not_read_or_bind_the_browser_session() {
    let (fixture, mut payload) =
        ready_prompt_none_fixture(Err(nazo_identity::ports::RepositoryError::Unavailable));
    payload.scopes = vec!["read".to_owned()];
    assert_prompt_none_returns_code(
        issue_prompt_none_for_session(
            &fixture,
            payload,
            &nazo_identity::SessionId::new("session-1"),
        )
        .unwrap(),
    );
    assert_eq!(
        fixture.ports.calls(),
        [
            "audit_transactional_ready",
            "commit_decision",
            "store_authorization_code",
        ]
    );
}

fn assert_prompt_none_returns_login_required(outcome: crate::authorization::AuthorizationOutcome) {
    let crate::authorization::AuthorizationOutcome::Redirect { location } = outcome else {
        panic!("login_required must use the selected query response mode")
    };
    let location = url::Url::parse(&location).unwrap();
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(
        query.get("error").map(String::as_str),
        Some("login_required")
    );
    assert!(!query.contains_key("code"));
    assert!(!query.contains_key("session_state"));
}

#[test]
fn prompt_none_oidc_without_session_id_does_not_return_a_code() {
    let (fixture, payload) = ready_prompt_none_fixture(Ok(None));
    let application = fixture.make_application();
    let facts = crate::authorization::AuthorizationRequestFacts {
        source_ip: "192.0.2.10",
        session_id: None,
        user_agent: None,
    };
    let outcome = futures_executor::block_on(
        super::issue_authorization_code_without_interaction_with_context(
            &application.context(),
            &facts,
            payload,
            None,
            None,
        ),
    )
    .unwrap();
    assert_prompt_none_returns_login_required(outcome);
    assert_eq!(
        fixture.ports.calls(),
        [
            "audit_transactional_ready",
            "commit_decision",
            "store_authorization_code",
        ]
    );
}

#[test]
fn prompt_none_rejected_commit_never_writes_a_code_or_binds_a_session() {
    let (fixture, payload) =
        ready_prompt_none_fixture(Err(nazo_identity::ports::RepositoryError::Unavailable));
    fixture
        .ports
        .record_code_writes
        .store(false, std::sync::atomic::Ordering::SeqCst);
    fixture.ports.decisions.lock().unwrap().outcome = Some(Ok(
        nazo_auth::AuthorizationDecisionCommitResult::GrantUnavailable,
    ));
    let outcome = issue_prompt_none_for_session(
        &fixture,
        payload,
        &nazo_identity::SessionId::new("session-1"),
    )
    .unwrap();
    let crate::authorization::AuthorizationOutcome::Redirect { location } = outcome else {
        panic!("rejected grant must produce a protocol error redirect")
    };
    let location = url::Url::parse(&location).unwrap();
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(
        query.get("error").map(String::as_str),
        Some("consent_required")
    );
    assert!(!query.contains_key("code"));
    assert_eq!(
        fixture.ports.calls(),
        ["audit_transactional_ready", "commit_decision"]
    );
    assert!(fixture.ports.decisions.lock().unwrap().facts.is_empty());
    assert!(fixture.ports.stored_codes.lock().unwrap().is_empty());
}

#[test]
fn prompt_none_cleanup_failure_preserves_success_and_durable_replay_fence() {
    let (fixture, payload, version, par_expires_at) = pushed_prompt_none_fixture();
    fixture
        .ports
        .par_cleanup_unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let application = fixture.make_application();
    let session_id = nazo_identity::SessionId::new("session-1");
    let facts = crate::authorization::AuthorizationRequestFacts {
        source_ip: "192.0.2.10",
        session_id: Some(&session_id),
        user_agent: None,
    };
    let first = futures_executor::block_on(
        super::issue_authorization_code_without_interaction_with_context(
            &application.context(),
            &facts,
            payload.clone(),
            Some(par_expires_at),
            Some(&version),
        ),
    )
    .unwrap();
    assert_prompt_none_returns_code(first);
    assert_eq!(fixture.ports.stored_par.lock().unwrap().len(), 1);
    let second = futures_executor::block_on(
        super::issue_authorization_code_without_interaction_with_context(
            &application.context(),
            &facts,
            payload,
            Some(par_expires_at),
            Some(&version),
        ),
    )
    .unwrap();
    let crate::authorization::AuthorizationOutcome::Redirect { location } = second else {
        panic!("replay must redirect with an error")
    };
    assert!(
        url::Url::parse(&location)
            .unwrap()
            .query_pairs()
            .any(|(k, v)| k == "error" && v == "invalid_request_uri")
    );
    assert_eq!(fixture.ports.stored_codes.lock().unwrap().len(), 1);
    assert_eq!(fixture.ports.decisions.lock().unwrap().facts.len(), 1);
    assert_eq!(
        fixture
            .ports
            .calls()
            .iter()
            .filter(|call| **call == "consume_par")
            .count(),
        1
    );
}
