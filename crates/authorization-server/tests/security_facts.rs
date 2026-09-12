use std::sync::atomic::{AtomicUsize, Ordering};

use nazo_auth::{
    DpopError, DpopNoncePolicy, DpopStateFuture, DpopStateStoreError, DpopStateStorePort,
};
use nazo_oauth_server::{
    contracts::{
        oauth_error::OAuthEndpointError,
        request_facts::DpopRequestFacts,
        token_client_auth::{BasicAuthorizationCredentials, TokenClientAuthTransportFacts},
        token_endpoint::prepare_token_request,
        token_forms::{ParsedTokenForm, PreAuthorizedTokenParameters, TokenForm},
    },
    ports::audit::{AuditFuture, SecurityAudit},
    security::dpop::validate_dpop_proof,
};

fn parsed(grant_type: &str, has_audience_param: bool) -> ParsedTokenForm {
    ParsedTokenForm {
        form: TokenForm {
            grant_type: grant_type.to_owned(),
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
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audiences: Vec::new(),
            has_audience_param,
        },
        pre_authorized: PreAuthorizedTokenParameters {
            pre_authorized_code: None,
            tx_code: None,
            invalid: false,
        },
    }
}

fn conflicting_auth() -> TokenClientAuthTransportFacts {
    TokenClientAuthTransportFacts::from_parts(
        BasicAuthorizationCredentials::Malformed,
        Some("form-client".to_owned()),
        None,
        None,
        None,
    )
}

#[test]
fn token_prepare_rejects_grant_parameter_before_auth_source_conflict() {
    let first = prepare_token_request(parsed("client_credentials", true), conflicting_auth());
    let Err(OAuthEndpointError::Token { fields, .. }) = first else {
        panic!("non-exchange audience must fail first");
    };
    assert_eq!(fields.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(fields.error, "invalid_request");
    assert_eq!(
        fields.description,
        "audience is only valid for OAuth token exchange; use RFC 8707 resource elsewhere."
    );

    let second = prepare_token_request(
        parsed(nazo_oauth_server::token::TOKEN_EXCHANGE_GRANT_TYPE, true),
        conflicting_auth(),
    );
    let Err(OAuthEndpointError::Token { fields, .. }) = second else {
        panic!("once grant permits audience, source conflict must fail");
    };
    assert_eq!(fields.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(fields.error, "invalid_request");
    assert_eq!(
        fields.description,
        "同一 token 请求不能同时使用多种客户端认证方式."
    );
}

#[derive(Default)]
struct CountingDpopState(AtomicUsize);

impl DpopStateStorePort for CountingDpopState {
    fn consume_replay<'a>(&'a self, _: &'a str, _: &'a str, _: u64) -> DpopStateFuture<'a, bool> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(DpopStateStoreError) })
    }

    fn issue_nonce<'a>(&'a self, _: &'a str, _: u64) -> DpopStateFuture<'a, ()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(DpopStateStoreError) })
    }

    fn validate_nonce<'a>(&'a self, _: &'a str) -> DpopStateFuture<'a, bool> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(DpopStateStoreError) })
    }
}

struct NoAudit;

impl SecurityAudit for NoAudit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn record(&self, _: &str, _: serde_json::Map<String, serde_json::Value>) {}

    fn record_required<'a>(
        &'a self,
        _: &'a str,
        _: serde_json::Map<String, serde_json::Value>,
    ) -> AuditFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn dpop_facts(
    proof: Result<Option<&'static str>, DpopError>,
    proof_present: bool,
) -> DpopRequestFacts<'static> {
    DpopRequestFacts {
        method: http::Method::POST,
        path: "/oauth/token",
        proof,
        proof_present,
    }
}

#[test]
fn malformed_present_proof_fails_before_state_and_missing_bound_proof_is_distinct() {
    let state = CountingDpopState::default();
    let result = futures_executor::block_on(validate_dpop_proof(
        &state,
        &NoAudit,
        "https://issuer.example",
        "https://mtls.example",
        DpopNoncePolicy::Optional,
        dpop_facts(Err(DpopError::MalformedProof), true),
        None,
        None,
    ));
    assert_eq!(result, Err(DpopError::MalformedProof));
    assert_eq!(state.0.load(Ordering::SeqCst), 0);

    let missing = futures_executor::block_on(validate_dpop_proof(
        &state,
        &NoAudit,
        "https://issuer.example",
        "https://mtls.example",
        DpopNoncePolicy::Optional,
        dpop_facts(Ok(None), false),
        None,
        Some("bound-thumbprint"),
    ));
    assert_eq!(missing, Err(DpopError::MissingProof));
    assert_eq!(state.0.load(Ordering::SeqCst), 0);
}

#[test]
fn unbound_request_without_proof_does_not_touch_dpop_state() {
    let state = CountingDpopState::default();
    let result = futures_executor::block_on(validate_dpop_proof(
        &state,
        &NoAudit,
        "https://issuer.example",
        "https://mtls.example",
        DpopNoncePolicy::Optional,
        dpop_facts(Ok(None), false),
        None,
        None,
    ));
    assert_eq!(result, Ok(None));
    assert_eq!(state.0.load(Ordering::SeqCst), 0);
}
