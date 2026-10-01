use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use chrono::{Duration, TimeZone, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::{
    AuthorizationCodeState, ConsentPayload, OAuthClient, PushedAuthorizationRequest,
    RequestObjectClaims, RequestObjectJtiPolicy, RequestObjectPolicy,
};

use super::{
    AuthorizationApprovalInput, AuthorizationDecisionAdmissionError, AuthorizationDecisionCommit,
    AuthorizationDecisionCommitResult, AuthorizationDecisionKind, AuthorizationFuture,
    AuthorizationPortError, AuthorizationRateDimension, AuthorizationRepositoryPort,
    AuthorizationResponseSignInput, AuthorizationResponseSignerPort, AuthorizationService,
    AuthorizationStateSnapshot, AuthorizationStateStorePort, PreparedAuthorizationCode,
    StoredAuthorizationGrant, prepare_authorization_code,
    stored_grant_covers_requested_authorization,
};

#[derive(Default)]
struct RepositoryState {
    client: Mutex<Option<OAuthClient>>,
    decisions: Mutex<DecisionState>,
    publication_probe: Mutex<Option<Arc<StoreState>>>,
    hold_commit_ack: AtomicBool,
}

/// Bounded persistence double: one lock represents one atomic repository call.
/// Client/principal/grant policy belongs to the real adapter, so tests configure
/// its outcome instead of maintaining a second policy implementation here.
#[derive(Default)]
struct DecisionState {
    outcome: Option<Result<AuthorizationDecisionCommitResult, AuthorizationPortError>>,
    commit_then_error: bool,
    facts: Vec<AuthorizationDecisionCommit>,
    grant_writes: usize,
}

#[derive(Clone, Default)]
struct FakeRepository(Arc<RepositoryState>);

impl AuthorizationRepositoryPort for FakeRepository {
    fn mtls_trust_anchor_bundle(&self, _client_id: Uuid) -> AuthorizationFuture<'_, String> {
        Box::pin(async { Ok(String::new()) })
    }

    fn client_by_id<'a>(
        &'a self,
        _client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        let client = self.0.client.lock().unwrap().clone();
        Box::pin(async move { Ok(client) })
    }

    fn grant<'a>(
        &'a self,
        _user_id: Uuid,
        _client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        Box::pin(async { Ok(None) })
    }

    fn commit_decision(
        &self,
        input: AuthorizationDecisionCommit,
    ) -> AuthorizationFuture<'_, AuthorizationDecisionCommitResult> {
        Box::pin(async move {
            let result = (|| {
                if let Some(store) = self.0.publication_probe.lock().unwrap().as_ref() {
                    assert!(
                        store.stored_code.lock().unwrap().is_none(),
                        "a code must not be published before the repository commits"
                    );
                }
                let mut state = self.0.decisions.lock().unwrap();
                if let Some(outcome) = state.outcome.take()
                    && outcome != Ok(AuthorizationDecisionCommitResult::Committed)
                {
                    return outcome;
                }
                if state.facts.iter().any(|fact| {
                    fact.tenant_id == input.tenant_id
                        && (fact.request_id == input.request_id
                            || input
                                .pushed_request_uri
                                .as_ref()
                                .is_some_and(|uri| fact.pushed_request_uri.as_ref() == Some(uri)))
                }) {
                    return Ok(AuthorizationDecisionCommitResult::Conflict);
                }
                if input.valid_until <= Utc::now() {
                    return Ok(AuthorizationDecisionCommitResult::Expired);
                }
                assert!(state.facts.len() < 16, "bounded decision fixture exhausted");
                state.grant_writes +=
                    usize::from(input.decision == AuthorizationDecisionKind::Approve);
                state.facts.push(input);
                if std::mem::take(&mut state.commit_then_error) {
                    return Err(AuthorizationPortError::Unavailable);
                }
                Ok(AuthorizationDecisionCommitResult::Committed)
            })();
            if result == Ok(AuthorizationDecisionCommitResult::Committed)
                && self.0.hold_commit_ack.load(Ordering::Relaxed)
            {
                std::future::pending::<()>().await;
            }
            result
        })
    }

    fn client_authentication_snapshot<'a>(
        &'a self,
        _client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<crate::ClientAuthenticationSnapshot>> {
        Box::pin(async { Ok(None) })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        _client_id: Uuid,
        _candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}

#[derive(Default)]
struct StoreState {
    consent: Mutex<Option<ConsentPayload>>,
    replace_consent_after_load: Mutex<Option<ConsentPayload>>,
    pushed: Mutex<Option<PushedAuthorizationRequest>>,
    replace_pushed_after_load: Mutex<Option<PushedAuthorizationRequest>>,
    stored_code: Mutex<Option<AuthorizationCodeState>>,
    code_error: Mutex<Option<AuthorizationPortError>>,
    jar_error: Mutex<Option<AuthorizationPortError>>,
    delete_error: Mutex<Option<AuthorizationPortError>>,
    consent_discard_error: Mutex<Option<AuthorizationPortError>>,
    par_discard_error: Mutex<Option<AuthorizationPortError>>,
    consent_takes: AtomicUsize,
    pushed_takes: AtomicUsize,
    code_deletes: AtomicUsize,
}

#[derive(Clone, Default)]
struct FakeStore(Arc<StoreState>);

impl AuthorizationStateStorePort for FakeStore {
    fn load_par<'a>(
        &'a self,
        _request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>>
    {
        let pushed = self.0.pushed.lock().unwrap().clone();
        if let Some(replacement) = self.0.replace_pushed_after_load.lock().unwrap().take() {
            *self.0.pushed.lock().unwrap() = Some(replacement);
        }
        Box::pin(async move {
            Ok(pushed.map(|payload| AuthorizationStateSnapshot {
                version: format!("revision:{}", serde_json::to_value(&payload).unwrap()),
                payload,
            }))
        })
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        _request_uri: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.0.pushed_takes.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.0.par_discard_error.lock().unwrap().take() {
            return Box::pin(async move { Err(error) });
        }
        let mut current = self.0.pushed.lock().unwrap();
        let matches = current.as_ref().is_some_and(|current| {
            format!("revision:{}", serde_json::to_value(current).unwrap()) == expected
        });
        if matches {
            current.take();
        }
        Box::pin(async move { Ok(matches) })
    }

    fn store_par<'a>(
        &'a self,
        _request_uri: &'a str,
        _payload: &'a PushedAuthorizationRequest,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn load_consent<'a>(
        &'a self,
        _request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<ConsentPayload>>> {
        let consent = self.0.consent.lock().unwrap().clone();
        if let Some(replacement) = self.0.replace_consent_after_load.lock().unwrap().take() {
            *self.0.consent.lock().unwrap() = Some(replacement);
        }
        Box::pin(async move {
            Ok(consent.map(|payload| AuthorizationStateSnapshot {
                version: format!("revision:{}", serde_json::to_value(&payload).unwrap()),
                payload,
            }))
        })
    }

    fn take_consent<'a>(
        &'a self,
        _request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.0.consent_takes.fetch_add(1, Ordering::Relaxed);
        let consent = self.0.consent.lock().unwrap().take();
        Box::pin(async move { Ok(consent) })
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        _request_id: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.0.consent_takes.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.0.consent_discard_error.lock().unwrap().take() {
            return Box::pin(async move { Err(error) });
        }
        let mut current = self.0.consent.lock().unwrap();
        let matches = current.as_ref().is_some_and(|current| {
            format!("revision:{}", serde_json::to_value(current).unwrap()) == expected
        });
        if matches {
            current.take();
        }
        Box::pin(async move { Ok(matches) })
    }

    fn store_consent<'a>(
        &'a self,
        _request_id: &'a str,
        _payload: &'a ConsentPayload,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn store_authorization_code<'a>(
        &'a self,
        _code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        let error = self.0.code_error.lock().unwrap().take();
        if error.is_none() {
            *self.0.stored_code.lock().unwrap() = Some(state.clone());
        }
        Box::pin(async move { error.map_or(Ok(()), Err) })
    }

    fn delete_authorization_code<'a>(&'a self, _code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        self.0.code_deletes.fetch_add(1, Ordering::Relaxed);
        let error = self.0.delete_error.lock().unwrap().take();
        if error.is_none() {
            *self.0.stored_code.lock().unwrap() = None;
        }
        Box::pin(async move { error.map_or(Ok(()), Err) })
    }

    fn take_reauth_nonce<'a>(&'a self, _nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        Box::pin(async { Ok(None) })
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        _nonce: &'a str,
        _started_at: i64,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn consume_jar<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        let error = self.0.jar_error.lock().unwrap().take();
        Box::pin(async move { error.map_or(Ok(true), Err) })
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn consume_ciba_request_object<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn consume_dpop<'a>(
        &'a self,
        _thumbprint: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        _nonce: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn validate_dpop_nonce<'a>(&'a self, _nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn increment_rate<'a>(
        &'a self,
        _dimension: AuthorizationRateDimension,
        _subject: &'a str,
        _window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        Box::pin(async { Ok(1) })
    }
}

#[derive(Clone, Copy)]
struct FakeSigner;

impl AuthorizationResponseSignerPort for FakeSigner {
    fn sign_authorization_response<'a>(
        &'a self,
        _input: AuthorizationResponseSignInput<'a>,
    ) -> AuthorizationFuture<'a, String> {
        Box::pin(async { Err(AuthorizationPortError::Unexpected) })
    }
}

fn consent(user_id: Uuid, request_uri: Option<&str>) -> ConsentPayload {
    let issued_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    ConsentPayload {
        request_id: "request-1".to_owned(),
        user_id,
        client_id: "client-1".to_owned(),
        client_name: "Test client".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: vec!["https://api.example".to_owned()],
        authorization_details: json!([]),
        state: Some("state-1".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: 1_699_999_990,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: Some("1".to_owned()),
        userinfo_claims: vec!["name".to_owned()],
        userinfo_claim_requests: Vec::new(),
        id_token_claims: vec!["email".to_owned()],
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: Some("jkt".to_owned()),
        mtls_x5t_s256: None,
        pushed_request_uri: request_uri.map(str::to_owned),
        pushed_request_digest: None,
        signed_authorization_response_required: None,
        session_management_allowed: None,
        authorization_code_ttl_seconds: None,
        issued_at,
        expires_at: issued_at + Duration::minutes(10),
    }
}

fn pushed() -> PushedAuthorizationRequest {
    let issued_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    PushedAuthorizationRequest {
        client_id: "client-1".to_owned(),
        params: std::collections::HashMap::new(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at,
        expires_at: issued_at + Duration::minutes(10),
    }
}

fn service(
    repository: FakeRepository,
    store: FakeStore,
) -> AuthorizationService<FakeStore, FakeSigner> {
    AuthorizationService::new(repository, store, FakeSigner)
}

#[test]
fn arc_trait_object_is_an_authorization_state_store() {
    fn assert_state_store<T: AuthorizationStateStorePort>() {}

    assert_state_store::<Arc<dyn AuthorizationStateStorePort>>();
}

#[test]
fn ciba_request_object_replay_is_delegated_to_the_state_store() {
    let accepted = futures_executor::block_on(
        service(FakeRepository::default(), FakeStore::default()).consume_ciba_request_object(
            "client-1",
            "request-object-jti",
            30,
        ),
    )
    .unwrap();
    assert!(accepted);
}

#[test]
fn owned_request_object_admission_keeps_outer_parameters_on_replay_dependency_failure() {
    let store = FakeStore::default();
    *store.0.jar_error.lock().unwrap() = Some(AuthorizationPortError::Unavailable);
    let service = service(FakeRepository::default(), store);
    let now = 1_700_000_000;
    let claims = RequestObjectClaims {
        client_id: "client".to_owned(),
        iss: Some("client".to_owned()),
        sub: Some("client".to_owned()),
        aud: Some(json!("https://issuer.example")),
        exp: Some(now + 120),
        nbf: Some(now),
        iat: Some(now),
        jti: Some("replay-jti".to_owned()),
        parameters: std::collections::HashMap::from([(
            "redirect_uri".to_owned(),
            json!("https://client.example/cb"),
        )]),
    };
    let policy = RequestObjectPolicy {
        issuer: "https://issuer.example",
        client_id: "client",
        jti_policy: RequestObjectJtiPolicy::RequiredForSignedJar,
        require_integrity_protected_parameters: true,
        now,
    };
    let mut outer = std::collections::HashMap::from([
        ("client_id".to_owned(), "client".to_owned()),
        ("request".to_owned(), "signed.jwt".to_owned()),
        ("state".to_owned(), "outer-state".to_owned()),
    ]);
    let original = outer.clone();

    assert_eq!(
        futures_executor::block_on(
            service.admit_request_object_owned(&mut outer, &claims, policy,)
        ),
        Err(crate::AuthorizationRequestError::Dependency(
            AuthorizationPortError::Unavailable,
        ))
    );
    assert_eq!(outer, original);
}

#[test]
fn stored_grant_must_cover_every_scope_and_resource() {
    let stored = StoredAuthorizationGrant {
        scopes: json!(["openid", "profile"]),
        resource_indicators: json!(["https://api.example"]),
        authorization_details: json!([]),
    };

    assert!(stored_grant_covers_requested_authorization(
        &stored,
        &["openid".to_owned()],
        &["https://api.example".to_owned()],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &stored,
        &["email".to_owned()],
        &["https://api.example".to_owned()],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &stored,
        &["openid".to_owned()],
        &["https://other.example".to_owned()],
        &json!([]),
    ));
}

#[test]
fn pushed_request_digest_is_independent_of_hash_map_iteration_order() {
    let mut first = pushed();
    first.params.insert("scope".to_owned(), "openid".to_owned());
    first.params.insert(
        "redirect_uri".to_owned(),
        "https://client.example/cb".to_owned(),
    );
    let mut second = pushed();
    second.params.insert(
        "redirect_uri".to_owned(),
        "https://client.example/cb".to_owned(),
    );
    second
        .params
        .insert("scope".to_owned(), "openid".to_owned());

    assert_eq!(
        super::pushed_authorization_request_digest(&first).unwrap(),
        super::pushed_authorization_request_digest(&second).unwrap()
    );
}

#[test]
fn foreign_user_cannot_consume_an_observed_consent() {
    futures_executor::block_on(foreign_user_cannot_consume_an_observed_consent_async());
}

async fn foreign_user_cannot_consume_an_observed_consent_async() {
    let owner = Uuid::from_u128(10);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, None));
    let service = service(FakeRepository::default(), store.clone());

    assert!(matches!(
        service
            .preview_user_decision("request-1", Uuid::from_u128(11))
            .await,
        Err(AuthorizationDecisionAdmissionError::UserMismatch)
    ));
    assert_eq!(store.0.consent_takes.load(Ordering::Relaxed), 0);
    assert!(store.0.consent.lock().unwrap().is_some());
}

#[test]
fn concurrent_preparation_disposal_removes_only_the_observed_snapshot() {
    futures_executor::block_on(
        concurrent_preparation_disposal_removes_only_the_observed_snapshot_async(),
    );
}

async fn concurrent_preparation_disposal_removes_only_the_observed_snapshot_async() {
    let owner = Uuid::from_u128(10);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, None));
    let service = service(FakeRepository::default(), store.clone());

    // Both previews observe the same state non-destructively. Only one
    // best-effort disposal removes it; this is not the durable decision fence.
    let first = service
        .preview_user_decision("request-1", owner)
        .await
        .unwrap();
    let second = service
        .preview_user_decision("request-1", owner)
        .await
        .unwrap();
    let (first, second) = futures_util::join!(
        service.discard_decision_material("request-1", &first),
        service.discard_decision_material("request-1", &second),
    );
    let results = [first, second];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(AuthorizationDecisionAdmissionError::ConsentMissing)
                )
            })
            .count(),
        1
    );
    assert_eq!(store.0.consent_takes.load(Ordering::Relaxed), 2);
    assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 0);
}

#[test]
fn consent_cleanup_mismatch_does_not_attempt_par_cleanup() {
    futures_executor::block_on(async {
        let owner = Uuid::from_u128(10);
        let store = FakeStore::default();
        *store.0.consent.lock().unwrap() = Some(consent(owner, Some("request-uri-1")));
        *store.0.pushed.lock().unwrap() = Some(pushed());
        let service = service(FakeRepository::default(), store.clone());
        let preview = service
            .preview_user_decision("request-1", owner)
            .await
            .unwrap();
        *store.0.consent.lock().unwrap() = Some(consent(Uuid::from_u128(11), None));

        assert!(matches!(
            service.discard_decision_material("request-1", &preview).await,
            Err(AuthorizationDecisionAdmissionError::ConsentMissing)
        ));
        assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 0);
        assert!(store.0.pushed.lock().unwrap().is_some());
        assert_eq!(
            store.0.consent.lock().unwrap().as_ref().unwrap().user_id,
            Uuid::from_u128(11)
        );
    });
}

#[test]
fn cleanup_dependency_errors_preserve_the_original_stage_mapping() {
    futures_executor::block_on(async {
        for fail_par in [false, true] {
            for source in [
                AuthorizationPortError::Unavailable,
                AuthorizationPortError::Unexpected,
            ] {
                let owner = Uuid::from_u128(10);
                let store = FakeStore::default();
                *store.0.consent.lock().unwrap() = Some(consent(owner, Some("request-uri-1")));
                *store.0.pushed.lock().unwrap() = Some(pushed());
                let service = service(FakeRepository::default(), store.clone());
                let preview = service
                    .preview_user_decision("request-1", owner)
                    .await
                    .unwrap();
                if fail_par {
                    *store.0.par_discard_error.lock().unwrap() = Some(source);
                } else {
                    *store.0.consent_discard_error.lock().unwrap() = Some(source);
                }

                let error = service
                    .discard_decision_material("request-1", &preview)
                    .await
                    .unwrap_err();
                match error {
                    AuthorizationDecisionAdmissionError::ConsentReadFailed(actual) => {
                        assert!(!fail_par);
                        assert_eq!(actual, source);
                        assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 0);
                        assert!(store.0.consent.lock().unwrap().is_some());
                    }
                    AuthorizationDecisionAdmissionError::PushedRequestReadFailed {
                        consent,
                        source: actual,
                    } => {
                        assert!(fail_par);
                        assert_eq!(actual, source);
                        assert_eq!(consent.user_id, owner);
                        assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 1);
                        assert!(store.0.consent.lock().unwrap().is_none());
                    }
                    other => panic!("cleanup dependency failure became {other:?}"),
                }
                assert!(store.0.pushed.lock().unwrap().is_some());
            }
        }
    });
}

#[test]
fn consent_replacement_between_load_and_claim_is_preserved() {
    futures_executor::block_on(consent_replacement_between_load_and_claim_is_preserved_async());
}

async fn consent_replacement_between_load_and_claim_is_preserved_async() {
    let owner = Uuid::from_u128(10);
    let replacement_owner = Uuid::from_u128(11);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, None));
    *store.0.replace_consent_after_load.lock().unwrap() = Some(consent(replacement_owner, None));
    let service = service(FakeRepository::default(), store.clone());

    let preview = service
        .preview_user_decision("request-1", owner)
        .await
        .unwrap();
    assert!(matches!(
        service
            .discard_decision_material("request-1", &preview)
            .await,
        Err(AuthorizationDecisionAdmissionError::ConsentMissing)
    ));
    let retained = store.0.consent.lock().unwrap().clone().unwrap();
    assert_eq!(retained.user_id, replacement_owner);
    assert_eq!(store.0.consent_takes.load(Ordering::Relaxed), 1);
}

#[test]
fn admitted_consent_consumes_its_par_handle_once() {
    futures_executor::block_on(admitted_consent_consumes_its_par_handle_once_async());
}

async fn admitted_consent_consumes_its_par_handle_once_async() {
    let owner = Uuid::from_u128(10);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, Some("request-uri-1")));
    *store.0.pushed.lock().unwrap() = Some(pushed());
    let service = service(FakeRepository::default(), store.clone());

    let preview = service
        .preview_user_decision("request-1", owner)
        .await
        .unwrap();
    assert_eq!(
        preview.consent.pushed_request_uri.as_deref(),
        Some("request-uri-1")
    );
    service
        .discard_decision_material("request-1", &preview)
        .await
        .unwrap();
    assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 1);
    assert!(store.0.pushed.lock().unwrap().is_none());
}

#[test]
fn missing_par_preview_retains_consent_for_protocol_redirect() {
    futures_executor::block_on(missing_par_preview_retains_consent_for_protocol_redirect_async());
}

async fn missing_par_preview_retains_consent_for_protocol_redirect_async() {
    let owner = Uuid::from_u128(10);
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(consent(owner, Some("missing-request-uri")));
    let service = service(FakeRepository::default(), store.clone());

    let error = service
        .preview_user_decision("request-1", owner)
        .await
        .unwrap_err();
    let AuthorizationDecisionAdmissionError::PushedRequestMissing(consent) = error else {
        panic!("missing PAR must still return the consent payload for the redirect")
    };
    assert_eq!(consent.redirect_uri, "https://client.example/callback");
    assert_eq!(consent.state.as_deref(), Some("state-1"));
    // The preview is non-destructive: neither consent nor PAR was consumed.
    assert_eq!(store.0.consent_takes.load(Ordering::Relaxed), 0);
    assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 0);
    assert!(store.0.consent.lock().unwrap().is_some());
}

#[test]
fn corrupt_par_snapshot_between_load_and_disposal_is_preserved() {
    futures_executor::block_on(corrupt_par_snapshot_between_load_and_disposal_is_preserved_async());
}

async fn corrupt_par_snapshot_between_load_and_disposal_is_preserved_async() {
    let owner = Uuid::from_u128(10);
    let original = pushed();
    let mut bound_consent = consent(owner, Some("request-uri-1"));
    bound_consent.pushed_request_digest =
        Some(super::pushed_authorization_request_digest(&original).unwrap());
    let mut replacement = pushed();
    replacement.client_id = "replacement-client".to_owned();
    let store = FakeStore::default();
    *store.0.consent.lock().unwrap() = Some(bound_consent);
    *store.0.pushed.lock().unwrap() = Some(original);
    *store.0.replace_pushed_after_load.lock().unwrap() = Some(replacement.clone());
    let service = service(FakeRepository::default(), store.clone());

    let preview = service
        .preview_user_decision("request-1", owner)
        .await
        .unwrap();
    let error = service
        .discard_decision_material("request-1", &preview)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthorizationDecisionAdmissionError::PushedRequestMissing(_)
    ));
    assert_eq!(
        store.0.pushed.lock().unwrap().as_ref().unwrap().client_id,
        replacement.client_id
    );
    assert_eq!(store.0.pushed_takes.load(Ordering::Relaxed), 1);
    assert!(store.0.consent.lock().unwrap().is_none());
}

fn decision_input(
    kind: AuthorizationDecisionKind,
    request_id: &str,
    par: Option<&str>,
) -> (
    AuthorizationDecisionCommit,
    Option<PreparedAuthorizationCode>,
) {
    let now = Utc::now();
    let tenant_id = Uuid::from_u128(1);
    let mut payload = consent(Uuid::from_u128(10), par);
    payload.request_id = request_id.into();
    payload.issued_at = now;
    payload.expires_at = now + Duration::minutes(5);
    let code = (kind != AuthorizationDecisionKind::Deny).then(|| {
        prepare_authorization_code(AuthorizationApprovalInput {
            consent: &payload,
            code_hash: "hash",
            code_id: "code-id",
            issued_at: now,
            code_ttl_seconds: 60,
            tenant_id,
        })
    });
    (
        AuthorizationDecisionCommit {
            tenant_id,
            user_id: payload.user_id,
            client_id: payload.client_id.clone(),
            request_id: payload.request_id.clone(),
            pushed_request_uri: payload.pushed_request_uri.clone(),
            valid_until: payload.expires_at,
            retain_until: payload.expires_at,
            decision: kind,
            event_id: Uuid::now_v7(),
            occurred_at: now,
            audit_fields: json!({"request_id_hash": "request-hash"}),
            scopes: payload.scopes.clone(),
            resource_indicators: payload.resource_indicators.clone(),
            authorization_details: payload.authorization_details.clone(),
        },
        code,
    )
}

#[test]
fn failed_or_unknown_decision_never_publishes_a_code() {
    futures_executor::block_on(async {
        for outcome in [
            Ok(AuthorizationDecisionCommitResult::Conflict),
            Ok(AuthorizationDecisionCommitResult::Expired),
            Ok(AuthorizationDecisionCommitResult::ClientUnavailable),
            Ok(AuthorizationDecisionCommitResult::GrantUnavailable),
            Err(AuthorizationPortError::Unavailable),
        ] {
            let repository = FakeRepository::default();
            repository.0.decisions.lock().unwrap().outcome = Some(outcome);
            let store = FakeStore::default();
            let service = service(repository.clone(), store.clone());
            let (input, code) = decision_input(AuthorizationDecisionKind::Approve, "request", None);
            assert!(store.0.stored_code.lock().unwrap().is_none());
            assert_eq!(service.commit_decision(input, code).await, outcome);
            assert!(store.0.stored_code.lock().unwrap().is_none());
            assert_eq!(store.0.code_deletes.load(Ordering::Relaxed), 0);
            let state = repository.0.decisions.lock().unwrap();
            assert!(state.facts.is_empty());
            assert_eq!(state.grant_writes, 0);
        }
    });
}

#[test]
fn approved_but_undelivered_keeps_fact_grant_and_consumption_fence() {
    futures_executor::block_on(async {
        for unknown_commit in [false, true] {
            let repository = FakeRepository::default();
            repository.0.decisions.lock().unwrap().commit_then_error = unknown_commit;
            let store = FakeStore::default();
            if !unknown_commit {
                *store.0.code_error.lock().unwrap() = Some(AuthorizationPortError::Unavailable);
            }
            let service = service(repository.clone(), store.clone());
            let (input, code) =
                decision_input(AuthorizationDecisionKind::Approve, "request", Some("par"));
            assert_eq!(
                service.commit_decision(input, code).await,
                Err(AuthorizationPortError::Unavailable)
            );
            assert!(store.0.stored_code.lock().unwrap().is_none());
            let (retry, code) =
                decision_input(AuthorizationDecisionKind::Approve, "request", Some("par"));
            assert_eq!(
                service.commit_decision(retry, code).await.unwrap(),
                AuthorizationDecisionCommitResult::Conflict
            );
            let (other_consent, code) = decision_input(
                AuthorizationDecisionKind::PromptNone,
                "another-request",
                Some("par"),
            );
            assert_eq!(
                service.commit_decision(other_consent, code).await.unwrap(),
                AuthorizationDecisionCommitResult::Conflict
            );
            assert!(store.0.stored_code.lock().unwrap().is_none());
            assert_eq!(store.0.code_deletes.load(Ordering::Relaxed), 0);
            let state = repository.0.decisions.lock().unwrap();
            assert_eq!(state.facts.len(), 1);
            assert_eq!(state.grant_writes, 1);
        }
    });
}

#[test]
fn cancellation_before_decision_ack_never_publishes_a_code() {
    let repository = FakeRepository::default();
    repository.0.hold_commit_ack.store(true, Ordering::Relaxed);
    let store = FakeStore::default();
    let service = service(repository.clone(), store.clone());
    let (input, code) =
        decision_input(AuthorizationDecisionKind::Approve, "cancelled", Some("par"));
    let retry = input.clone();
    let retry_code = code.as_ref().map(|code| PreparedAuthorizationCode {
        tenant_id: code.tenant_id,
        hash: code.hash.clone(),
        payload: code.payload.clone(),
        ttl_seconds: code.ttl_seconds,
    });
    let mut pending = Box::pin(service.commit_decision(input, code));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(pending.as_mut(), &mut context).is_pending());
    // The repository has committed, but its durable acknowledgement is held.
    // Dropping this service future cannot run the later code-publication step.
    assert_eq!(repository.0.decisions.lock().unwrap().facts.len(), 1);
    assert!(store.0.stored_code.lock().unwrap().is_none());
    drop(pending);
    assert!(store.0.stored_code.lock().unwrap().is_none());
    assert_eq!(store.0.code_deletes.load(Ordering::Relaxed), 0);
    assert_eq!(
        futures_executor::block_on(service.commit_decision(retry, retry_code)).unwrap(),
        AuthorizationDecisionCommitResult::Conflict
    );
    assert!(store.0.stored_code.lock().unwrap().is_none());
    let state = repository.0.decisions.lock().unwrap();
    assert_eq!(state.facts.len(), 1);
    assert_eq!(state.grant_writes, 1);
}

#[test]
fn successful_commit_binds_exact_prepared_code_before_publication() {
    futures_executor::block_on(async {
        let repository = FakeRepository::default();
        let store = FakeStore::default();
        *repository.0.publication_probe.lock().unwrap() = Some(store.0.clone());
        let service = service(repository.clone(), store.clone());
        let (input, code) = decision_input(AuthorizationDecisionKind::Approve, "request", None);
        let prepared = code.unwrap();
        let expected_digest = blake3::hash(&serde_json::to_vec(&prepared.payload).unwrap())
            .to_hex()
            .to_string();
        let issued_at = prepared.payload.issued_at;
        assert!(
            store.0.stored_code.lock().unwrap().is_none(),
            "preparation is not publication"
        );
        assert!(repository.0.decisions.lock().unwrap().facts.is_empty());
        assert_eq!(
            service
                .commit_decision(input, Some(prepared))
                .await
                .unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        let stored = store.0.stored_code.lock().unwrap().clone().unwrap();
        let AuthorizationCodeState::Pending { payload } = stored else {
            panic!("a committed approval publishes a pending authorization code")
        };
        assert_eq!(payload.code_id, "code-id");
        assert_eq!(payload.nonce.as_deref(), Some("nonce-1"));
        assert_eq!(payload.dpop_jkt.as_deref(), Some("jkt"));
        assert_eq!(payload.code_challenge.as_deref(), Some("challenge"));
        assert_eq!(payload.issued_at, issued_at);
        assert_eq!(payload.expires_at, issued_at + Duration::seconds(60));
        let state = repository.0.decisions.lock().unwrap();
        assert_eq!(state.grant_writes, 1);
        assert_eq!(state.facts.len(), 1);
        assert_eq!(state.facts[0].audit_fields["code_id"], "code-id");
        assert_eq!(state.facts[0].audit_fields["code_hash"], "hash");
        assert_eq!(
            state.facts[0].audit_fields["code_payload_digest"],
            expected_digest
        );
    });
}

#[test]
fn deny_and_prompt_none_share_par_fence_without_incrementing_explicit_grants() {
    futures_executor::block_on(async {
        for winner in [
            AuthorizationDecisionKind::Deny,
            AuthorizationDecisionKind::PromptNone,
        ] {
            let repository = FakeRepository::default();
            let store = FakeStore::default();
            let service = service(repository.clone(), store.clone());
            let (input, code) = decision_input(winner, "first", Some("par"));
            assert_eq!(
                service.commit_decision(input, code).await.unwrap(),
                AuthorizationDecisionCommitResult::Committed
            );
            assert_eq!(
                store.0.stored_code.lock().unwrap().is_some(),
                winner == AuthorizationDecisionKind::PromptNone
            );
            for loser in [
                AuthorizationDecisionKind::Approve,
                AuthorizationDecisionKind::Deny,
                AuthorizationDecisionKind::PromptNone,
            ] {
                let (input, code) = decision_input(loser, "second", Some("par"));
                assert_eq!(
                    service.commit_decision(input, code).await.unwrap(),
                    AuthorizationDecisionCommitResult::Conflict
                );
            }
            let state = repository.0.decisions.lock().unwrap();
            assert_eq!(state.facts.len(), 1);
            assert_eq!(state.grant_writes, 0);
            if winner == AuthorizationDecisionKind::Deny {
                assert!(state.facts[0].audit_fields.get("code_id").is_none());
            }
        }
    });
}

#[test]
fn mismatched_prepared_authorization_is_rejected_before_repository_commit() {
    futures_executor::block_on(async {
        let repository = FakeRepository::default();
        let store = FakeStore::default();
        let service = service(repository.clone(), store.clone());
        let (mut input, code) = decision_input(AuthorizationDecisionKind::Approve, "request", None);
        input.scopes.push("unapproved".into());
        assert_eq!(
            service.commit_decision(input, code).await,
            Err(AuthorizationPortError::CorruptData)
        );
        assert!(repository.0.decisions.lock().unwrap().facts.is_empty());
        assert!(store.0.stored_code.lock().unwrap().is_none());
    });
}

#[test]
fn preview_preserves_longest_material_retention_and_shortest_admission_expiry() {
    futures_executor::block_on(async {
        let owner = Uuid::from_u128(10);
        let mut payload = consent(owner, Some("par"));
        let mut par = pushed();
        payload.expires_at = Utc::now() + Duration::seconds(30);
        par.expires_at = payload.expires_at + Duration::minutes(5);
        let expected_valid_until = payload.expires_at;
        let expected_retain_until = par.expires_at;
        let store = FakeStore::default();
        *store.0.consent.lock().unwrap() = Some(payload);
        *store.0.pushed.lock().unwrap() = Some(par);
        let service = service(FakeRepository::default(), store);
        let preview = service
            .preview_user_decision("request-1", owner)
            .await
            .unwrap();
        assert_eq!(preview.valid_until(), expected_valid_until);
        assert_eq!(preview.retain_until(), expected_retain_until);
    });
}

#[test]
fn independent_request_fence_is_tenant_scoped_and_expired_input_cannot_commit() {
    futures_executor::block_on(async {
        let repository = FakeRepository::default();
        let store = FakeStore::default();
        let service = service(repository.clone(), store.clone());
        let (input, code) = decision_input(
            AuthorizationDecisionKind::Deny,
            "request",
            Some("first-par"),
        );
        assert_eq!(
            service.commit_decision(input, code).await.unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        let (input, code) = decision_input(
            AuthorizationDecisionKind::Deny,
            "request",
            Some("different-par"),
        );
        assert_eq!(
            service.commit_decision(input, code).await.unwrap(),
            AuthorizationDecisionCommitResult::Conflict
        );
        let (mut input, code) = decision_input(
            AuthorizationDecisionKind::Deny,
            "request",
            Some("first-par"),
        );
        input.tenant_id = Uuid::from_u128(2);
        assert_eq!(
            service.commit_decision(input, code).await.unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        let (mut input, code) =
            decision_input(AuthorizationDecisionKind::Approve, "expired-request", None);
        input.valid_until = Utc::now() - Duration::seconds(1);
        assert_eq!(
            service.commit_decision(input, code).await.unwrap(),
            AuthorizationDecisionCommitResult::Expired
        );
        assert_eq!(repository.0.decisions.lock().unwrap().facts.len(), 2);
        assert!(store.0.stored_code.lock().unwrap().is_none());
    });
}

#[test]
fn competing_decision_kinds_share_one_par_commit() {
    futures_executor::block_on(async {
        for first_kind in [
            AuthorizationDecisionKind::Approve,
            AuthorizationDecisionKind::Deny,
            AuthorizationDecisionKind::PromptNone,
        ] {
            let repository = FakeRepository::default();
            let store = FakeStore::default();
            let service = service(repository.clone(), store.clone());
            let (first, first_code) =
                decision_input(first_kind, "first-request", Some("shared-par"));
            let (second, second_code) = decision_input(
                AuthorizationDecisionKind::Approve,
                "second-request",
                Some("shared-par"),
            );
            let (first, second) = futures_util::join!(
                service.commit_decision(first, first_code),
                service.commit_decision(second, second_code),
            );
            let results = [first.unwrap(), second.unwrap()];
            assert_eq!(
                results
                    .iter()
                    .filter(|result| **result == AuthorizationDecisionCommitResult::Committed)
                    .count(),
                1
            );
            assert_eq!(
                results
                    .iter()
                    .filter(|result| **result == AuthorizationDecisionCommitResult::Conflict)
                    .count(),
                1
            );
            let state = repository.0.decisions.lock().unwrap();
            assert_eq!(state.facts.len(), 1);
            assert_eq!(
                state.grant_writes,
                usize::from(state.facts[0].decision == AuthorizationDecisionKind::Approve)
            );
            assert_eq!(
                store.0.stored_code.lock().unwrap().is_some(),
                state.facts[0].decision != AuthorizationDecisionKind::Deny
            );
        }
    });
}

#[test]
fn decision_kind_requires_matching_code_presence() {
    futures_executor::block_on(async {
        let repository = FakeRepository::default();
        let store = FakeStore::default();
        let service = service(repository.clone(), store.clone());
        let (approve, code) = decision_input(AuthorizationDecisionKind::Approve, "request", None);
        assert_eq!(
            service.commit_decision(approve, None).await,
            Err(AuthorizationPortError::CorruptData)
        );
        let (deny, _) = decision_input(AuthorizationDecisionKind::Deny, "request", None);
        assert_eq!(
            service.commit_decision(deny, code).await,
            Err(AuthorizationPortError::CorruptData)
        );
        assert!(repository.0.decisions.lock().unwrap().facts.is_empty());
        assert!(store.0.stored_code.lock().unwrap().is_none());
    });
}

#[test]
fn code_expiry_extends_retention_without_extending_admission_expiry() {
    futures_executor::block_on(async {
        let repository = FakeRepository::default();
        let store = FakeStore::default();
        let service = service(repository.clone(), store);
        let (input, code) = decision_input(AuthorizationDecisionKind::Approve, "request", None);
        let valid_until = input.valid_until;
        let mut prepared = code.unwrap();
        prepared.payload.expires_at = valid_until + Duration::minutes(5);
        prepared.ttl_seconds = 600;
        let code_expiry = prepared.payload.expires_at;
        assert_eq!(
            service
                .commit_decision(input, Some(prepared))
                .await
                .unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        let state = repository.0.decisions.lock().unwrap();
        assert_eq!(state.facts[0].valid_until, valid_until);
        assert_eq!(state.facts[0].retain_until, code_expiry);
    });
}
