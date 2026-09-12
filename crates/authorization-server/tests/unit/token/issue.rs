use super::*;
use crate::domain::oauth::NativeSsoTokenBinding;
use chrono::Utc;
use nazo_auth::OidcClaimRequest;
use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
pub(super) fn client_with_grants(grant_types: &[&str]) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        require_mtls_bound_tokens: false,
        is_active: true,
        registration: nazo_auth::ValidatedClientRegistration {
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "public".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
            allowed_audiences: vec!["resource://default".to_owned()],
            grant_types: grant_types
                .iter()
                .map(|grant| (*grant).to_owned())
                .collect(),
            token_endpoint_auth_method: "none".to_owned(),
            require_dpop_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            jwks_uri: None,
            jwks: None,
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: nazo_auth::ClientPresentationMetadata::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            security_policy: nazo_auth::ClientSecurityPolicy::default(),
        },
    }
}
fn token_issue_with_sid(id_token_claims: Vec<String>) -> TokenIssue {
    TokenIssue {
        user_id: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: None,
        auth_time: Some(1_000),
        amr: vec!["password".to_owned()],
        oidc_sid: Some("op-session-sid".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims,
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: false,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

fn token_issue_without_openid() -> TokenIssue {
    TokenIssue {
        user_id: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["accounts".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: None,
        auth_time: Some(1_000),
        amr: vec!["password".to_owned()],
        oidc_sid: None,
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

#[test]
fn refresh_token_requires_authorized_use_case_and_client_grant() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));

    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes, false));

    let scopes = vec!["org.iso.18013.5.1.mDL".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes, true));

    let client = client_with_grants(&["authorization_code"]);
    assert!(!should_issue_refresh_token(&client, &scopes, true));
}

#[test]
fn refresh_token_grant_matching_is_exact_and_scope_case_sensitive() {
    let client = client_with_grants(&["authorization_code", "refresh_token:legacy"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(
        !should_issue_refresh_token(&client, &scopes, false),
        "refresh issuance must require the exact refresh_token grant"
    );

    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    for scopes in [
        vec!["openid".to_owned(), "OFFLINE_ACCESS".to_owned()],
        vec!["openid".to_owned(), "offline_access ".to_owned()],
        vec!["openid".to_owned(), "offline".to_owned()],
    ] {
        assert!(
            !should_issue_refresh_token(&client, &scopes, false),
            "refresh issuance must require exact offline_access authorization scope: {scopes:?}"
        );
    }
}

#[test]
fn failed_authorization_code_transition_is_idempotent_only_for_terminal_or_missing_states() {
    use nazo_auth::AuthorizationCodeTransitionResult::*;
    for state in [Applied, Missing, Failed, Consumed] {
        assert!(
            authorization_code_state::failed_authorization_code_transition_result(state).is_ok(),
            "failed marker cleanup should tolerate {state:?}"
        );
    }

    for state in [Pending, Consuming, Malformed] {
        let error = authorization_code_state::failed_authorization_code_transition_result(state)
            .expect_err("failed marker must not hide an unexpected active state");
        assert!(
            error.to_string().contains(&format!("{state:?}")),
            "error should preserve the unexpected state for diagnostics"
        );
    }
}

#[test]
fn consumed_authorization_code_marker_lives_as_long_as_issued_credentials() {
    let refresh_family_id = Uuid::now_v7();

    assert_eq!(
        authorization_code_state::consumed_authorization_code_ttl_seconds(
            300,
            2_592_000,
            Some(refresh_family_id),
        ),
        2_592_000,
        "authorization code replay marker must not expire before the refresh token family"
    );

    assert_eq!(
        authorization_code_state::consumed_authorization_code_ttl_seconds(300, 2_592_000, None),
        300,
        "without a refresh token family the marker only needs to cover the access token lifetime"
    );
}

#[test]
fn consumed_authorization_code_marker_ttl_fails_closed_for_non_positive_settings() {
    assert_eq!(
        authorization_code_state::consumed_authorization_code_ttl_seconds(0, 2_592_000, None),
        1,
        "zero access-token TTL settings must still leave a replay marker"
    );

    assert_eq!(
        authorization_code_state::consumed_authorization_code_ttl_seconds(
            300,
            -10,
            Some(Uuid::now_v7())
        ),
        1,
        "invalid refresh-token TTL settings must not produce an absent or already-expired marker"
    );
}

#[test]
fn issuance_digest_binds_every_result_affecting_grant_identity() {
    let client = client_with_grants(&["urn:ietf:params:oauth:grant-type:token-exchange"]);
    let grant_key = "idempotency:stable-grant";
    let baseline = issuance_request_digest(&client, &token_issue_without_openid(), grant_key);

    let mut actor_changed = token_issue_without_openid();
    actor_changed.actor = Some(json!({
        "sub": "delegating-actor",
        "client_id": "actor-client",
    }));
    assert_ne!(
        issuance_request_digest(&client, &actor_changed, grant_key),
        baseline,
        "RFC 8693 actor identity must not reuse another actor's issued response",
    );

    let mut authorization_code_changed = token_issue_without_openid();
    authorization_code_changed.authorization_code_hash = Some("code-hash".to_owned());
    assert_ne!(
        issuance_request_digest(&client, &authorization_code_changed, grant_key),
        baseline,
        "authorization-code consumption identity must be bound to the issuance",
    );

    let mut refresh_policy_changed = token_issue_without_openid();
    refresh_policy_changed.refresh_token_policy = RefreshTokenPolicy::Rotate {
        family_id: Uuid::now_v7(),
        rotated_from_id: Uuid::now_v7(),
    };
    assert_ne!(
        issuance_request_digest(&client, &refresh_policy_changed, grant_key),
        baseline,
        "refresh rotation identity must not reuse a non-rotation response",
    );

    let mut native_sso_changed = token_issue_without_openid();
    native_sso_changed.native_sso = Some(NativeSsoTokenBinding {
        device_secret: "device-secret".to_owned(),
        ds_hash: "device-secret-hash".to_owned(),
        sid: "native-sso-session".to_owned(),
    });
    assert_ne!(
        issuance_request_digest(&client, &native_sso_changed, grant_key),
        baseline,
        "Native SSO device binding must not reuse an ordinary token response",
    );

    let native_sso_digest = issuance_request_digest(&client, &native_sso_changed, grant_key);
    native_sso_changed.native_sso = Some(NativeSsoTokenBinding {
        device_secret: "fresh-device-secret-from-retry".to_owned(),
        ds_hash: "fresh-device-secret-hash-from-retry".to_owned(),
        sid: "native-sso-session".to_owned(),
    });
    assert_eq!(
        issuance_request_digest(&client, &native_sso_changed, grant_key),
        native_sso_digest,
        "server-generated Native SSO secret material must not break idempotent retries",
    );

    native_sso_changed
        .native_sso
        .as_mut()
        .expect("Native SSO binding should remain present")
        .sid = "different-native-sso-session".to_owned();
    assert_ne!(
        issuance_request_digest(&client, &native_sso_changed, grant_key),
        native_sso_digest,
        "a different Native SSO session must not reuse another session's response",
    );
}

#[test]
fn id_token_sid_is_omitted_unless_explicitly_requested() {
    let client = client_with_grants(&["authorization_code"]);
    let issue = token_issue_with_sid(Vec::new());
    assert_eq!(id_token_session_sid(&client, &issue, false), None);

    let issue = token_issue_with_sid(vec!["sid".to_owned()]);
    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("op-session-sid")
    );
}

#[test]
fn id_token_sid_is_included_for_session_bound_logout_clients() {
    let issue = token_issue_with_sid(Vec::new());

    let mut frontchannel_client = client_with_grants(&["authorization_code"]);
    frontchannel_client.frontchannel_logout_uri = Some("https://client.example/logout".to_owned());
    assert_eq!(
        id_token_session_sid(&frontchannel_client, &issue, true),
        Some("op-session-sid")
    );

    let mut backchannel_client = client_with_grants(&["authorization_code"]);
    backchannel_client.backchannel_logout_uri =
        Some("https://client.example/backchannel".to_owned());
    assert_eq!(
        id_token_session_sid(&backchannel_client, &issue, false),
        Some("op-session-sid")
    );
}

#[test]
fn id_token_sid_is_not_enabled_for_all_clients_by_logout_feature_flags() {
    let client = client_with_grants(&["authorization_code"]);
    let issue = token_issue_with_sid(Vec::new());

    assert_eq!(id_token_session_sid(&client, &issue, true), None);
}

#[test]
fn id_token_sid_request_object_also_allows_session_sid() {
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.id_token_claim_requests.push(OidcClaimRequest {
        name: "sid".to_owned(),
        essential: true,
        value: None,
        values: Vec::new(),
    });

    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("op-session-sid")
    );
}

#[test]
fn refresh_id_token_sid_contract_distinguishes_presence_and_original_omission() {
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.refresh_id_token_sid = Some(Some("native-sso-sid".to_owned()));
    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("native-sso-sid")
    );

    issue.refresh_id_token_sid = Some(None);
    assert_eq!(id_token_session_sid(&client, &issue, false), None);
}

#[test]
fn refresh_without_id_token_preserves_the_original_sid_contract() {
    let mut issue = token_issue_with_sid(Vec::new());
    issue.refresh_id_token_sid = Some(Some("original-sid".to_owned()));

    assert_eq!(persisted_id_token_sid(&issue, None), Some("original-sid"));
    assert_eq!(
        persisted_id_token_sid(&issue, Some("new-sid")),
        Some("new-sid")
    );
}

#[test]
fn essential_id_token_claim_requests_match_protocol_claim_values() {
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.acr = Some("urn:example:loa:2".to_owned());
    issue.id_token_claim_requests = vec![
        OidcClaimRequest {
            name: "auth_time".to_owned(),
            essential: true,
            value: Some(json!(1_000)),
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "amr".to_owned(),
            essential: true,
            value: None,
            values: vec![json!(["password"]), json!(["password", "otp"])],
        },
        OidcClaimRequest {
            name: "acr".to_owned(),
            essential: true,
            value: Some(json!("urn:example:loa:2")),
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "sid".to_owned(),
            essential: true,
            value: None,
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: None,
            values: vec![json!("engineering"), json!("security")],
        },
    ];
    let extra_claims = json!({"department": "engineering"});

    assert!(refreshed_id_token_essential_claims_satisfied(
        &issue,
        &client,
        false,
        Some(&extra_claims),
    ));

    assert!(claim_request_value_matches(
        &OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: None,
            values: Vec::new(),
        },
        &json!("anything"),
    ));
    assert!(!claim_request_value_matches(
        &OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: Some(json!("finance")),
            values: Vec::new(),
        },
        &json!("engineering"),
    ));
    assert!(!claim_request_value_matches(
        &OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: None,
            values: vec![json!("finance")],
        },
        &json!("engineering"),
    ));

    issue.acr = Some("urn:example:loa:1".to_owned());
    assert!(!refreshed_id_token_essential_claims_satisfied(
        &issue,
        &client,
        false,
        Some(&extra_claims),
    ));
}

#[test]
fn response_from_token_issuance_returns_only_a_persisted_body() {
    let mut record = TokenIssuanceRecord {
        issuance_id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        client_id: Uuid::now_v7(),
        user_id: None,
        grant_key: "grant".to_owned(),
        request_digest: "digest".to_owned(),
        access_token_jti: Some("jti".to_owned()),
        access_token_expires_at: Some(Utc::now().timestamp() + 300),
        response_body: Some(br#"{}"#.to_vec()),
        response_digest: Some("digest".to_owned()),
        response_key_version: Some("v1".to_owned()),
    };
    let response = response_from_token_issuance(&record)
        .expect("committed issuance with a response body should be recoverable");
    assert_eq!(
        response,
        TokenEndpointSuccess::Replayed {
            body: br#"{}"#.to_vec()
        }
    );
    record.response_body = None;
    assert!(response_from_token_issuance(&record).is_none());
}

#[test]
fn id_token_signing_alg_uses_rs256_default_and_ps256_for_fapi_clients() {
    let baseline = client_with_grants(&["authorization_code"]);
    assert_eq!(
        id_token_signing_alg_for_client(&baseline),
        jsonwebtoken::Algorithm::RS256
    );

    let mut private_key_jwt = baseline.clone();
    private_key_jwt.token_endpoint_auth_method = "private_key_jwt".to_owned();
    assert_eq!(
        id_token_signing_alg_for_client(&private_key_jwt),
        jsonwebtoken::Algorithm::RS256
    );

    let mut holder_bound = baseline.clone();
    holder_bound.require_dpop_bound_tokens = true;
    assert_eq!(
        id_token_signing_alg_for_client(&holder_bound),
        jsonwebtoken::Algorithm::PS256
    );

    let mut par_request_object = baseline;
    par_request_object.require_par_request_object = true;
    assert_eq!(
        id_token_signing_alg_for_client(&par_request_object),
        jsonwebtoken::Algorithm::PS256
    );

    let mut negotiated = par_request_object;
    negotiated.id_token_signed_response_alg = Some("ES256".to_owned());
    assert_eq!(
        id_token_signing_alg_for_client(&negotiated),
        jsonwebtoken::Algorithm::ES256
    );
}
