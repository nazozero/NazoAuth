use super::*;
use nazo_auth::OidcClaimRequest;
use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use uuid::Uuid;
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
        native_sso_source: None,
        user_id: None,
        prepared_subject: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: None,
        auth_time: Some(1_000),
        amr: vec!["password".to_owned()],
        oidc_sid: Some("op-session-sid".to_owned()),
        acr: None,
        userinfo_claim_requests: (Vec::new()).into(),
        id_token_claim_requests: ((id_token_claims)
            .into_iter()
            .map(nazo_auth::OidcClaimRequest::named)
            .collect::<Vec<_>>())
        .into(),

        include_refresh: false,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
        refresh_authority: None,
        refresh_grant_audiences: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
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
fn essential_id_token_claim_requests_match_protocol_claim_values() {
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.acr = Some("urn:example:loa:2".to_owned());
    issue.id_token_claim_requests = (vec![
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
    ])
    .into();
    let extra_claims = json!({"department": "engineering"});

    assert!(refreshed_id_token_essential_claims_satisfied(
        &issue,
        &client,
        false,
        extra_claims.as_object().unwrap(),
    ));

    assert!(
        OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: None,
            values: Vec::new(),
        }
        .matches_value(&json!("anything"))
    );
    assert!(
        !OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: Some(json!("finance")),
            values: Vec::new(),
        }
        .matches_value(&json!("engineering"))
    );
    assert!(
        !OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: None,
            values: vec![json!("finance")],
        }
        .matches_value(&json!("engineering"))
    );

    issue.acr = Some("urn:example:loa:1".to_owned());
    assert!(!refreshed_id_token_essential_claims_satisfied(
        &issue,
        &client,
        false,
        extra_claims.as_object().unwrap(),
    ));
}

#[test]
fn id_token_signing_algorithm_follows_the_profile_not_sender_binding() {
    assert_eq!(
        nazo_auth::id_token_signing_algorithm(None, false),
        Ok("RS256")
    );
    assert_eq!(
        nazo_auth::id_token_signing_algorithm(None, true),
        Ok("PS256")
    );
    assert_eq!(
        nazo_auth::id_token_signing_algorithm(Some("ES256"), true),
        Ok("ES256")
    );
    assert!(nazo_auth::id_token_signing_algorithm(Some("RS256"), true).is_err());
}
