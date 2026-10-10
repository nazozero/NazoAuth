use super::super::tests::client_with_grants;
use super::*;

fn openid_issue() -> TokenIssue {
    TokenIssue {
        native_sso_source: None,
        user_id: Some(Uuid::now_v7()),
        prepared_subject: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: Some("original-nonce".to_owned()),
        auth_time: Some(1_700_000_000),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("original-sid".to_owned()),
        acr: Some("1".to_owned()),
        userinfo_claim_requests: ((vec!["email".to_owned()])
            .into_iter()
            .map(nazo_auth::OidcClaimRequest::named)
            .collect::<Vec<_>>())
        .into(),
        id_token_claim_requests: ((vec!["email".to_owned()])
            .into_iter()
            .map(nazo_auth::OidcClaimRequest::named)
            .collect::<Vec<_>>())
        .into(),

        include_refresh: true,
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
fn refresh_authentication_context_preserves_original_claim_contract_on_scope_narrowing() {
    let mut issue = openid_issue();
    // The issued AT narrows scopes; its original claim context is unchanged.
    issue.scopes = vec!["openid".to_owned()];

    let context = refresh_authentication_context(&issue, "https://issuer.example", "client-1")
        .expect("openid refresh token should carry authentication context");
    assert_eq!(context.issuer, "https://issuer.example");
    assert_eq!(context.audience, "client-1");
    let wire = serde_json::to_value(&context).unwrap();
    assert!(wire.get("id_token_sid").is_none());
    assert_eq!(context.auth_time, 1_700_000_000);
    assert_eq!(context.amr, vec!["pwd"]);
    assert_eq!(context.oidc_sid.as_deref(), Some("original-sid"));
    assert_eq!(context.acr.as_deref(), Some("1"));
    assert!(wire.get("nonce").is_none());
    assert_eq!(issue.nonce.as_deref(), Some("original-nonce"));
    assert_eq!(context.id_token_claim_requests.names(), vec!["email"]);
}

#[test]
fn should_issue_refresh_token_true_with_refresh_grant_and_offline_access() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes, false));
}

#[test]
fn should_issue_refresh_token_false_without_offline_access_scope() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));
}

#[test]
fn should_issue_refresh_token_for_openid4vci_credential_authorization() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["org.iso.18013.5.1.mDL".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes, true));
}

#[test]
fn openid4vci_credential_authorization_still_requires_refresh_grant() {
    let client = client_with_grants(&["authorization_code"]);
    let scopes = vec!["org.iso.18013.5.1.mDL".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, true));
}

#[test]
fn should_issue_refresh_token_false_without_refresh_grant() {
    let client = client_with_grants(&["authorization_code"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));
}

#[test]
fn should_issue_refresh_token_exact_grant_match_required() {
    let client = client_with_grants(&["authorization_code", "refresh_token:legacy"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));
}

#[test]
fn should_issue_refresh_token_scope_case_sensitive() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "OFFLINE_ACCESS".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));

    let scopes = vec!["openid".to_owned(), "offline_access ".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));

    let scopes = vec!["openid".to_owned(), "offline".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));
}

fn source_for_issue(issue: &TokenIssue, client: &ClientRow) -> nazo_auth::RefreshTokenAuthority {
    let contract = nazo_auth::RefreshContract {
        subject: issue.subject.clone(),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://a".to_owned(), "resource://b".to_owned()],
        authorization_details: issue.authorization_details.clone(),
        authentication_context: refresh_authentication_context(
            issue,
            "https://issuer.example",
            &client.client_id,
        )
        .unwrap(),
    }
    .clone();
    nazo_auth::RefreshTokenAuthority {
        tenant_id: client.tenant_id,
        client_id: client.id,
        user_id: issue.user_id,
        family_id: Uuid::now_v7(),
        member_id: Uuid::now_v7(),
        token_blake3: [4; 32],
        contract_key: (*blake3::hash(&serde_json::to_vec(&contract).unwrap()).as_bytes()),
        current_audiences: contract.audiences.clone(),
        id_token_sid: None,
        dpop_jkt: None,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
        contract,
    }
}

#[test]
fn rotated_refresh_preserves_original_contract_while_selecting_current_audience() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = openid_issue();
    let source = source_for_issue(&issue, &client);
    let original = source.contract.clone();
    let now = Utc::now();
    let pending = PendingRefreshToken {
        raw: "replacement".to_owned(),
        member_id: Uuid::now_v7(),
        family: source.family_id,
        rotated_from: Some(source.member_id),
        lost_response_retry: None,
        issued_at: now,
        expires_at: now + chrono::Duration::hours(1),
    };
    issue.audiences = vec!["resource://a".to_owned()];

    issue.refresh_token_policy = RefreshTokenPolicy::Rotate {
        family_id: source.family_id,
        rotated_from_id: source.member_id,
    };
    issue.refresh_authority = Some(source);
    assert!(refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
    let replacement = prepare_refresh_token(&client, &issue, &pending, None);
    assert_eq!(replacement.audiences, vec!["resource://a"]);
    assert_eq!(issue.refresh_authority.as_ref().unwrap().contract, original);
    assert_eq!(original.scopes, vec!["openid", "offline_access"]);
    for audience in [vec!["resource://c".to_owned()], vec![]] {
        issue.audiences = audience;
        assert!(!refresh_issue_matches_source(
            &issue,
            &client,
            "https://issuer.example"
        ));
    }
    issue.audiences = vec!["resource://a".to_owned()];
    issue.auth_time = Some(issue.auth_time.unwrap() + 1);
    assert!(!refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
}

#[test]
fn new_refresh_family_retains_full_code_grant_when_access_token_is_narrower() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = openid_issue();
    issue.audiences = vec!["resource://a".to_owned()];
    issue.refresh_grant_audiences =
        Some(vec!["resource://a".to_owned(), "resource://b".to_owned()]);
    let now = Utc::now();
    let pending = PendingRefreshToken {
        raw: "initial".to_owned(),
        member_id: Uuid::now_v7(),
        family: Uuid::now_v7(),
        rotated_from: None,
        lost_response_retry: None,
        issued_at: now,
        expires_at: now + chrono::Duration::hours(1),
    };
    let token = prepare_refresh_token(&client, &issue, &pending, None);
    assert_eq!(issue.audiences, vec!["resource://a"]);
    assert_eq!(token.audiences, vec!["resource://a", "resource://b"]);
}

#[test]
fn refresh_signing_input_preserves_sender_binding_and_cannot_add_an_actor() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = openid_issue();
    issue.audiences = vec!["resource://a".to_owned()];

    let mut source = source_for_issue(&issue, &client);
    source.dpop_jkt = Some("original-key".to_owned());
    issue.refresh_token_policy = RefreshTokenPolicy::PreserveExisting;
    issue.refresh_token_dpop_jkt = source.dpop_jkt.clone();
    issue.refresh_authority = Some(source);
    assert!(!refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
    issue.dpop_jkt = Some("different-key".to_owned());
    assert!(!refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
    issue.dpop_jkt = Some("original-key".to_owned());
    assert!(refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));

    issue.dpop_jkt = None;
    issue.refresh_token_dpop_jkt = None;
    let source = issue.refresh_authority.as_mut().unwrap();
    source.dpop_jkt = None;
    source.mtls_x5t_s256 = Some("original-certificate".to_owned());
    issue.refresh_token_mtls_x5t_s256 = Some("original-certificate".to_owned());
    assert!(!refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
    issue.mtls_x5t_s256 = Some("different-certificate".to_owned());
    assert!(!refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
    issue.mtls_x5t_s256 = Some("original-certificate".to_owned());
    assert!(refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
    issue.actor = Some(json!({"sub": "different-actor"}));
    assert!(!refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
}

#[test]
fn refresh_policy_requires_exact_source_shape_even_without_a_refresh_response() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = openid_issue();
    let source = source_for_issue(&issue, &client);
    issue.audiences = vec!["resource://a".to_owned()];

    issue.include_refresh = false;
    let matches =
        |issue: &TokenIssue| refresh_issue_matches_source(issue, &client, "https://issuer.example");

    for policy in [RefreshTokenPolicy::NoRefresh, RefreshTokenPolicy::IssueNew] {
        issue.refresh_token_policy = policy;
        assert!(matches(&issue));
        issue.refresh_authority = Some(source.clone());
        assert!(!matches(&issue));
        issue.refresh_authority = None;
    }
    issue.refresh_token_policy = RefreshTokenPolicy::NoRefresh;
    issue.include_refresh = true;
    assert!(!matches(&issue));
    issue.include_refresh = false;

    for policy in [
        RefreshTokenPolicy::PreserveExisting,
        RefreshTokenPolicy::Rotate {
            family_id: source.family_id,
            rotated_from_id: source.member_id,
        },
        RefreshTokenPolicy::RotateLostResponse {
            family_id: source.family_id,
            original_id: Uuid::now_v7(),
            original_blake3: [5; 32],
            successor_id: source.member_id,
            retry_started_at: Utc::now(),
        },
    ] {
        issue.refresh_token_policy = policy;
        assert!(!matches(&issue));
        issue.refresh_authority = Some(source.clone());
        assert!(matches(&issue));
        issue.subject = "changed-subject".to_owned();
        assert!(!matches(&issue));
        issue.subject = source.contract.subject.clone();
        if !matches!(policy, RefreshTokenPolicy::PreserveExisting) {
            issue.refresh_authority.as_mut().unwrap().family_id = Uuid::now_v7();
            assert!(!matches(&issue));
            issue.refresh_authority = Some(source.clone());
            issue.refresh_authority.as_mut().unwrap().member_id = Uuid::now_v7();
            assert!(!matches(&issue));
        }
        issue.refresh_authority = None;
    }
}

#[test]
fn unbound_refresh_source_can_constrain_access_token_without_rebinding_refresh_token() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = openid_issue();
    let source = source_for_issue(&issue, &client);
    issue.audiences = vec!["resource://a".to_owned()];

    issue.refresh_token_policy = RefreshTokenPolicy::PreserveExisting;
    issue.refresh_authority = Some(source.clone());
    issue.dpop_jkt = Some("new-proof-key".to_owned());
    let matches =
        |issue: &TokenIssue| refresh_issue_matches_source(issue, &client, "https://issuer.example");
    assert!(matches(&issue));
    issue.refresh_token_dpop_jkt = issue.dpop_jkt.clone();
    assert!(!matches(&issue));
    issue.refresh_token_dpop_jkt = None;
    issue.dpop_jkt = None;
    issue.mtls_x5t_s256 = Some("new-certificate".to_owned());
    assert!(matches(&issue));
    issue.refresh_token_mtls_x5t_s256 = issue.mtls_x5t_s256.clone();
    assert!(!matches(&issue));
    issue.refresh_token_mtls_x5t_s256 = None;
    issue.refresh_token_client_attestation_jkt = Some("new-instance".to_owned());
    assert!(!matches(&issue));
    issue.refresh_token_client_attestation_jkt = None;

    issue.refresh_token_policy = RefreshTokenPolicy::Rotate {
        family_id: source.family_id,
        rotated_from_id: source.member_id,
    };
    assert!(matches(&issue));
    let now = Utc::now();
    let pending = PendingRefreshToken {
        raw: "replacement".to_owned(),
        member_id: Uuid::now_v7(),
        family: source.family_id,
        rotated_from: Some(source.member_id),
        lost_response_retry: None,
        issued_at: now,
        expires_at: now + chrono::Duration::hours(1),
    };
    let replacement = prepare_refresh_token(&client, &issue, &pending, None);
    assert!(replacement.dpop_jkt.is_none());
    assert!(replacement.mtls_x5t_s256.is_none());
    assert!(replacement.client_attestation_jkt.is_none());
}

fn ownership_preserved_issue(client: &ClientRow) -> TokenIssue {
    let mut issue = openid_issue();
    issue.refresh_authority = Some(source_for_issue(&issue, client));
    issue.refresh_token_policy = RefreshTokenPolicy::PreserveExisting;

    issue.audiences = vec!["resource://a".into()];
    issue
}

#[test]
fn ownership_refresh_borrowed_context_rejects_each_contract_field_difference() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    for field in 0..11 {
        let mut issue = ownership_preserved_issue(&client);
        assert!(refresh_issue_matches_source(
            &issue,
            &client,
            "https://issuer.example"
        ));
        let context = &mut issue
            .refresh_authority
            .as_mut()
            .unwrap()
            .contract
            .authentication_context;
        let request = nazo_auth::OidcClaimRequest {
            name: "profile".into(),
            essential: true,
            value: Some(json!("expected")),
            values: vec![],
        };
        match field {
            0 => context.version += 1,
            1 => context.issuer.push_str("/different"),
            2 => context.audience.push_str("-different"),
            3 => context.auth_time += 1,
            4 => context.amr.push("mfa".into()),
            5 => context.oidc_sid = Some("different".into()),
            6 => context.acr = Some("different".into()),
            7 => context
                .userinfo_claim_requests
                .push(nazo_auth::OidcClaimRequest::named("profile")),
            8 => context.userinfo_claim_requests.push(request),
            9 => context
                .id_token_claim_requests
                .push(nazo_auth::OidcClaimRequest::named("profile")),
            10 => context.id_token_claim_requests.push(request),
            _ => unreachable!(),
        }
        assert!(
            !refresh_issue_matches_source(&issue, &client, "https://issuer.example"),
            "context field {field}"
        );
    }
}

#[test]
fn ownership_refresh_context_normalizes_nonce_and_keeps_generation_sid_separate() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = ownership_preserved_issue(&client);
    issue.nonce = Some("different-response-nonce".into());
    issue.refresh_authority.as_mut().unwrap().id_token_sid = Some("generation-sid".into());
    assert!(refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("generation-sid")
    );
    // The current login session cannot overwrite the original generation SID.
    issue.oidc_sid = Some("other-sid".into());
    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("generation-sid")
    );
    assert!(!refresh_issue_matches_source(
        &issue,
        &client,
        "https://issuer.example"
    ));
}

#[test]
fn ownership_refresh_context_rejects_equal_but_malformed_issue_and_source() {
    for field in 0..6 {
        let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
        let mut issue = ownership_preserved_issue(&client);
        let mut issuer = "https://issuer.example";
        let context = &mut issue
            .refresh_authority
            .as_mut()
            .unwrap()
            .contract
            .authentication_context;
        match field {
            0 => {
                issuer = " ";
                context.issuer = issuer.into();
            }
            1 => {
                client.client_id = " ".into();
                context.audience = " ".into();
            }
            2 => {
                issue.auth_time = Some(0);
                context.auth_time = 0;
            }
            3 => {
                issue.amr = vec![" ".into()];
                context.amr = issue.amr.clone();
            }
            4 => {
                issue.oidc_sid = Some(" ".into());
                context.oidc_sid = issue.oidc_sid.clone();
            }
            5 => {
                issue.acr = Some(" ".into());
                context.acr = issue.acr.clone();
            }
            _ => unreachable!(),
        }
        assert!(
            !refresh_issue_matches_source(&issue, &client, issuer),
            "malformed context field {field}"
        );
    }
}

#[test]
fn ownership_refresh_rejects_blank_generation_sid_after_lifecycle_separation() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    for sid in ["", " "] {
        let mut issue = ownership_preserved_issue(&client);
        issue.refresh_authority.as_mut().unwrap().id_token_sid = Some(sid.into());
        assert!(!refresh_issue_matches_source(
            &issue,
            &client,
            "https://issuer.example"
        ));
    }
}

#[test]
fn refresh_id_token_sid_contract_distinguishes_presence_and_original_omission() {
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = ownership_preserved_issue(&client);
    issue.refresh_authority.as_mut().unwrap().id_token_sid = Some("native-sso-sid".to_owned());
    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("native-sso-sid")
    );

    issue.refresh_authority.as_mut().unwrap().id_token_sid = None;
    assert_eq!(id_token_session_sid(&client, &issue, false), None);
}

#[test]
fn refresh_without_id_token_preserves_the_original_sid_contract() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = ownership_preserved_issue(&client);
    issue.refresh_authority.as_mut().unwrap().id_token_sid = Some("original-sid".to_owned());

    assert_eq!(persisted_id_token_sid(&issue, None), Some("original-sid"));
    assert_eq!(
        persisted_id_token_sid(&issue, Some("new-sid")),
        Some("new-sid")
    );
}
