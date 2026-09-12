use super::super::tests::client_with_grants;
use super::*;

#[test]
fn rotated_refresh_token_preserves_the_original_scope_authorization() {
    let access_token_scopes = vec!["openid".to_owned()];
    let original_refresh_token_scopes = vec!["openid".to_owned(), "offline_access".to_owned()];

    assert_eq!(
        refresh_token_persistence_scopes(
            &access_token_scopes,
            Some(&original_refresh_token_scopes),
        ),
        original_refresh_token_scopes
    );
}

fn openid_issue() -> TokenIssue {
    TokenIssue {
        user_id: Some(Uuid::now_v7()),
        subject: "subject-1".to_owned(),
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: Some("original-nonce".to_owned()),
        auth_time: Some(1_700_000_000),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("original-sid".to_owned()),
        acr: Some("1".to_owned()),
        userinfo_claims: vec!["email".to_owned()],
        userinfo_claim_requests: Vec::new(),
        id_token_claims: vec!["email".to_owned()],
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
fn refresh_authentication_context_preserves_original_claim_contract_on_scope_narrowing() {
    let mut issue = openid_issue();
    issue.refresh_token_scopes = Some(vec!["openid".to_owned(), "offline_access".to_owned()]);
    issue.scopes = vec!["openid".to_owned()];

    let context = refresh_authentication_context(
        &issue,
        "https://issuer.example",
        "client-1",
        Some("original-sid"),
    )
    .expect("openid refresh token should carry authentication context");
    assert_eq!(context.issuer, "https://issuer.example");
    assert_eq!(context.audience, "client-1");
    assert_eq!(context.id_token_sid.as_deref(), Some("original-sid"));
    assert_eq!(context.auth_time, 1_700_000_000);
    assert_eq!(context.amr, vec!["pwd"]);
    assert_eq!(context.oidc_sid.as_deref(), Some("original-sid"));
    assert_eq!(context.acr.as_deref(), Some("1"));
    assert_eq!(context.nonce.as_deref(), Some("original-nonce"));
    assert_eq!(context.id_token_claims, vec!["email"]);
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
