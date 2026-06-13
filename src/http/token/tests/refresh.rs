use super::*;

fn client_row() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code", "refresh_token"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: true,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
    }
}

fn token_row() -> TokenRow {
    TokenRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        token_family_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: Some(Uuid::now_v7()),
        scopes: json!(["openid", "offline_access"]),
        authorization_details: json!([]),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(30),
        revoked_at: None,
        subject: "subject-1".to_owned(),
        dpop_jkt: Some("dpop-jkt".to_owned()),
        mtls_x5t_s256: None,
    }
}

#[test]
fn fapi_profiles_preserve_sender_constrained_refresh_tokens() {
    let token = token_row();
    let client = client_row();

    for profile in [
        AuthorizationServerProfile::Fapi2Security,
        AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
    ] {
        assert_eq!(
            refresh_token_policy_for_authorization_server_profile(profile, &client, &token),
            RefreshTokenPolicy::PreserveExisting
        );
    }
}

#[test]
fn baseline_profile_preserves_confidential_sender_constrained_refresh_tokens() {
    let token = token_row();
    let client = client_row();

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::PreserveExisting
    );
}

#[test]
fn baseline_profile_preserves_confidential_dpop_refresh_tokens_without_client_requirement() {
    let token = token_row();
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::PreserveExisting
    );
}

#[test]
fn baseline_profile_preserves_confidential_sender_constrained_client_refresh_tokens() {
    let mut token = token_row();
    token.dpop_jkt = None;
    token.mtls_x5t_s256 = None;
    let client = client_row();

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::PreserveExisting
    );
}

#[test]
fn baseline_profile_rotates_public_sender_constrained_refresh_tokens() {
    let token = token_row();
    let mut client = client_row();
    client.client_type = "public".to_owned();
    client.token_endpoint_auth_method = "none".to_owned();

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        },
        "public-client refresh tokens must rotate even when sender-constrained"
    );
}

#[test]
fn baseline_profile_rotates_confidential_secret_authenticated_sender_constrained_refresh_tokens() {
    let token = token_row();
    let mut client = client_row();
    client.token_endpoint_auth_method = "client_secret_basic".to_owned();

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        },
        "only confidential clients using holder-of-key client auth may preserve sender-constrained refresh tokens"
    );
}

#[test]
fn baseline_profile_rotates_unbound_refresh_tokens() {
    let mut token = token_row();
    token.dpop_jkt = None;
    let mut client = client_row();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = false;

    assert_eq!(
        refresh_token_policy_for_authorization_server_profile(
            AuthorizationServerProfile::Oauth2Baseline,
            &client,
            &token,
        ),
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        }
    );
}

#[test]
fn lost_refresh_retry_allows_only_short_post_rotation_window() {
    let now = Utc::now();

    assert!(within_lost_refresh_token_retry_window(
        now - Duration::seconds(1),
        now
    ));
    assert!(within_lost_refresh_token_retry_window(
        now - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS),
        now
    ));
    assert!(!within_lost_refresh_token_retry_window(
        now - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS + 1),
        now
    ));
}

#[test]
fn lost_refresh_retry_rejects_future_revocation_times() {
    let now = Utc::now();

    assert!(!within_lost_refresh_token_retry_window(
        now + Duration::seconds(1),
        now
    ));
}

#[test]
fn refresh_token_scope_request_defaults_to_original_authorization() {
    let original = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ];

    assert_eq!(refresh_token_scopes(&original, None).unwrap(), original);
    assert_eq!(refresh_token_scopes(&original, Some("")).unwrap(), original);
    assert_eq!(
        refresh_token_scopes(&original, Some("   ")).unwrap(),
        original
    );
}

#[test]
fn refresh_token_scope_request_may_only_narrow_original_authorization() {
    let original = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ];

    assert_eq!(
        refresh_token_scopes(&original, Some("openid offline_access")).unwrap(),
        vec!["openid".to_owned(), "offline_access".to_owned()]
    );
    assert_eq!(
        refresh_token_scopes(&original, Some("openid openid")).unwrap(),
        vec!["openid".to_owned(), "openid".to_owned()],
        "scope parsing preserves request shape while still enforcing subset authorization"
    );
}

#[test]
fn refresh_token_scope_request_rejects_privilege_expansion() {
    let original = vec!["openid".to_owned(), "offline_access".to_owned()];

    for requested in ["email", "openid email", "offline_access admin"] {
        assert!(
            refresh_token_scopes(&original, Some(requested)).is_err(),
            "refresh_token grant must reject scope outside original authorization: {requested}"
        );
    }
}

#[test]
fn lost_refresh_retry_allows_exact_rotation_timestamp_only_until_window_expires() {
    let now = Utc::now();

    assert!(within_lost_refresh_token_retry_window(now, now));
    assert!(!within_lost_refresh_token_retry_window(
        now - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS + 1),
        now
    ));
}
