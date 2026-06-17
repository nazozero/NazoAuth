use super::*;
use std::path::PathBuf;

use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, RateLimitSettings,
    RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr};

fn code_payload(dpop_jkt: Option<&str>) -> CodePayload {
    CodePayload {
        code_id: "code-id".to_owned(),
        user_id: Uuid::nil(),
        client_id: "client-1".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        nonce: None,
        auth_time: 1,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: dpop_jkt.map(ToOwned::to_owned),
        mtls_x5t_s256: None,
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn settings(profile: AuthorizationServerProfile) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins: vec!["https://app.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        authorization_server_profile: profile,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "sid".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 3600,
        auth_code_ttl_seconds: 60,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: PathBuf::from("runtime/avatars"),
        jwk_keys_dir: PathBuf::from("runtime/keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        trusted_proxy_cidrs: Vec::<IpCidr>::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: profile.requires_fapi2_security(),
        scim_bearer_token: None,
        passkey: crate::settings::PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: crate::settings::FederationSettings {
            oidc: None,
            saml_gateway: None,
        },
    }
}

fn client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_argon2_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
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

#[test]
fn pending_authorization_code_detects_dpop_binding() {
    let raw = serde_json::to_string(&AuthorizationCodeState::Pending {
        payload: code_payload(Some("thumbprint")),
    })
    .expect("pending code should serialize");

    assert!(
        pending_authorization_code_payload(&raw)
            .expect("state should parse")
            .is_some_and(|payload| payload.dpop_jkt.is_some())
    );
}

#[test]
fn non_dpop_or_non_pending_authorization_code_is_not_holder_bound() {
    let pending = serde_json::to_string(&AuthorizationCodeState::Pending {
        payload: code_payload(None),
    })
    .expect("pending code should serialize");
    let failed = serde_json::to_string(&AuthorizationCodeState::Failed {
        failed_at: Utc::now(),
        error: "invalid_grant".to_owned(),
    })
    .expect("failed code should serialize");

    assert!(
        pending_authorization_code_payload(&pending)
            .expect("state should parse")
            .is_some_and(|payload| payload.dpop_jkt.is_none())
    );
    assert!(
        pending_authorization_code_payload(&failed)
            .expect("state should parse")
            .is_none()
    );
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

#[test]
fn missing_client_dpop_authorization_code_holder_uses_invalid_grant() {
    let response = authorization_code_holder_missing_client_error(true, false)
        .expect("dpop holder binding should return an error");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
}

#[test]
fn missing_client_mtls_authorization_code_holder_uses_invalid_request() {
    for (dpop_bound, mtls_bound) in [(false, true), (true, true)] {
        let response = authorization_code_holder_missing_client_error(dpop_bound, mtls_bound)
            .expect("mtls holder binding should return an error");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "invalid_request");
    }
}

#[test]
fn missing_client_unbound_authorization_code_does_not_mask_client_auth_failure() {
    assert!(
        authorization_code_holder_missing_client_error(false, false).is_none(),
        "authorization codes without sender binding should proceed to normal client authentication"
    );
}

#[test]
fn missing_client_client_credentials_without_dpop_uses_invalid_request() {
    let form = TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: Some("accounts".to_owned()),
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: Vec::new(),
    };
    let response = client_credentials_holder_missing_client_error(&form, false)
        .expect("missing DPoP proof should be reported before generic client auth");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
}

#[test]
fn missing_client_holder_check_ignores_non_client_credentials_grants() {
    let form = TokenForm {
        grant_type: "refresh_token".to_owned(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: Some("refresh-token".to_owned()),
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: Vec::new(),
    };

    assert!(client_credentials_holder_missing_client_error(&form, false).is_none());
}

#[test]
fn missing_client_client_credentials_with_dpop_stays_client_auth_failure() {
    let form = TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: Some("accounts".to_owned()),
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: Vec::new(),
    };

    assert!(client_credentials_holder_missing_client_error(&form, true).is_none());
}

#[test]
fn missing_client_mtls_client_credentials_uses_invalid_request() {
    let form = TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: Some("accounts".to_owned()),
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: Vec::new(),
    };

    let response = client_credentials_holder_missing_client_error(&form, false)
        .expect("missing holder-of-key proof should be reported before generic client auth");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
}

#[test]
fn token_request_auth_material_detects_assertion_even_without_client_id() {
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("code".to_owned()),
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: Some("malformed-or-missing-sub".to_owned()),
        audiences: Vec::new(),
    };

    assert!(token_request_has_client_auth_material(false, &form));
}

#[test]
fn token_request_auth_material_detects_each_registered_client_auth_channel() {
    let base = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("code".to_owned()),
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: Vec::new(),
    };

    assert!(token_request_has_client_auth_material(true, &base));

    let mut with_client_id = base;
    with_client_id.client_id = Some("client-1".to_owned());
    assert!(token_request_has_client_auth_material(
        false,
        &with_client_id
    ));

    let mut with_secret = with_client_id;
    with_secret.client_id = None;
    with_secret.client_secret = Some("secret".to_owned());
    assert!(token_request_has_client_auth_material(false, &with_secret));

    let mut with_assertion_type = with_secret;
    with_assertion_type.client_secret = None;
    with_assertion_type.client_assertion_type =
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned());
    assert!(token_request_has_client_auth_material(
        false,
        &with_assertion_type
    ));
}

#[test]
fn token_request_auth_material_allows_absent_client_credentials() {
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("code".to_owned()),
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: Vec::new(),
    };

    assert!(!token_request_has_client_auth_material(false, &form));
}

#[test]
fn mtls_client_credentials_uses_tls_auth_method() {
    let credentials = mtls_client_credentials("client-1".to_owned());

    assert_eq!(credentials.client_id.as_deref(), Some("client-1"));
    assert_eq!(credentials.method, "tls_client_auth");
    assert!(credentials.client_secret.is_none());
    assert!(credentials.client_assertion.is_none());
}

#[test]
fn baseline_profile_does_not_restrict_token_client_auth() {
    let mut client = client();
    client.token_endpoint_auth_method = "client_secret_basic".to_owned();
    client.require_dpop_bound_tokens = false;

    assert!(
        validate_token_request_profile(
            &settings(AuthorizationServerProfile::Oauth2Baseline),
            &client,
            "client_secret_basic",
        )
        .is_ok()
    );
}

#[test]
fn disabled_client_is_rejected_before_grant_dispatch() {
    let mut client = client();
    client.is_active = false;

    let response = validate_token_client_enabled(&client, "authorization_code")
        .expect_err("disabled clients must not use token grants");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");
}

#[test]
fn active_client_with_registered_grant_is_allowed_to_dispatch() {
    let client = client();

    assert!(validate_token_client_enabled(&client, "authorization_code").is_ok());
}

#[test]
fn missing_grant_registration_is_rejected_before_grant_dispatch() {
    let client = client();

    let response = validate_token_client_enabled(&client, "client_credentials")
        .expect_err("client must be registered for the requested grant");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");
}

#[test]
fn fapi2_profile_requires_confidential_client_auth_and_sender_constraint() {
    let fapi = settings(AuthorizationServerProfile::Fapi2Security);
    let valid_client = client();

    assert!(validate_token_request_profile(&fapi, &valid_client, "private_key_jwt").is_ok());

    let weak_auth = validate_token_request_profile(&fapi, &valid_client, "client_secret_basic")
        .expect_err("client_secret_basic is not a FAPI2 client auth method");
    assert_eq!(weak_auth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&weak_auth), "invalid_client");

    let mut bearer_client = client();
    bearer_client.require_dpop_bound_tokens = false;
    let bearer = validate_token_request_profile(&fapi, &bearer_client, "private_key_jwt")
        .expect_err("FAPI2 requires sender-constrained tokens");
    assert_eq!(bearer.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&bearer), "invalid_request");

    let mut public_client = client();
    public_client.client_type = "public".to_owned();
    let public = validate_token_request_profile(&fapi, &public_client, "none")
        .expect_err("FAPI2 rejects public clients");
    assert_eq!(public.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&public), "unauthorized_client");
}

#[test]
fn fapi2_profile_accepts_mtls_confidential_sender_constrained_clients() {
    let fapi = settings(AuthorizationServerProfile::Fapi2Security);
    let mut client = client();
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;

    assert!(
        validate_token_request_profile(&fapi, &client, "tls_client_auth").is_ok(),
        "FAPI2 allows confidential mTLS clients when tokens are sender constrained"
    );
}

#[test]
fn fapi2_profile_accepts_self_signed_mtls_confidential_sender_constrained_clients() {
    let fapi = settings(AuthorizationServerProfile::Fapi2Security);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;

    assert!(
        validate_token_request_profile(&fapi, &client, "self_signed_tls_client_auth").is_ok(),
        "FAPI2 allows self-signed mTLS when the client is confidential and sender constrained"
    );
}

#[test]
fn grant_dispatch_rejects_malformed_grant_registration_without_panicking() {
    let mut client = client();
    client.grant_types = json!("authorization_code");

    let response = validate_token_client_enabled(&client, "authorization_code")
        .expect_err("non-array grant_types must fail closed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");
}
