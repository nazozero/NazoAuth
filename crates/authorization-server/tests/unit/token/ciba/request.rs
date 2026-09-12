use super::*;
use crate::contracts::oauth_error::{OAuthEndpointError, OAuthErrorFields};
use crate::crypto::blake3_hex;
use crate::domain::rows::ClientRow;
use crate::token::ciba::{policy::*, state::*};
use crate::token::dispatch::validate_token_request_profile;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use http::StatusCode;
use nazo_auth::{CibaRequestState, CibaStatus};
use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use serde_json::{Value, json};
use uuid::Uuid;
fn fields(error: &OAuthEndpointError) -> &OAuthErrorFields {
    match error {
        OAuthEndpointError::Json(f)
        | OAuthEndpointError::Authorization(f)
        | OAuthEndpointError::Bearer(f)
        | OAuthEndpointError::Token { fields: f, .. } => f,
        _ => panic!("expected OAuth fields"),
    }
}
trait ErrorStatus {
    fn status(&self) -> StatusCode;
}
impl ErrorStatus for OAuthEndpointError {
    fn status(&self) -> StatusCode {
        fields(self).status
    }
}
fn oauth_error_code(error: OAuthEndpointError) -> String {
    fields(&error).error.clone()
}
fn config() -> CibaConfig {
    CibaConfig {
        issuer: "https://issuer.example".into(),
        mtls_endpoint_base_url: "".into(),
        frontend_base_url: "https://app.example".into(),
        client_secret_pepper: "".into(),
        default_audience: "resource://default".into(),
        tenant_id: DEFAULT_TENANT_ID,
        auth_req_id_ttl_seconds: 600,
        poll_interval_seconds: 5,
        ciba_fapi_profile: true,
        ciba_fapi2_hardening: false,
    }
}
struct ClientSigningFixture {
    keys: nazo_key_management::KeyManager,
}
fn client_signing_fixture(algorithm: jsonwebtoken::Algorithm) -> ClientSigningFixture {
    ClientSigningFixture {
        keys: nazo_key_management::KeyManager::for_test(algorithm),
    }
}
impl ClientSigningFixture {
    fn public_jwk(&self, kid: &str) -> Value {
        let mut jwk = self.keys.snapshot().verification_keys[0].public_jwk.clone();
        jwk["kid"] = json!(kid);
        jwk
    }
    fn encode_jwt<T: serde::Serialize>(&self, header: &jsonwebtoken::Header, claims: &T) -> String {
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("fixture header")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("fixture claims")),
        );
        let signature = futures_executor::block_on(nazo_auth::Signer::sign(
            &self.keys,
            nazo_auth::SignRequest {
                purpose: nazo_auth::SigningPurpose::IdToken,
                algorithm: nazo_key_management::signing_algorithm_name(header.alg)
                    .expect("fixture algorithm"),
                signing_input: signing_input.as_bytes(),
            },
        ))
        .expect("signed fixture");
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_bytes())
        )
    }
}
fn ciba_private_key_jwt_client_with_alg(kid: &str, fixture: &ClientSigningFixture) -> ClientRow {
    let mut client = base_client();
    client.client_id = "client-1".into();
    client.scopes = vec![
        "openid".into(),
        "profile".into(),
        "email".into(),
        "offline_access".into(),
    ];
    client.grant_types = vec![CIBA_GRANT_TYPE.into(), "refresh_token".into()];
    client.require_dpop_bound_tokens = false;
    client.jwks = Some(json!({"keys":[fixture.public_jwk(kid)]}));
    client.security_policy.allow_cross_device_flows = true;
    client
}
fn base_client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        require_mtls_bound_tokens: false,
        is_active: true,
        registration: nazo_auth::ValidatedClientRegistration {
            client_id: "client-a".to_owned(),
            client_name: "Client A".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
            allowed_audiences: vec!["resource://default".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
            require_dpop_bound_tokens: true,
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
fn ciba_private_key_jwt_client(kid: &str, fixture: &ClientSigningFixture) -> ClientRow {
    ciba_private_key_jwt_client_with_alg(kid, fixture)
}

fn signed_ciba_request_object_with_alg(
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    fixture: &ClientSigningFixture,
    extra_claims: Value,
) -> String {
    signed_ciba_request_object_for_client_with_alg("client-1", kid, alg, fixture, extra_claims)
}

fn signed_ciba_request_object_for_client_with_alg(
    client_id: &str,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    fixture: &ClientSigningFixture,
    extra_claims: Value,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": client_id,
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("ciba-request-{}", Uuid::now_v7()),
        "scope": "openid profile email",
        "login_hint": "subject@example.test",
        "binding_message": "1234"
    });
    let target = claims.as_object_mut().expect("claims should be object");
    for (key, value) in extra_claims
        .as_object()
        .expect("extra claims should be object")
    {
        if value.is_null() {
            target.remove(key);
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    let mut header = jsonwebtoken::Header::new(alg);
    header.kid = Some(kid.to_owned());
    fixture.encode_jwt(&header, &claims)
}

fn signed_ciba_request_object(
    kid: &str,
    fixture: &ClientSigningFixture,
    extra_claims: Value,
) -> String {
    signed_ciba_request_object_with_alg(kid, jsonwebtoken::Algorithm::PS256, fixture, extra_claims)
}

fn unsigned_ciba_request_object(client_id: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": client_id,
            "sub": client_id,
        }))
        .expect("payload should serialize"),
    );
    format!("{header}.{payload}.")
}
#[test]
fn ciba_status_serializes_as_protocol_state() {
    assert_eq!(
        serde_json::to_value(CibaStatus::Pending).unwrap(),
        json!("pending")
    );
}

#[test]
fn ciba_start_audit_fields_are_redacted() {
    let now = Utc::now().timestamp();
    let state = CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: None,
        authentication_context: None,
        binding_message: Some("sensitive binding text".to_owned()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
        ping_notification: None,
    };

    let fields = ciba_start_audit_fields(
        &state,
        "secret-auth-req-id",
        Some("source-ip-hash".to_owned()),
    );
    let serialized = serde_json::to_string(&fields).unwrap();

    assert!(serialized.contains(&blake3_hex("secret-auth-req-id")));
    assert!(!serialized.contains("secret-auth-req-id"));
    assert!(!serialized.contains("sensitive binding text"));
    assert!(!serialized.contains("binding_message"));
    assert!(!serialized.contains("client_assertion"));
    assert_eq!(fields.get("client_id"), Some(&json!("client-1")));
    assert_eq!(fields.get("source_ip_hash"), Some(&json!("source-ip-hash")));
}

#[test]
fn ciba_request_object_helpers_cover_protocol_boundaries() {
    let now = Utc::now().timestamp();
    let claims =
        |aud: Option<Value>, exp: i64, nbf: i64, iat: i64| CibaAuthenticationRequestClaims {
            iss: Some("client-1".to_owned()),
            aud,
            exp: Some(exp),
            nbf: Some(nbf),
            iat: Some(iat),
            jti: Some("jti-1".to_owned()),
            scope: None,
            login_hint: None,
            id_token_hint: None,
            login_hint_token: None,
            binding_message: None,
            acr_values: None,
            requested_expiry: None,
            client_notification_token: None,
        };
    let valid = claims(Some(json!("https://issuer.example")), now + 120, now, now);
    assert!(ciba_request_object_audience_valid(
        &valid,
        "https://issuer.example"
    ));
    assert!(ciba_request_object_audience_valid(
        &claims(
            Some(json!(["other", "https://issuer.example/bc-authorize"])),
            now + 120,
            now,
            now,
        ),
        "https://issuer.example"
    ));
    assert!(!ciba_request_object_audience_valid(
        &claims(Some(json!(42)), now + 120, now, now),
        "https://issuer.example"
    ));
    assert!(!ciba_request_object_audience_valid(
        &claims(None, now + 120, now, now),
        "https://issuer.example"
    ));

    assert!(ciba_request_object_times_valid(&valid, now));
    assert!(!ciba_request_object_times_valid(
        &claims(Some(json!("https://issuer.example")), now, now, now),
        now
    ));
    assert!(!ciba_request_object_times_valid(
        &claims(
            Some(json!("https://issuer.example")),
            now + 120,
            now + CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS + 1,
            now,
        ),
        now
    ));
    assert!(!ciba_request_object_times_valid(
        &claims(
            Some(json!("https://issuer.example")),
            now + 120,
            now - CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS - 1,
            now,
        ),
        now
    ));
    assert!(!ciba_request_object_times_valid(
        &claims(
            Some(json!("https://issuer.example")),
            now + 120,
            now,
            now + CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS + 1,
        ),
        now
    ));
    assert!(!ciba_request_object_times_valid(
        &claims(
            Some(json!("https://issuer.example")),
            now + 120,
            now,
            now - CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS - 1,
        ),
        now
    ));
    assert!(!ciba_request_object_times_valid(
        &claims(
            Some(json!("https://issuer.example")),
            now + CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS + 120,
            now,
            now,
        ),
        now
    ));
    assert!(!ciba_request_object_jti_valid(None));
    assert!(!ciba_request_object_jti_valid(Some("  ")));
    assert!(ciba_request_object_jti_valid(Some("jti")));
    assert!(!ciba_request_object_jti_valid(Some(&"x".repeat(129))));
    assert_eq!(ciba_request_object_hint_count(&valid), 0);
    let mut hinted = claims(Some(json!("https://issuer.example")), now + 120, now, now);
    hinted.login_hint = Some("user".to_owned());
    hinted.id_token_hint = Some("token".to_owned());
    assert_eq!(ciba_request_object_hint_count(&hinted), 2);

    let mut form = BackchannelAuthenticationForm {
        login_hint: Some("user".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    form.id_token_hint = Some("token".to_owned());
    assert_eq!(ciba_hint_count(&form), 2);
    assert_eq!(ciba_selected_acr(Some("0 1 2")).as_deref(), Some("1"));
    assert_eq!(ciba_selected_acr(Some("0 2")), None);
    assert!(ciba_binding_message_is_supported("1234"));
    assert!(!ciba_binding_message_is_supported("\n"));
    assert!(!ciba_binding_message_is_supported(
        &"x".repeat(CIBA_BINDING_MESSAGE_MAX_CHARS + 1)
    ));
    let valid_binding = BackchannelAuthenticationForm {
        binding_message: Some("1234".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    validate_ciba_binding_message(&valid_binding).expect("valid binding message must pass");
    for invalid in [
        " ".to_owned(),
        "line\nbreak".to_owned(),
        "x".repeat(CIBA_BINDING_MESSAGE_MAX_CHARS + 1),
    ] {
        let invalid_binding = BackchannelAuthenticationForm {
            binding_message: Some(invalid),
            ..BackchannelAuthenticationForm::default()
        };
        let response = validate_ciba_binding_message(&invalid_binding)
            .expect_err("invalid outer binding message must fail closed");
        assert_eq!(oauth_error_code(response), "invalid_binding_message");
    }

    let mut target = None;
    merge_request_object_string(&mut target, Some(" value ".to_owned()), "conflict")
        .expect("first request object value should apply");
    merge_request_object_string(&mut target, None, "conflict").expect("missing value is a no-op");
    merge_request_object_string(&mut target, Some("value".to_owned()), "conflict")
        .expect("equal request object value should be accepted");
    assert!(
        merge_request_object_string(&mut target, Some("other".to_owned()), "conflict").is_err()
    );
    assert!(merge_request_object_string(&mut target, Some("  ".to_owned()), "conflict").is_err());
    assert_eq!(ciba_requested_expiry_seconds(&json!(30)), Some(30));
    assert_eq!(ciba_requested_expiry_seconds(&json!("30")), Some(30));
    assert_eq!(ciba_requested_expiry_seconds(&json!(0)), None);
    assert_eq!(ciba_requested_expiry_seconds(&json!(true)), None);
    assert_eq!(parse_requested_expiry_string(" 30 "), Some(30));
    assert_eq!(parse_requested_expiry_string("0"), None);
    assert_eq!(parse_requested_expiry_string("bad"), None);

    assert_eq!(split_compact_jwt("a.b.c"), Some(("a", "b", "c")));
    assert_eq!(split_compact_jwt("a.b.c.d"), None);
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"PS256"}"#);
    assert_eq!(decode_jwt_header_value(&header).unwrap()["alg"], "PS256");
    assert!(decode_jwt_header_value("*").is_err());

    let fixture = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let signed = signed_ciba_request_object("ciba-kid", &fixture, json!({}));
    assert_eq!(
        unverified_signed_ciba_request_object_client_id(&signed).as_deref(),
        Some("client-1")
    );
    assert_eq!(unverified_signed_ciba_request_object_client_id("bad"), None);
    assert_eq!(
        unverified_signed_ciba_request_object_client_id("a.b."),
        None
    );
}

#[test]
fn ciba_request_object_without_request_is_a_noop() {
    let state = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);
    let mut form = BackchannelAuthenticationForm::default();

    assert!(
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect("missing request object should be accepted")
            .is_none()
    );
}

#[test]
fn ciba_request_object_rejects_unsupported_binding_and_parameter_conflicts() {
    let state = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);
    let unsupported =
        signed_ciba_request_object("ciba-kid", &key, json!({"binding_message": "\u{0001}"}));
    let mut form = BackchannelAuthenticationForm {
        request: Some(unsupported),
        ..BackchannelAuthenticationForm::default()
    };
    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect_err("unsupported binding_message must be rejected");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response), "invalid_binding_message");

    for field in [
        "scope",
        "login_hint",
        "id_token_hint",
        "login_hint_token",
        "binding_message",
        "acr_values",
        "client_notification_token",
    ] {
        let extra = match field {
            "scope" => json!({"scope": "openid"}),
            "login_hint" => json!({"login_hint": "request-user"}),
            "id_token_hint" => json!({
                "login_hint": null,
                "id_token_hint": "request-id-token"
            }),
            "login_hint_token" => json!({
                "login_hint": null,
                "login_hint_token": "request-login-token"
            }),
            "binding_message" => json!({"binding_message": "request-binding"}),
            "acr_values" => json!({"acr_values": "1"}),
            "client_notification_token" => {
                json!({"client_notification_token": "request-notification"})
            }
            _ => unreachable!("conflict field list is exhaustive"),
        };
        let request_object = signed_ciba_request_object("ciba-kid", &key, extra);
        let mut form = BackchannelAuthenticationForm {
            request: Some(request_object),
            ..BackchannelAuthenticationForm::default()
        };
        match field {
            "scope" => form.scope = Some("outer-scope".to_owned()),
            "login_hint" => form.login_hint = Some("outer-user".to_owned()),
            "id_token_hint" => form.id_token_hint = Some("outer-id-token".to_owned()),
            "login_hint_token" => form.login_hint_token = Some("outer-login-token".to_owned()),
            "binding_message" => form.binding_message = Some("outer-binding".to_owned()),
            "acr_values" => form.acr_values = Some("2".to_owned()),
            "client_notification_token" => {
                form.client_notification_token = Some("outer-notification".to_owned())
            }
            _ => unreachable!("conflict field list is exhaustive"),
        }
        let response =
            validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
                .expect_err("outer and request object parameters must not conflict");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(oauth_error_code(response), "invalid_request", "{field}");
    }
}

#[test]
fn ciba_request_object_rejects_invalid_or_conflicting_requested_expiry() {
    let state = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);

    let request_object = signed_ciba_request_object(
        "ciba-kid",
        &key,
        json!({"requested_expiry": "not-a-duration"}),
    );
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };
    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect_err("invalid request object expiry must be rejected");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response), "invalid_request");

    let request_object =
        signed_ciba_request_object("ciba-kid", &key, json!({"requested_expiry": "30"}));
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        requested_expiry_seconds: Some(31),
        ..BackchannelAuthenticationForm::default()
    };
    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect_err("outer and request object expiry must not conflict");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response), "invalid_request");
}

#[test]
fn ciba_request_object_rejects_invalid_compact_jwt_metadata() {
    let state = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);

    for request_object in ["not-a-jwt".to_owned(), "a.b.".to_owned()] {
        let mut form = BackchannelAuthenticationForm {
            request: Some(request_object),
            ..BackchannelAuthenticationForm::default()
        };
        let response =
            validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
                .expect_err("malformed request object must be rejected");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(response), "invalid_request");
    }

    let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(r#"{"iss":"client-1"}"#);
    let mut form = BackchannelAuthenticationForm {
        request: Some(format!("{none_header}.{payload}.signature")),
        ..BackchannelAuthenticationForm::default()
    };
    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect_err("alg=none request object must be rejected");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response), "invalid_request");

    let mut mismatched = client.clone();
    mismatched.backchannel_authentication_request_signing_alg = Some("ES256".to_owned());
    let request_object = signed_ciba_request_object("ciba-kid", &key, json!({}));
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };
    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &mismatched, &mut form)
            .expect_err("request object algorithm must match registration");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response), "invalid_request");

    let claims = json!({
        "iss": "client-1",
        "aud": "https://issuer.example",
        "iat": Utc::now().timestamp(),
        "nbf": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 120,
        "jti": format!("missing-kid-{}", Uuid::now_v7()),
        "login_hint": "subject@example.test"
    });
    let request_object = key.encode_jwt(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256),
        &claims,
    );
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };
    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect_err("request object without kid must be rejected");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response), "invalid_request");

    let request_object = signed_ciba_request_object("unknown-kid", &key, json!({}));
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };
    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect_err("request object with an unknown key must be rejected");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response), "invalid_request");
}

#[test]
fn ciba_unverified_request_object_hint_rejects_none_and_empty_issuers() {
    let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(r#"{"iss":"client-1","sub":"client-1"}"#);
    assert_eq!(
        unverified_signed_ciba_request_object_client_id(&format!(
            "{none_header}.{payload}.signature"
        )),
        None
    );

    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"PS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(r#"{"iss":"  "}"#);
    assert_eq!(
        unverified_signed_ciba_request_object_client_id(&format!("{header}.{payload}.signature")),
        None
    );
}

#[test]
fn ciba_signed_request_object_claims_apply_to_backchannel_form() {
    let state = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);
    let request_object = signed_ciba_request_object(
        "ciba-kid",
        &key,
        json!({"requested_expiry": "30", "acr_values": "1"}),
    );
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };

    validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
        .expect("valid signed CIBA request object should apply");

    assert_eq!(form.scope.as_deref(), Some("openid profile email"));
    assert_eq!(form.login_hint.as_deref(), Some("subject@example.test"));
    assert_eq!(form.binding_message.as_deref(), Some("1234"));
    assert_eq!(form.acr_values.as_deref(), Some("1"));
    assert_eq!(form.requested_expiry_seconds, Some(30));
}

#[test]
fn ciba_request_object_presence_enforces_client_policy() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_par_request_object = true;

    let settings = config();
    let missing_request_response = validate_ciba_request_object_presence_with_config(
        &settings,
        &client,
        &BackchannelAuthenticationForm::default(),
    )
    .expect_err("CIBA request object policy must reject unsigned form parameters");

    assert_eq!(missing_request_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(missing_request_response).as_str()),
        Some("invalid_request")
    );

    let form_with_request = BackchannelAuthenticationForm {
        request: Some("request-object.jwt".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    validate_ciba_request_object_presence_with_config(&settings, &client, &form_with_request)
        .expect("present request object should satisfy the presence policy");
}

#[test]
fn fapi_ciba_id1_requires_a_signed_backchannel_authentication_request() {
    let settings = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);

    let response = validate_ciba_request_object_presence_with_config(
        &settings,
        &client,
        &BackchannelAuthenticationForm::default(),
    )
    .expect_err("FAPI-CIBA ID1 requires a signed request object");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn fapi_ciba_id1_accepts_both_private_key_jwt_and_mtls_client_authentication() {
    let settings = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.security_policy = nazo_auth::ClientSecurityPolicy::fapi2();
    client.require_mtls_bound_tokens = true;

    validate_ciba_security_profile_client_with_config(&settings, &client, "private_key_jwt")
        .expect("FAPI-CIBA ID1 supports private_key_jwt");
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    validate_ciba_security_profile_client_with_config(&settings, &client, "tls_client_auth")
        .expect("FAPI-CIBA ID1 supports mTLS client authentication");

    let response =
        validate_ciba_security_profile_client_with_config(&settings, &client, "client_secret_post")
            .expect_err("FAPI-CIBA ID1 must reject shared-secret client authentication");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn ciba_ping_requires_a_registered_endpoint_and_high_entropy_notification_token() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.backchannel_token_delivery_mode = "ping".to_owned();
    client.backchannel_client_notification_endpoint =
        Some("https://client.example/ciba-notification".to_owned());

    let missing =
        validate_ciba_delivery_request(&client, &BackchannelAuthenticationForm::default())
            .expect_err("ping requests require client_notification_token");
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    let weak = BackchannelAuthenticationForm {
        client_notification_token: Some("too-short".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    assert!(validate_ciba_delivery_request(&client, &weak).is_err());

    let valid = BackchannelAuthenticationForm {
        client_notification_token: Some("notification-token-0123456789".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    validate_ciba_delivery_request(&client, &valid)
        .expect("registered ping clients may supply a bearer notification token");
}

#[test]
fn ciba_poll_rejects_ping_only_notification_credentials() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);
    let form = BackchannelAuthenticationForm {
        client_notification_token: Some("notification-token-0123456789".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };

    assert!(validate_ciba_delivery_request(&client, &form).is_err());
}

#[test]
fn ciba_profile_does_not_apply_authorization_code_only_controls() {
    let mut settings = config();
    settings.ciba_fapi_profile = true;
    settings.ciba_fapi2_hardening = false;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let form = BackchannelAuthenticationForm {
        request: Some("signed-request-object".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };

    validate_token_request_profile(&client, "private_key_jwt")
        .expect("CIBA-compatible client authentication should pass the server profile");
    validate_ciba_security_profile_client_with_config(&settings, &client, "private_key_jwt")
        .expect("official FAPI-CIBA compatibility policy should remain separate");
    validate_ciba_request_object_presence_with_config(&settings, &client, &form)
        .expect("CIBA must not require PAR, PKCE, or authorization response_type fields");
}

#[test]
fn fapi2_ciba_profile_requires_signed_backchannel_authentication_request() {
    let mut settings = config();
    settings.ciba_fapi_profile = true;
    settings.ciba_fapi2_hardening = true;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);

    let response = validate_ciba_request_object_presence_with_config(
        &settings,
        &client,
        &BackchannelAuthenticationForm::default(),
    )
    .expect_err("Fapi2Ciba must require a signed backchannel authentication request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).as_str()),
        Some("invalid_request")
    );
}

#[test]
fn fapi2_ciba_client_policy_rejects_public_weak_auth_and_bearer_tokens() {
    let mut settings = config();
    settings.ciba_fapi_profile = true;
    settings.ciba_fapi2_hardening = true;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);

    let response =
        validate_ciba_security_profile_client_with_config(&settings, &client, "private_key_jwt")
            .expect_err("Fapi2Ciba must reject bearer access tokens");
    assert_eq!(
        Some(oauth_error_code(response).as_str()),
        Some("invalid_request")
    );

    client.require_mtls_bound_tokens = true;
    validate_ciba_security_profile_client_with_config(&settings, &client, "private_key_jwt")
        .expect("Fapi2Ciba must allow private_key_jwt with sender-constrained tokens");

    client.require_mtls_bound_tokens = false;
    client.require_dpop_bound_tokens = true;
    validate_ciba_security_profile_client_with_config(&settings, &client, "private_key_jwt")
        .expect("Fapi2Ciba must allow DPoP sender-constrained tokens");

    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    let response = validate_ciba_security_profile_client_with_config(
        &settings,
        &client,
        "client_secret_basic",
    )
    .expect_err("Fapi2Ciba must reject shared-secret client authentication");
    assert_eq!(
        Some(oauth_error_code(response).as_str()),
        Some("invalid_client")
    );

    client.client_type = "public".to_owned();
    let response = validate_ciba_security_profile_client_with_config(&settings, &client, "none")
        .expect_err("Fapi2Ciba must reject public CIBA clients");
    assert_eq!(
        Some(oauth_error_code(response).as_str()),
        Some("unauthorized_client")
    );
}

#[test]
fn fapi2_ciba_private_key_jwt_requires_issuer_audience_only() {
    let mut settings = config();
    settings.ciba_fapi_profile = true;
    settings.ciba_fapi2_hardening = true;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    client.allow_client_assertion_endpoint_audience = true;

    let response =
        validate_ciba_security_profile_client_with_config(&settings, &client, "private_key_jwt")
            .expect_err("Fapi2Ciba must reject endpoint-audience client assertions");
    assert_eq!(
        Some(oauth_error_code(response).as_str()),
        Some("invalid_client")
    );

    settings.ciba_fapi_profile = true;
    settings.ciba_fapi2_hardening = false;
    validate_ciba_security_profile_client_with_config(&settings, &client, "private_key_jwt")
        .expect("FAPI-CIBA ID1 permits the registered token endpoint as assertion audience");
}

#[test]
fn ciba_selected_acr_uses_supported_requested_value() {
    assert_eq!(ciba_selected_acr(Some("1")).as_deref(), Some("1"));
    assert_eq!(ciba_selected_acr(Some("0 1")).as_deref(), Some("1"));
    assert_eq!(ciba_selected_acr(Some("0")).as_deref(), None);
    assert_eq!(ciba_selected_acr(None), None);
}

#[test]
fn ciba_signed_request_object_missing_audience_maps_to_invalid_request() {
    let state = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("ciba-kid", &key);
    let request_object = signed_ciba_request_object("ciba-kid", &key, json!({"aud": null}));
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };

    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect_err("missing CIBA request object audience must be invalid_request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).as_str()),
        Some("invalid_request")
    );
    assert!(form.scope.is_none());
}

#[test]
fn ciba_mtls_lookup_may_use_signed_request_object_issuer_as_hint() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let request_object = signed_ciba_request_object(
        "ciba-kid",
        &key,
        json!({
            "nbf": null,
            "sub": "client-1"
        }),
    );
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };

    apply_ciba_request_object_client_id_hint(&mut form, false, false);

    assert_eq!(form.client_id.as_deref(), Some("client-1"));
}

#[test]
fn ciba_lookup_hint_never_trusts_unsigned_request_object_or_mixed_auth() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let signed = signed_ciba_request_object("ciba-kid", &key, json!({"sub": "client-1"}));
    let mut unsigned = BackchannelAuthenticationForm {
        request: Some(unsigned_ciba_request_object("client-1")),
        ..BackchannelAuthenticationForm::default()
    };
    let mut basic = BackchannelAuthenticationForm {
        request: Some(signed),
        ..BackchannelAuthenticationForm::default()
    };

    apply_ciba_request_object_client_id_hint(&mut unsigned, false, false);
    apply_ciba_request_object_client_id_hint(&mut basic, true, false);

    assert!(unsigned.client_id.is_none());
    assert!(basic.client_id.is_none());
}

#[test]
fn ciba_signed_request_object_missing_required_claim_maps_to_invalid_request() {
    for claim in ["iss", "aud", "iat", "nbf", "exp", "jti"] {
        let state = config();
        let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
        let client = ciba_private_key_jwt_client("ciba-kid", &key);
        let request_object = signed_ciba_request_object(
            "ciba-kid",
            &key,
            Value::Object(serde_json::Map::from_iter([(
                claim.to_owned(),
                Value::Null,
            )])),
        );
        let mut form = BackchannelAuthenticationForm {
            request: Some(request_object),
            ..BackchannelAuthenticationForm::default()
        };

        let response =
            validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
                .expect_err("missing CIBA request object claim must be invalid");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            Some(oauth_error_code(response).as_str()),
            Some("invalid_request"),
            "unexpected OAuth error for missing {claim}"
        );
        assert!(
            form.scope.is_none(),
            "missing {claim} must not merge claims"
        );
    }
}

#[test]
fn ciba_rejects_rs256_request_object_signing_algorithm() {
    let state = config();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let client = ciba_private_key_jwt_client_with_alg("ciba-kid", &key);
    let request_object = signed_ciba_request_object_with_alg(
        "ciba-kid",
        jsonwebtoken::Algorithm::RS256,
        &key,
        json!({}),
    );
    let mut form = BackchannelAuthenticationForm {
        request: Some(request_object),
        ..BackchannelAuthenticationForm::default()
    };

    let response =
        validate_and_apply_ciba_request_object_claims_with_config(&state, &client, &mut form)
            .expect_err("FAPI-CIBA request objects must reject RS256");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).as_str()),
        Some("invalid_request")
    );
}

#[test]
fn ciba_rejects_rs256_client_assertion_algorithm() {
    assert!(!ciba_jwt_signing_algorithm_supported(
        jsonwebtoken::Algorithm::RS256
    ));
    assert!(ciba_jwt_signing_algorithm_supported(
        jsonwebtoken::Algorithm::PS256
    ));
}

#[test]
fn ciba_policy_covers_algorithm_names_and_delivery_rejections() {
    assert_eq!(
        ciba_algorithm_name(jsonwebtoken::Algorithm::EdDSA),
        Some("EdDSA")
    );
    assert_eq!(
        ciba_algorithm_name(jsonwebtoken::Algorithm::ES256),
        Some("ES256")
    );
    assert_eq!(ciba_algorithm_name(jsonwebtoken::Algorithm::RS256), None);

    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut ping_client = ciba_private_key_jwt_client("policy-ping-kid", &key);
    ping_client.backchannel_token_delivery_mode = "ping".to_owned();
    ping_client.backchannel_client_notification_endpoint = None;
    let valid_notification = BackchannelAuthenticationForm {
        client_notification_token: Some("notification-token-0123456789".to_owned()),
        ..BackchannelAuthenticationForm::default()
    };
    let missing_endpoint = validate_ciba_delivery_request(&ping_client, &valid_notification)
        .expect_err("ping mode must require a registered notification endpoint");
    assert_eq!(missing_endpoint.status(), StatusCode::BAD_REQUEST);

    let mut unsupported_client = ping_client;
    unsupported_client.backchannel_token_delivery_mode = "push".to_owned();
    let unsupported = validate_ciba_delivery_request(&unsupported_client, &valid_notification)
        .expect_err("unsupported CIBA delivery modes must fail closed");
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);

    let mut poll_client = ciba_private_key_jwt_client("policy-poll-kid", &key);
    poll_client.backchannel_token_delivery_mode = "poll".to_owned();
    let poll_with_notification = validate_ciba_delivery_request(&poll_client, &valid_notification)
        .expect_err("poll mode must reject notification credentials");
    assert_eq!(poll_with_notification.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn ciba_token_profile_covers_fapi2_client_and_sender_constraints() {
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("profile-kid", &key);

    for (dpop, mtls) in [(false, false), (true, false), (false, true), (true, true)] {
        client.require_dpop_bound_tokens = dpop;
        client.require_mtls_bound_tokens = mtls;
        validate_ciba_token_request_profile(&client, "private_key_jwt")
            .expect("baseline CIBA profile should preserve each sender-constraint mapping");
    }

    client.security_policy = nazo_auth::ClientSecurityPolicy::fapi2();

    client.client_type = "public".to_owned();
    let public_client = validate_ciba_token_request_profile(&client, "private_key_jwt")
        .expect_err("FAPI2 CIBA must reject public clients");
    assert_eq!(oauth_error_code(public_client), "unauthorized_client");

    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = false;
    let bearer = validate_ciba_token_request_profile(&client, "private_key_jwt")
        .expect_err("FAPI2 CIBA must reject bearer tokens");
    assert_eq!(oauth_error_code(bearer), "invalid_request");

    client.require_mtls_bound_tokens = true;
    let bad_auth_method = validate_ciba_token_request_profile(&client, "client_secret_basic")
        .expect_err("FAPI2 CIBA must reject shared-secret authentication");
    assert_eq!(oauth_error_code(bad_auth_method), "invalid_client");
    validate_ciba_token_request_profile(&client, "private_key_jwt")
        .expect("FAPI2 CIBA should accept constrained private_key_jwt clients");
}
