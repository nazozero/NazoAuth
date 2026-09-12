use super::{
    client_auth::{
        attestation_client_id_matches_form_hint, missing_client_authorization_code_holder_error,
        validate_token_client_enabled,
    },
    errors::{
        authorization_code_holder_missing_client_error,
        client_credentials_holder_missing_client_error,
    },
};
use crate::contracts::{
    oauth_error::{OAuthEndpointError, OAuthErrorFields},
    token_forms::TokenForm,
};
use crate::domain::rows::ClientRow;
use crate::token::ciba::CIBA_GRANT_TYPE;
use chrono::{Duration, Utc};
use http::StatusCode;
use nazo_auth::*;
use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use serde_json::json;
use uuid::Uuid;

fn token_error_fields(error: &OAuthEndpointError) -> &OAuthErrorFields {
    match error {
        OAuthEndpointError::Token { fields, .. } => fields,
        _ => panic!("expected token error"),
    }
}

fn client() -> ClientRow {
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
fn code_payload(dpop_jkt: Option<&str>) -> CodePayload {
    CodePayload {
        code_id: "code-id".to_owned(),
        user_id: Uuid::nil(),
        client_id: "client-1".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
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
#[test]
fn missing_client_dpop_authorization_code_holder_uses_invalid_grant() {
    let response = authorization_code_holder_missing_client_error(true, false)
        .expect("dpop holder binding should return an error");

    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "invalid_grant");
}

#[test]
fn missing_client_mtls_authorization_code_holder_uses_invalid_request() {
    for (dpop_bound, mtls_bound) in [(false, true), (true, true)] {
        let response = authorization_code_holder_missing_client_error(dpop_bound, mtls_bound)
            .expect("mtls holder binding should return an error");

        assert_eq!(
            token_error_fields(&response).status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(token_error_fields(&response).error, "invalid_request");
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
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: Some("accounts".to_owned()),
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
        has_audience_param: false,
    };
    let response = client_credentials_holder_missing_client_error(&form, false)
        .expect("missing DPoP proof should be reported before generic client auth");

    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "invalid_request");
}

#[test]
fn missing_client_holder_check_ignores_non_client_credentials_grants() {
    let form = TokenForm {
        grant_type: "refresh_token".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: Some("refresh-token".to_owned()),
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
        has_audience_param: false,
    };

    assert!(client_credentials_holder_missing_client_error(&form, false).is_none());
}

#[test]
fn missing_client_client_credentials_with_dpop_stays_client_auth_failure() {
    let form = TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: Some("accounts".to_owned()),
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
        has_audience_param: false,
    };

    assert!(client_credentials_holder_missing_client_error(&form, true).is_none());
}

#[test]
fn missing_client_mtls_client_credentials_uses_invalid_request() {
    let form = TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: Some("accounts".to_owned()),
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
        has_audience_param: false,
    };

    let response = client_credentials_holder_missing_client_error(&form, false)
        .expect("missing holder-of-key proof should be reported before generic client auth");

    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "invalid_request");
}

#[test]
fn disabled_client_is_rejected_before_grant_dispatch() {
    let mut client = client();
    client.is_active = false;

    let response = validate_token_client_enabled(&client, "authorization_code")
        .expect_err("disabled clients must not use token grants");

    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "unauthorized_client");
}

#[test]
fn active_client_with_registered_grant_is_allowed_to_dispatch() {
    let client = client();

    assert!(validate_token_client_enabled(&client, "authorization_code").is_ok());
}

#[test]
fn ciba_dispatch_requires_the_client_registered_grant() {
    let client = client();

    let response = validate_token_client_enabled(&client, CIBA_GRANT_TYPE)
        .expect_err("client without the CIBA grant must fail before CIBA execution");

    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "unauthorized_client");
}

#[test]
fn missing_grant_registration_is_rejected_before_grant_dispatch() {
    let client = client();

    let response = validate_token_client_enabled(&client, "client_credentials")
        .expect_err("client must be registered for the requested grant");

    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "unauthorized_client");
}

#[test]
fn attested_client_id_must_match_optional_token_request_client_id_hint() {
    assert!(attestation_client_id_matches_form_hint(
        None,
        "attested-client"
    ));
    assert!(attestation_client_id_matches_form_hint(
        Some("attested-client"),
        "attested-client"
    ));
    assert!(!attestation_client_id_matches_form_hint(
        Some("other-client"),
        "attested-client"
    ));
}

#[test]
fn grant_dispatch_rejects_unregistered_grant_without_panicking() {
    let mut client = client();
    client.grant_types = vec!["authorization_code".to_owned()];

    let response = validate_token_client_enabled(&client, "refresh_token")
        .expect_err("unregistered grant_types must fail closed");

    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "unauthorized_client");
}

use crate::test_support::token_ports;
use token_ports::services;

#[test]
fn missing_client_authorization_code_holder_check_fails_closed_when_valkey_is_unavailable() {
    futures_executor::block_on(async {
        let (token_service, authorization_service) =
            services(Err(TokenPortError::Unavailable), Ok(None));
        let form = TokenForm {
            grant_type: "authorization_code".to_owned(),
            code: Some("code-unavailable".to_owned()),
            device_code: None,
            auth_req_id: None,
            redirect_uri: None,
            code_verifier: Some("verifier".to_owned()),
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
            has_audience_param: false,
        };
        let response = missing_client_authorization_code_holder_error(
            &token_service,
            &authorization_service,
            &form,
        )
        .await
        .expect("authorization code state lookup failures must not be ignored");
        assert_eq!(
            token_error_fields(&response).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(token_error_fields(&response).error, "server_error");
    });
}

#[test]
fn missing_client_authorization_code_holder_check_fails_closed_when_client_lookup_errors() {
    futures_executor::block_on(async {
        let (token_service, authorization_service) = services(
            Ok(Some(AuthorizationCodeState::Pending {
                payload: code_payload(None),
            })),
            Err(AuthorizationPortError::Unavailable),
        );
        let form = TokenForm {
            grant_type: "authorization_code".to_owned(),
            code: Some("code-1".to_owned()),
            device_code: None,
            auth_req_id: None,
            redirect_uri: None,
            code_verifier: Some("verifier".to_owned()),
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
            has_audience_param: false,
        };
        let response = missing_client_authorization_code_holder_error(
            &token_service,
            &authorization_service,
            &form,
        )
        .await
        .expect("client lookup failures must not degrade to invalid_client");
        assert_eq!(
            token_error_fields(&response).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(token_error_fields(&response).error, "server_error");
    });
}

#[test]
fn missing_client_authorization_code_holder_error_returns_none_when_code_missing() {
    futures_executor::block_on(async {
        let (token_service, authorization_service) = services(Ok(None), Ok(None));
        let form = TokenForm {
            grant_type: "authorization_code".to_owned(),
            code: Some("missing-code".to_owned()),
            device_code: None,
            auth_req_id: None,
            redirect_uri: None,
            code_verifier: Some("verifier".to_owned()),
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
            has_audience_param: false,
        };
        assert!(
            missing_client_authorization_code_holder_error(
                &token_service,
                &authorization_service,
                &form
            )
            .await
            .is_none()
        );
    });
}

#[test]
fn missing_client_authorization_code_holder_error_returns_none_when_client_is_not_sender_bound() {
    futures_executor::block_on(async {
        let (token_service, authorization_service) = services(
            Ok(Some(AuthorizationCodeState::Pending {
                payload: code_payload(None),
            })),
            Ok(Some({
                let mut client = client();
                client.require_dpop_bound_tokens = false;
                client
            })),
        );
        let form = TokenForm {
            grant_type: "authorization_code".to_owned(),
            code: Some("code-1".to_owned()),
            device_code: None,
            auth_req_id: None,
            redirect_uri: None,
            code_verifier: Some("verifier".to_owned()),
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
            has_audience_param: false,
        };
        assert!(
            missing_client_authorization_code_holder_error(
                &token_service,
                &authorization_service,
                &form
            )
            .await
            .is_none()
        );
    });
}
