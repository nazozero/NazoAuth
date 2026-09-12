use super::{
    authenticate_device_authorization_client, device_authorization_request_payload,
    normalize_user_code,
};
use crate::contracts::{
    device::DeviceAuthorizationForm,
    dynamic_client_registration::{RemoteJwksFuture, RemoteJwksResolverPort},
    oauth_error::OAuthEndpointError,
};
use crate::domain::rows::ClientRow;
use crate::ports::audit::{AuditFuture, SecurityAudit};
use crate::test_support::token_ports;
use crate::token::{
    DEVICE_CODE_GRANT_TYPE, client_auth::ClientAuthRequestFacts, device_config::DeviceConfig,
};
use chrono::{Duration, Utc};
use http::StatusCode;
use nazo_auth::{
    DeviceAuthorizationPayload, DeviceAuthorizationRequestError, DeviceAuthorizationState,
    DevicePollTransition, PresentedClientCredentials as ClientCredentials, evaluate_device_poll,
};
use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use serde_json::json;
use uuid::Uuid;

fn device_config() -> DeviceConfig {
    DeviceConfig {
        issuer: "http://127.0.0.1:8000".into(),
        mtls_endpoint_base_url: "http://127.0.0.1:8000".into(),
        frontend_base_url: "http://127.0.0.1:8000/ui".into(),
        client_secret_pepper: "test-pepper".into(),
        default_audience: "resource://default".into(),
        ttl_seconds: 600,
        poll_interval_seconds: 5,
        pairwise_subject_secret: None,
    }
}
struct Dependencies;
impl RemoteJwksResolverPort for Dependencies {
    fn resolve<'a>(&'a self, _: &'a str, _: Option<&'a str>) -> RemoteJwksFuture<'a> {
        panic!("public device clients must not resolve remote keys")
    }
}
impl SecurityAudit for Dependencies {
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

fn device_client() -> ClientRow {
    let mut client = ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        require_mtls_bound_tokens: false,
        is_active: true,
        registration: nazo_auth::ValidatedClientRegistration {
            client_id: "device-client".to_owned(),
            client_name: "Device Client".to_owned(),
            client_type: "public".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            scopes: vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "offline_access".to_owned(),
            ],
            allowed_audiences: vec![
                "resource://default".to_owned(),
                "https://api.example.com".to_owned(),
            ],
            grant_types: vec![DEVICE_CODE_GRANT_TYPE.to_owned()],
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
    };
    client.security_policy.allow_cross_device_flows = true;
    client
}

#[test]
fn device_client_authentication_accepts_registered_public_none_and_rejects_secret() {
    futures_executor::block_on(async {
        let (_, service) = token_ports::services(Ok(None), Ok(None));
        let config = device_config();
        let resolver = Dependencies;
        let mut client = device_client();
        let credentials = ClientCredentials {
            client_id: Some(client.client_id.clone()),
            method: "none".into(),
            ..Default::default()
        };
        assert!(
            authenticate_device_authorization_client(
                &service,
                &config,
                &ClientAuthRequestFacts::new("/", None),
                &mut client,
                &credentials,
                &resolver,
                &Dependencies,
            )
            .await
            .is_ok()
        );
        let credentials = ClientCredentials {
            client_secret: Some(Uuid::now_v7().to_string()),
            method: "client_secret_post".into(),
            ..credentials
        };
        let response = authenticate_device_authorization_client(
            &service,
            &config,
            &ClientAuthRequestFacts::new("/", None),
            &mut client,
            &credentials,
            &resolver,
            &Dependencies,
        )
        .await
        .expect_err("public clients cannot present a secret");
        assert!(
            matches!(response, OAuthEndpointError::Json(fields) if fields.status == StatusCode::UNAUTHORIZED)
        );
    });
}

#[test]
fn device_authorization_request_rejects_disabled_or_unregistered_client_grant() {
    let form = DeviceAuthorizationForm {
        client_id: Some("device-client".to_owned()),
        scope: Some("openid".to_owned()),
        resources: Vec::new(),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    };
    let config = device_config();
    let client = device_client();

    assert!(matches!(
        device_authorization_request_payload(&config, &client, &form, false,),
        Err(DeviceAuthorizationRequestError::Disabled)
    ));

    let mut client = client;
    client.grant_types = vec!["authorization_code".to_owned()];
    assert!(matches!(
        device_authorization_request_payload(&config, &client, &form, true,),
        Err(DeviceAuthorizationRequestError::UnauthorizedClient)
    ));
}

#[test]
fn device_authorization_request_binds_scope_audience_ttl_and_poll_interval() {
    let config = device_config();
    let client = device_client();
    let form = DeviceAuthorizationForm {
        client_id: Some("device-client".to_owned()),
        scope: Some("openid profile".to_owned()),
        resources: vec!["https://api.example.com".to_owned()],
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    };

    let payload = device_authorization_request_payload(&config, &client, &form, true)
        .expect("device authorization request should be accepted");

    assert_eq!(payload.client_id, "device-client");
    assert_eq!(payload.scopes, vec!["openid", "profile"]);
    assert_eq!(payload.resource_indicators, vec!["https://api.example.com"]);
    assert_eq!(payload.interval_seconds, 5);
    assert_eq!(
        payload.expires_at,
        payload.issued_at + Duration::seconds(600)
    );
}

#[test]
fn device_code_polling_enforces_pending_slow_down_denied_and_expired_results() {
    let now = Utc::now();
    let payload = DeviceAuthorizationPayload {
        client_id: "device-client".to_owned(),
        client_name: "Device Client".to_owned(),
        scopes: vec!["openid".to_owned()],
        resource_indicators: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        interval_seconds: 5,
        issued_at: now,
        expires_at: now + Duration::seconds(600),
    };

    let pending = DeviceAuthorizationState::Pending {
        payload: payload.clone(),
        last_poll_at: None,
        slow_down_count: 0,
    };
    assert!(matches!(
        evaluate_device_poll(&pending, now),
        DevicePollTransition::AuthorizationPending(_)
    ));

    let too_soon = DeviceAuthorizationState::Pending {
        payload: payload.clone(),
        last_poll_at: Some(now - Duration::seconds(1)),
        slow_down_count: 0,
    };
    assert!(matches!(
        evaluate_device_poll(&too_soon, now),
        DevicePollTransition::SlowDown(_)
    ));

    let denied = DeviceAuthorizationState::Denied {
        payload: payload.clone(),
        denied_at: now,
    };
    assert!(matches!(
        evaluate_device_poll(&denied, now),
        DevicePollTransition::AccessDenied
    ));

    let expired = DeviceAuthorizationState::Pending {
        payload: DeviceAuthorizationPayload {
            expires_at: now - Duration::seconds(1),
            ..payload
        },
        last_poll_at: None,
        slow_down_count: 0,
    };
    assert!(matches!(
        evaluate_device_poll(&expired, now),
        DevicePollTransition::Expired
    ));
}

#[test]
fn device_user_code_normalization_is_case_insensitive_and_separator_safe() {
    assert_eq!(normalize_user_code(" ab-cd_12 "), "ABCD12");
    assert_eq!(normalize_user_code("\t\n"), "");
}

#[path = "device_application.rs"]
mod application;
