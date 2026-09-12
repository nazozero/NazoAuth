#[path = "../../support/authorization_code.rs"]
mod code_fixture;
use code_fixture::{code_payload, form_for_code};

use super::{
    ClientRow, TokenForm, authorization_code_audiences_with_default,
    authorization_code_requires_pkce,
};
use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use uuid::Uuid;

fn pkce_policy_client() -> ClientRow {
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
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            scopes: vec!["openid".to_owned()],
            allowed_audiences: vec!["resource://default".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: "client_secret_basic".to_owned(),
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

#[test]
fn baseline_confidential_oidc_compatibility_does_not_weaken_hardened_clients() {
    let mut client = pkce_policy_client();
    let mut payload = code_payload(false);
    payload.code_challenge = None;
    payload.code_challenge_method = None;
    payload.nonce = Some("per-transaction-nonce".to_owned());

    assert!(!authorization_code_requires_pkce(&client, &payload));

    payload.nonce = None;
    assert!(!authorization_code_requires_pkce(&client, &payload));
    payload.nonce = Some("per-transaction-nonce".to_owned());

    client.client_type = "public".to_owned();
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = true;
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.require_mtls_bound_tokens = false;
    let mut holder_bound_payload = code_payload(false);
    holder_bound_payload.dpop_jkt = Some("thumbprint".to_owned());
    assert!(authorization_code_requires_pkce(
        &client,
        &holder_bound_payload
    ));

    holder_bound_payload.dpop_jkt = None;
    holder_bound_payload.mtls_x5t_s256 = Some("thumbprint".to_owned());
    assert!(authorization_code_requires_pkce(
        &client,
        &holder_bound_payload
    ));

    holder_bound_payload.mtls_x5t_s256 = None;
    holder_bound_payload.scopes = vec!["accounts".to_owned()];
    assert!(authorization_code_requires_pkce(
        &client,
        &holder_bound_payload
    ));
}

#[test]
fn authorization_code_audiences_inherit_authorized_resources_when_token_request_omits_resource() {
    let mut payload = code_payload(true);
    payload.resource_indicators = vec![
        "https://api.example/one".to_owned(),
        "https://api.example/two".to_owned(),
    ];
    let form = form_for_code("code-1");

    assert_eq!(
        authorization_code_audiences_with_default("resource://default", None, &payload, &form)
            .unwrap(),
        payload.resource_indicators
    );
}

#[test]
fn authorization_code_audiences_allow_token_request_to_narrow_authorized_resources() {
    let mut payload = code_payload(true);
    payload.resource_indicators = vec![
        "https://api.example/one".to_owned(),
        "https://api.example/two".to_owned(),
    ];
    let mut form = form_for_code("code-1");
    form.audiences = vec!["https://api.example/two".to_owned()];

    assert_eq!(
        authorization_code_audiences_with_default("resource://default", None, &payload, &form)
            .unwrap(),
        vec!["https://api.example/two".to_owned()]
    );
}

#[test]
fn authorization_code_audiences_reject_token_request_resource_outside_authorization() {
    let mut payload = code_payload(true);
    payload.resource_indicators = vec!["https://api.example/one".to_owned()];
    let mut form = form_for_code("code-1");
    form.audiences = vec!["https://api.example/two".to_owned()];

    assert!(
        authorization_code_audiences_with_default("resource://default", None, &payload, &form)
            .is_err()
    );
}

#[test]
fn authorization_code_audiences_use_credential_issuer_for_openid4vci_scope() {
    let mut payload = code_payload(true);
    payload.scopes = vec!["eu.europa.ec.eudi.pid.1".to_owned()];
    let form = form_for_code("code-1");

    assert_eq!(
        authorization_code_audiences_with_default(
            "resource://default",
            Some("https://issuer.example"),
            &payload,
            &form,
        )
        .unwrap(),
        vec!["https://issuer.example".to_owned()]
    );
}

#[test]
fn explicit_token_audience_overrides_openid4vci_default() {
    let mut payload = code_payload(true);
    payload.scopes = vec!["eu.europa.ec.eudi.pid.1".to_owned()];
    let mut form = form_for_code("code-1");
    form.audiences = vec!["https://issuer.example/openid4vci/credential".to_owned()];

    assert_eq!(
        authorization_code_audiences_with_default(
            "resource://default",
            Some("https://issuer.example"),
            &payload,
            &form,
        )
        .unwrap(),
        form.audiences
    );
}
