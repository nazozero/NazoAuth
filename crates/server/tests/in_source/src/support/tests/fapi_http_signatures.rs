use serde_json::{Value, json};
use uuid::Uuid;

use super::*;
use crate::domain::ClientRow;
use crate::support::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, client_signing_fixture,
};

fn client(jwks: Value) -> ClientRow {
    crate::client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!([]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: false,
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
        jwks: Some(jwks),
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

fn public_jwk() -> (String, Value) {
    let kid = "client-signing-key".to_owned();
    let material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let jwk = material.public_jwk(&kid);
    (kid, jwk)
}

#[test]
fn client_verification_requires_exact_tenant_and_client_binding() {
    let (kid, jwk) = public_jwk();
    let client = client(json!({"keys": [jwk]}));

    for (tenant_id, client_id) in [
        (Uuid::now_v7(), "client-1"),
        (DEFAULT_TENANT_ID, "other-client"),
    ] {
        assert!(
            verify_client_http_message(
                &client,
                tenant_id,
                client_id,
                &kid,
                "ed25519",
                b"input",
                b"signature",
            )
            .is_err()
        );
    }
}

#[test]
fn client_verification_delegates_unique_kid_and_algorithm_policy() {
    let (kid, jwk) = public_jwk();
    let client = client(json!({"keys": [jwk.clone(), jwk]}));

    for (selected_kid, algorithm) in [
        (kid.as_str(), "ed25519"),
        ("missing", "ed25519"),
        (kid.as_str(), "unknown"),
    ] {
        assert!(
            verify_client_http_message(
                &client,
                DEFAULT_TENANT_ID,
                "client-1",
                selected_kid,
                algorithm,
                b"input",
                b"signature",
            )
            .is_err()
        );
    }
}
