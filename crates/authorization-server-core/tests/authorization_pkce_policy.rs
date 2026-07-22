use std::collections::HashMap;

use nazo_auth::{
    AuthorizationCapabilityPolicy, AuthorizationClientPolicy, AuthorizationPolicyError,
    AuthorizationProfilePolicy, normalize_authorization_request,
};

fn request(include_nonce: bool, include_pkce: bool) -> HashMap<String, String> {
    let mut parameters = HashMap::from([
        ("response_type".to_owned(), "code".to_owned()),
        ("scope".to_owned(), "openid phone".to_owned()),
    ]);
    if include_nonce {
        parameters.insert("nonce".to_owned(), "per-transaction-nonce".to_owned());
    }
    if include_pkce {
        parameters.insert("code_challenge".to_owned(), "A".repeat(43));
        parameters.insert("code_challenge_method".to_owned(), "S256".to_owned());
    }
    parameters
}

fn normalize(
    parameters: &HashMap<String, String>,
    client_type: &str,
) -> Result<nazo_auth::NormalizedAuthorizationRequest, AuthorizationPolicyError> {
    let scopes = ["openid".to_owned(), "phone".to_owned()];
    let audiences = [];
    normalize_authorization_request(
        parameters,
        AuthorizationClientPolicy {
            client_type,
            allowed_scopes: &scopes,
            allowed_audiences: &audiences,
            require_dpop_bound_tokens: false,
            require_mtls_bound_tokens: false,
        },
        AuthorizationCapabilityPolicy {
            authorization_details: true,
            jarm: true,
            native_sso: true,
            form_post: true,
        },
        AuthorizationProfilePolicy {
            signed_authorization_response_required: false,
        },
        false,
    )
}

#[test]
fn confidential_oidc_client_cannot_replace_project_pkce_policy_with_nonce() {
    assert_eq!(
        normalize(&request(true, false), "confidential"),
        Err(AuthorizationPolicyError::InvalidRequest)
    );
}

#[test]
fn public_client_cannot_replace_pkce_with_oidc_nonce() {
    assert_eq!(
        normalize(&request(true, false), "public"),
        Err(AuthorizationPolicyError::InvalidRequest)
    );
}

#[test]
fn confidential_oidc_code_flow_rejects_missing_pkce_and_nonce() {
    assert_eq!(
        normalize(&request(false, false), "confidential"),
        Err(AuthorizationPolicyError::InvalidRequest)
    );
}

#[test]
fn confidential_oidc_client_accepts_s256_pkce() {
    assert!(normalize(&request(true, true), "confidential").is_ok());
}
