use nazo_auth::{
    DpopError, DpopNoncePolicy, DpopProofRequest, DpopStateStorePort,
    validate_authorization_server_dpop,
};
use serde_json::json;

use crate::{contracts::request_facts::DpopRequestFacts, ports::audit::SecurityAudit};

#[allow(clippy::too_many_arguments)]
pub async fn validate_dpop_proof<S>(
    store: &S,
    audit: &dyn SecurityAudit,
    issuer: &str,
    mtls_endpoint_base_url: &str,
    nonce_policy: DpopNoncePolicy,
    request: DpopRequestFacts<'_>,
    token_for_ath: Option<&str>,
    expected_jkt: Option<&str>,
) -> Result<Option<String>, DpopError>
where
    S: DpopStateStorePort + ?Sized,
{
    let proof = request.proof?;
    let target_uris = dpop_target_uris(issuer, mtls_endpoint_base_url, request.path);
    let target_uri_refs = [target_uris[0].as_str(), target_uris[1].as_str()];
    let result = validate_authorization_server_dpop(
        store,
        DpopProofRequest {
            proof,
            method: request.method.as_str(),
            target_uris: &target_uri_refs,
            access_token: token_for_ath,
            expected_jkt,
        },
        nonce_policy,
    )
    .await;
    if let Err(DpopError::ReplayDetected(event)) = &result {
        audit.record(
            "dpop_replay_detected",
            [
                ("jti_hash".to_owned(), json!(event.jti_hash)),
                ("kid".to_owned(), json!(event.key_id)),
            ]
            .into_iter()
            .collect(),
        );
    }
    result
}

/// Uses configured endpoint origins and the original path, never forwarding headers.
pub fn dpop_target_uris(issuer: &str, mtls_endpoint_base_url: &str, path: &str) -> [String; 2] {
    [
        format!("{}{path}", issuer.trim_end_matches('/')),
        format!("{}{path}", mtls_endpoint_base_url.trim_end_matches('/')),
    ]
}
