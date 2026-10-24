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
    let target_uri = proof
        .map(|_| {
            dpop_target_uri(
                issuer,
                mtls_endpoint_base_url,
                request.authority,
                request.path,
            )
        })
        .transpose()?;
    let target_uri_refs = [target_uri.as_deref().unwrap_or("")];
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
        // Required evidence: the replay detection must be durable before the
        // rejection is returned; an audit outage fails closed instead of
        // silently dropping the fact.
        if let Err(error) = audit
            .record_required(
                "dpop_replay_detected",
                [
                    ("jti_hash".to_owned(), json!(event.jti_hash)),
                    ("kid".to_owned(), json!(event.key_id)),
                ]
                .into_iter()
                .collect(),
            )
            .await
        {
            tracing::error!(%error, "DPoP replay audit failed");
            return Err(DpopError::StateStoreUnavailable);
        }
    }
    result
}

/// Select one configured origin using the request's original HTTP authority.
pub fn dpop_target_uri(
    issuer: &str,
    mtls_endpoint_base_url: &str,
    authority: Option<&str>,
    path: &str,
) -> Result<String, DpopError> {
    let authority = authority
        .filter(|value| !value.contains('@'))
        .and_then(|value| value.parse::<http::uri::Authority>().ok())
        .ok_or(DpopError::InvalidProof)?;
    let mut selected = None;
    for base in [issuer, mtls_endpoint_base_url] {
        let origin = url::Url::parse(base).map_err(|_| DpopError::InvalidProof)?;
        if !matches!(origin.scheme(), "http" | "https") {
            return Err(DpopError::InvalidProof);
        }
        let request_origin = url::Url::parse(&format!("{}://{authority}", origin.scheme()))
            .map_err(|_| DpopError::InvalidProof)?;
        if origin.origin() == request_origin.origin() {
            let candidate = format!("{}{path}", base.trim_end_matches('/'));
            if selected
                .as_ref()
                .is_some_and(|current| current != &candidate)
            {
                return Err(DpopError::InvalidProof);
            }
            selected = Some(candidate);
        }
    }
    selected.ok_or(DpopError::InvalidProof)
}
