use crate::{crypto::blake3_hex, domain::rows::ClientRow};
use chrono::Utc;
use nazo_auth::{
    ClientAssertionVerificationInput, ValidatedClientAssertion, verify_private_key_jwt,
};

#[derive(Debug)]
pub enum ClientAssertionError {
    Invalid,
    ReplayDetected,
    StoreUnavailable,
}

pub fn verify_private_key_jwt_claims_for_issuer(
    issuer: &str,
    endpoint_path: &str,
    endpoint_audience_aliases: &[&str],
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    verify_private_key_jwt_claims_with_issuer(
        issuer,
        endpoint_path,
        endpoint_audience_aliases,
        client,
        assertion,
    )
}

fn verify_private_key_jwt_claims_with_issuer(
    issuer: &str,
    endpoint_path: &str,
    endpoint_audience_aliases: &[&str],
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedClientAssertion, ClientAssertionError> {
    verify_private_key_jwt(ClientAssertionVerificationInput {
        issuer,
        endpoint_path,
        endpoint_audience_aliases,
        client,
        assertion,
        now: Utc::now().timestamp(),
        expected_signing_algorithm: client.token_endpoint_auth_signing_alg.as_deref(),
    })
    .map_err(|error| {
        log_client_assertion_rejection(endpoint_path, client, error.audit_reason());
        ClientAssertionError::Invalid
    })
}

fn log_client_assertion_rejection(endpoint_path: &str, client: &ClientRow, reason: &'static str) {
    tracing::warn!(
        target: "client_assertion",
        "client_assertion_rejected reason={} path={} client_id_hash={}",
        reason,
        endpoint_path,
        blake3_hex(&client.client_id)
    );
}

pub async fn consume_private_key_jwt_with_authorization_service(
    service: &crate::services::ServerAuthorizationService,
    client: &nazo_auth::OAuthClient,
    assertion: &nazo_auth::ValidatedClientAssertion,
    audit: &dyn crate::ports::audit::SecurityAudit,
) -> Result<(), ClientAssertionError> {
    let now = chrono::Utc::now().timestamp();
    let ttl_seconds = assertion.replay_ttl_seconds(now);
    match service
        .consume_private_key_jwt(&client.client_id, assertion.jti(), ttl_seconds)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => {
            audit.record(
                "client_assertion_replay_detected",
                crate::ports::audit::audit_fields(&[
                    ("client_id", serde_json::json!(client.client_id)),
                    (
                        "jti_hash",
                        serde_json::json!(crate::crypto::blake3_hex(assertion.jti())),
                    ),
                    ("kid", serde_json::json!(assertion.kid())),
                ]),
            );
            Err(ClientAssertionError::ReplayDetected)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to store private_key_jwt jti");
            Err(ClientAssertionError::StoreUnavailable)
        }
    }
}
