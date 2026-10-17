use chrono::{DateTime, Utc};
use nazo_openid4vci::{CredentialResponseEncoding, CredentialSelection, StoredCredentialResponse};
use uuid::Uuid;

pub fn response(
    token_id: Uuid,
    selection: Option<CredentialSelection>,
    expires_at: DateTime<Utc>,
    status: u16,
) -> StoredCredentialResponse {
    let issuance_id = Uuid::now_v7();
    StoredCredentialResponse {
        selection,
        issuance_id,
        token_id,
        request_digest: blake3::hash(issuance_id.as_bytes()).to_hex().to_string(),
        body: b"{}".as_slice().into(),
        encoding: CredentialResponseEncoding::Json,
        status,
        dpop_nonce: None,
        expires_at,
    }
}

/// Seed a claim fixture through the same response-bearing commit used by issuance.
pub async fn persist_deferred(
    store: &impl nazo_openid4vci::CredentialStorePort,
    credential: &nazo_openid4vci::DeferredCredential,
) -> Result<(), nazo_openid4vci::CredentialStoreError> {
    store
        .store_deferred_with_response(
            credential,
            &response(
                credential.access.token_id,
                credential.selection.clone(),
                credential.expires_at,
                202,
            ),
            Utc::now(),
        )
        .await
}
