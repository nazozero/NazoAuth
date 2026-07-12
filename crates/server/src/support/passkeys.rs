//! WebAuthn/passkey shared helpers.

use passkey_auth::{CredentialId, PasskeyCredential, Webauthn};

use super::prelude::*;
use super::{oauth_error, valkey_getdel, valkey_set_ex};

pub(crate) const PASSKEY_CEREMONY_TTL_SECONDS: u64 = 300;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredPasskeyRegistration {
    pub(crate) user_id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) label: String,
    pub(crate) state: passkey_auth::RegistrationState,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredPasskeyAuthentication {
    pub(crate) user_id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) state: passkey_auth::AuthenticationState,
}

pub(crate) fn passkey_webauthn(settings: &Settings) -> Webauthn {
    Webauthn::new(
        &settings.passkey.rp_id,
        &settings.passkey.rp_name,
        &settings.passkey.origin,
    )
    .require_user_verification(settings.passkey.require_user_verification)
    .require_user_handle(settings.passkey.require_user_handle)
    .strict_base64(settings.passkey.strict_base64)
}

pub(crate) fn passkey_user_handle(user: &PublicAccount) -> anyhow::Result<Vec<u8>> {
    let tenant_id = nazo_identity::TenantId::new(user.tenant_id())
        .map_err(|error| anyhow::anyhow!("invalid persisted passkey tenant ID: {error}"))?;
    let user_id = nazo_identity::UserId::new(user.id())
        .map_err(|error| anyhow::anyhow!("invalid persisted passkey user ID: {error}"))?;
    Ok(nazo_identity::passkey::passkey_user_handle(
        tenant_id, user_id,
    ))
}

pub(crate) fn normalize_passkey_label(value: Option<String>) -> Result<String, HttpResponse> {
    nazo_identity::passkey::normalize_passkey_label(value.as_deref()).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey label is too long.",
        )
    })
}

pub(crate) fn passkey_credential_from_row(
    row: &nazo_identity::ports::PasskeyCredential,
) -> anyhow::Result<PasskeyCredential> {
    Ok(serde_json::from_value::<PasskeyCredential>(
        row.credential.clone(),
    )?)
}

pub(crate) fn passkey_credential_id(credential: &PasskeyCredential) -> String {
    credential.id.to_b64url()
}

pub(crate) fn passkey_credential_ids(
    rows: &[nazo_identity::ports::PasskeyCredential],
) -> anyhow::Result<Vec<CredentialId>> {
    rows.iter()
        .map(|row| passkey_credential_from_row(row).map(|credential| credential.id))
        .collect()
}

pub(crate) fn passkey_public_json(row: &nazo_identity::ports::PasskeyCredential) -> Value {
    json!({
        "id": row.id,
        "label": row.label,
        "credential_id": row.credential_id,
        "sign_count": row.sign_count,
        "last_used_at": row.last_used_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at
    })
}

pub(crate) fn registration_key(ceremony_id: &str) -> String {
    format!("oauth:passkey:registration:{ceremony_id}")
}

pub(crate) fn authentication_key(ceremony_id: &str) -> String {
    format!("oauth:passkey:authentication:{ceremony_id}")
}

pub(crate) async fn store_passkey_ceremony<T>(
    state: &AppState,
    key: String,
    value: &T,
) -> anyhow::Result<()>
where
    T: Serialize,
{
    let body = serde_json::to_string(value)?;
    valkey_set_ex(&state.valkey, key, body, PASSKEY_CEREMONY_TTL_SECONDS).await?;
    Ok(())
}

pub(crate) async fn take_passkey_ceremony<T>(
    state: &AppState,
    key: String,
) -> Result<Option<T>, HttpResponse>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = valkey_getdel(&state.valkey, key).await.map_err(|error| {
        tracing::warn!(%error, "failed to take passkey ceremony");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "passkey state unavailable.",
        )
    })?;
    raw.map(|body| {
        serde_json::from_str::<T>(&body).map_err(|error| {
            tracing::warn!(%error, "stored passkey ceremony is malformed");
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "passkey ceremony expired.",
            )
        })
    })
    .transpose()
}

pub(crate) fn normalize_ceremony_id(value: &str) -> Result<String, HttpResponse> {
    nazo_identity::passkey::normalize_ceremony_id(value).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid ceremony id.",
        )
    })
}

pub(crate) fn credential_id_from_response(id: &str) -> Result<CredentialId, HttpResponse> {
    nazo_identity::passkey::credential_id_from_response(id)
        .map(CredentialId)
        .map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid passkey credential id.",
            )
        })
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/passkeys.rs"]
mod tests;
