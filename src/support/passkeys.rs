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

pub(crate) fn passkey_user_handle(user: &UserRow) -> Vec<u8> {
    let mut handle = Vec::with_capacity(32);
    handle.extend_from_slice(user.tenant_id.as_bytes());
    handle.extend_from_slice(user.id.as_bytes());
    handle
}

pub(crate) fn normalize_passkey_label(value: Option<String>) -> Result<String, HttpResponse> {
    let label = value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Passkey".to_owned());
    if label.len() > 120 {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey label is too long.",
        ));
    }
    Ok(label)
}

pub(crate) fn passkey_credential_from_row(
    row: &PasskeyCredentialRow,
) -> anyhow::Result<PasskeyCredential> {
    Ok(serde_json::from_value::<PasskeyCredential>(
        row.credential.clone(),
    )?)
}

pub(crate) fn passkey_credential_id(credential: &PasskeyCredential) -> String {
    credential.id.to_b64url()
}

pub(crate) fn passkey_credential_ids(
    rows: &[PasskeyCredentialRow],
) -> anyhow::Result<Vec<CredentialId>> {
    rows.iter()
        .map(|row| passkey_credential_from_row(row).map(|credential| credential.id))
        .collect()
}

pub(crate) fn passkey_public_json(row: &PasskeyCredentialRow) -> Value {
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
    let value = value.trim();
    if value.len() < 32
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid ceremony id.",
        ));
    }
    Ok(value.to_owned())
}

pub(crate) fn credential_id_from_response(id: &str) -> Result<CredentialId, HttpResponse> {
    CredentialId::from_b64url(id).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid passkey credential id.",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use passkey_auth::{CosePublicKey, CredentialId, PasskeyCredential};

    #[test]
    fn passkey_user_handle_binds_tenant_and_user() {
        let user = UserRow {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            realm_id: Uuid::now_v7(),
            organization_id: Uuid::now_v7(),
            username: "user@example.com".to_owned(),
            email: "user@example.com".to_owned(),
            display_name: None,
            avatar_url: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile_url: None,
            website_url: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            role: "user".to_owned(),
            admin_level: 0,
            address_formatted: None,
            address_street_address: None,
            address_locality: None,
            address_region: None,
            address_postal_code: None,
            address_country: None,
            phone_number: None,
            phone_number_verified: false,
            email_verified: true,
            mfa_enabled: false,
            password_hash: "hash".to_owned(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let handle = passkey_user_handle(&user);
        assert_eq!(handle.len(), 32);
        assert!(handle.starts_with(user.tenant_id.as_bytes()));
        assert!(handle.ends_with(user.id.as_bytes()));
    }

    #[test]
    fn passkey_credential_id_is_base64url() {
        let credential = PasskeyCredential {
            id: CredentialId(vec![1, 2, 3, 4]),
            public_key_cose: CosePublicKey(vec![5, 6, 7]),
            counter: 0,
            transports: vec!["internal".to_owned()],
            aaguid: [0; 16],
        };

        assert_eq!(passkey_credential_id(&credential), "AQIDBA");
    }

    #[test]
    fn ceremony_id_rejects_malformed_values() {
        assert!(normalize_ceremony_id("short").is_err());
        assert!(normalize_ceremony_id("x".repeat(300).as_str()).is_err());
        assert!(normalize_ceremony_id("abc/def/ghi/jkl/mno/pqr/stu/vwx/yz1234567890").is_err());
    }

    #[test]
    fn ceremony_id_accepts_urlsafe_tokens() {
        let value = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_";
        assert_eq!(normalize_ceremony_id(value).unwrap(), value);
    }
}
