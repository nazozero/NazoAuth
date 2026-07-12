//! MFA helper functions.
//! TOTP follows RFC 6238 with SHA-1, 30-second steps, six digits, and one-step clock skew.

use chrono::Duration;

use super::prelude::*;
use super::{blake3_hex, hash_password, random_urlsafe_token};

pub(crate) const MFA_REMEMBERED_COOKIE_NAME: &str = "nazo_oauth_mfa_remembered";
pub(crate) const MFA_REMEMBERED_TTL_SECONDS: u64 = 2_592_000;
pub(crate) use nazo_identity::mfa::{
    MFA_BACKUP_CODE_COUNT, MFA_TOTP_DIGITS, MFA_TOTP_PERIOD_SECONDS, MfaVerificationMethod,
};

pub(crate) async fn remembered_mfa_device_valid(
    state: &AppState,
    req: &HttpRequest,
    user: &PublicAccount,
) -> anyhow::Result<bool> {
    let Some(token) = cookie_value(req, MFA_REMEMBERED_COOKIE_NAME) else {
        return Ok(false);
    };
    let token_hash = blake3_hex(token.trim());
    let user_agent_hash = request_user_agent_hash(req);
    nazo_postgres::MfaRepository::new(state.diesel_db.clone())
        .remembered_device_valid(
            user.tenant().tenant_id,
            user.user_id(),
            &token_hash,
            user_agent_hash.as_deref(),
            Utc::now(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to validate remembered MFA device: {error:?}"))
}

pub(crate) async fn remember_mfa_device(
    state: &AppState,
    req: &HttpRequest,
    user: &PublicAccount,
) -> anyhow::Result<String> {
    let token = random_urlsafe_token();
    let token_hash = blake3_hex(&token);
    let expires_at = Utc::now() + Duration::seconds(MFA_REMEMBERED_TTL_SECONDS as i64);
    nazo_postgres::MfaRepository::new(state.diesel_db.clone())
        .remember_device(
            user.tenant().tenant_id,
            user.user_id(),
            token_hash,
            request_user_agent_hash(req),
            expires_at,
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to remember MFA device: {error:?}"))?;
    Ok(token)
}

pub(crate) async fn verify_user_mfa_code(
    db: &DbPool,
    user: &PublicAccount,
    code: &str,
) -> anyhow::Result<Option<MfaVerificationMethod>> {
    let now = Utc::now();
    let tenant_id = nazo_identity::TenantId::new(user.tenant_id())?;
    let user_id = nazo_identity::UserId::new(user.id())?;
    let repository = nazo_postgres::MfaRepository::new(db.clone());
    let totp_credential = repository
        .totp_credential(tenant_id, user_id)
        .await
        .map_err(|error| anyhow::anyhow!("failed to load TOTP credential: {error:?}"))?;
    if let Some(credential) = totp_credential
        && let Some(step) = nazo_identity::mfa::verified_totp_step(
            &credential.secret_base32,
            code,
            now.timestamp(),
            credential.last_used_step,
        )
        && repository
            .compare_and_set_totp_step(tenant_id, user_id, step)
            .await
            .map_err(|error| anyhow::anyhow!("failed to consume TOTP step: {error:?}"))?
    {
        return Ok(Some(MfaVerificationMethod::Totp));
    }

    let Some(normalized) = nazo_identity::mfa::normalize_backup_code(code) else {
        return Ok(None);
    };
    repository
        .consume_backup_code(tenant_id, user_id, &normalized)
        .await
        .map(|consumed| consumed.then_some(MfaVerificationMethod::BackupCode))
        .map_err(|error| anyhow::anyhow!("failed to consume backup code: {error:?}"))
}

pub(crate) async fn replace_backup_codes(
    db: &DbPool,
    user: &PublicAccount,
) -> anyhow::Result<Vec<String>> {
    let (codes, hashes) = generate_backup_codes_and_hashes()?;
    let tenant_id = user.tenant().tenant_id;
    let user_id = user.user_id();
    nazo_postgres::MfaRepository::new(db.clone())
        .replace_backup_code_hashes(tenant_id, user_id, hashes)
        .await
        .map_err(|error| anyhow::anyhow!("failed to replace backup codes: {error:?}"))?;
    Ok(codes)
}

pub(crate) fn generate_backup_codes_and_hashes() -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let mut codes = Vec::with_capacity(MFA_BACKUP_CODE_COUNT);
    let mut hashes = Vec::with_capacity(MFA_BACKUP_CODE_COUNT);
    for _ in 0..MFA_BACKUP_CODE_COUNT {
        let code = nazo_identity::mfa::generate_backup_code();
        let normalized = nazo_identity::mfa::normalize_backup_code(&code)
            .expect("generated backup code is valid");
        let hash = hash_password(&normalized)
            .map_err(|error| anyhow::anyhow!("failed to hash backup code: {error}"))?;
        hashes.push(hash);
        codes.push(code);
    }
    Ok((codes, hashes))
}

pub(crate) async fn clear_user_mfa_state(db: &DbPool, user: &PublicAccount) -> anyhow::Result<()> {
    let tenant_id = user.tenant().tenant_id;
    let user_id = user.user_id();
    nazo_postgres::MfaRepository::new(db.clone())
        .clear_mfa_state(tenant_id, user_id)
        .await
        .map_err(|error| anyhow::anyhow!("failed to clear MFA state: {error:?}"))
}

fn request_user_agent_hash(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(blake3_hex)
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/mfa.rs"]
mod tests;
