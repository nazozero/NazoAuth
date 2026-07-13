//! MFA helper functions.
//! TOTP follows RFC 6238 with SHA-1, 30-second steps, six digits, and one-step clock skew.

use crate::domain::AppState;
use actix_web::HttpRequest;
use actix_web::http::header;
use chrono::Duration;
use chrono::Utc;
use nazo_http_actix::cookie_value;
use nazo_identity::PublicAccount;
#[cfg(test)]
use nazo_postgres::DbPool;
use nazo_postgres::MfaRepository;

use super::{blake3_hex, hash_password, random_urlsafe_token};

pub(crate) const MFA_REMEMBERED_COOKIE_NAME: &str = "nazo_oauth_mfa_remembered";
pub(crate) const MFA_REMEMBERED_TTL_SECONDS: u64 = 2_592_000;
pub(crate) use nazo_identity::mfa::{
    MFA_BACKUP_CODE_COUNT, MFA_TOTP_DIGITS, MFA_TOTP_PERIOD_SECONDS, MfaVerificationMethod,
};

#[cfg(test)]
pub(crate) async fn remembered_mfa_device_valid(
    state: &AppState,
    req: &HttpRequest,
    user: &PublicAccount,
) -> anyhow::Result<bool> {
    remembered_mfa_device_valid_with_repository(
        &MfaRepository::new(state.diesel_db.clone()),
        req,
        user,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn remembered_mfa_device_valid_with_repository(
    repository: &MfaRepository,
    req: &HttpRequest,
    user: &PublicAccount,
) -> anyhow::Result<bool> {
    let Some(token) = cookie_value(req, MFA_REMEMBERED_COOKIE_NAME) else {
        return Ok(false);
    };
    let token_hash = blake3_hex(token.trim());
    let user_agent_hash = request_user_agent_hash(req);
    repository
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

#[cfg(test)]
pub(crate) async fn remember_mfa_device(
    state: &AppState,
    req: &HttpRequest,
    user: &PublicAccount,
) -> anyhow::Result<String> {
    remember_mfa_device_with_repository(&MfaRepository::new(state.diesel_db.clone()), req, user)
        .await
}

pub(crate) async fn remember_mfa_device_with_repository(
    repository: &MfaRepository,
    req: &HttpRequest,
    user: &PublicAccount,
) -> anyhow::Result<String> {
    let token = random_urlsafe_token();
    let token_hash = blake3_hex(&token);
    let expires_at = Utc::now() + Duration::seconds(MFA_REMEMBERED_TTL_SECONDS as i64);
    repository
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

#[cfg(test)]
pub(crate) async fn verify_user_mfa_code(
    db: &DbPool,
    user: &PublicAccount,
    code: &str,
) -> anyhow::Result<Option<MfaVerificationMethod>> {
    verify_user_mfa_code_with_repository(&MfaRepository::new(db.clone()), user, code).await
}

pub(crate) async fn verify_user_mfa_code_with_repository(
    repository: &MfaRepository,
    user: &PublicAccount,
    code: &str,
) -> anyhow::Result<Option<MfaVerificationMethod>> {
    let tenant_id = nazo_identity::TenantId::new(user.tenant_id())?;
    let user_id = nazo_identity::UserId::new(user.id())?;
    if let Some(normalized) = nazo_identity::mfa::normalize_backup_code(code) {
        return repository
            .consume_backup_code(tenant_id, user_id, &normalized)
            .await
            .map(|consumed| consumed.then_some(MfaVerificationMethod::BackupCode))
            .map_err(|error| anyhow::anyhow!("failed to consume backup code: {error:?}"));
    }
    repository
        .verify_and_consume_totp(tenant_id, user_id, code, Utc::now().timestamp())
        .await
        .map(|outcome| {
            (outcome == nazo_identity::ports::TotpVerificationOutcome::Accepted)
                .then_some(MfaVerificationMethod::Totp)
        })
        .map_err(|error| anyhow::anyhow!("failed to verify and consume TOTP: {error:?}"))
}

#[cfg(test)]
pub(crate) async fn replace_backup_codes(
    db: &DbPool,
    user: &PublicAccount,
) -> anyhow::Result<Vec<String>> {
    replace_backup_codes_with_repository(&MfaRepository::new(db.clone()), user).await
}

pub(crate) async fn replace_backup_codes_with_repository(
    repository: &MfaRepository,
    user: &PublicAccount,
) -> anyhow::Result<Vec<String>> {
    let (codes, hashes) = generate_backup_codes_and_hashes()?;
    let tenant_id = user.tenant().tenant_id;
    let user_id = user.user_id();
    repository
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

pub(crate) async fn clear_user_mfa_state_with_repository(
    repository: &MfaRepository,
    user: &PublicAccount,
) -> anyhow::Result<()> {
    let tenant_id = user.tenant().tenant_id;
    let user_id = user.user_id();
    repository
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
