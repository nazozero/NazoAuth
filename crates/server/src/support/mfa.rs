//! MFA helper functions.
//! TOTP follows RFC 6238 with SHA-1, 30-second steps, six digits, and one-step clock skew.

use chrono::Duration;
use diesel::dsl::now as diesel_now;

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
    user: &UserRow,
) -> anyhow::Result<bool> {
    let Some(token) = cookie_value(req, MFA_REMEMBERED_COOKIE_NAME) else {
        return Ok(false);
    };
    let token_hash = blake3_hex(token.trim());
    let user_agent_hash = request_user_agent_hash(req);
    let mut conn = get_conn(&state.diesel_db).await?;
    let row = user_mfa_remembered_devices::table
        .filter(user_mfa_remembered_devices::tenant_id.eq(user.tenant_id))
        .filter(user_mfa_remembered_devices::user_id.eq(user.id))
        .filter(user_mfa_remembered_devices::token_hash.eq(token_hash))
        .filter(user_mfa_remembered_devices::expires_at.gt(Utc::now()))
        .select((
            user_mfa_remembered_devices::id,
            user_mfa_remembered_devices::user_agent_hash,
        ))
        .first::<(Uuid, Option<String>)>(&mut conn)
        .await
        .optional()?;
    let Some((id, stored_user_agent_hash)) = row else {
        return Ok(false);
    };
    if stored_user_agent_hash != user_agent_hash {
        return Ok(false);
    }
    diesel::update(user_mfa_remembered_devices::table.find(id))
        .set(user_mfa_remembered_devices::last_used_at.eq(diesel_now))
        .execute(&mut conn)
        .await?;
    Ok(true)
}

pub(crate) async fn remember_mfa_device(
    state: &AppState,
    req: &HttpRequest,
    user: &UserRow,
) -> anyhow::Result<String> {
    let token = random_urlsafe_token();
    let token_hash = blake3_hex(&token);
    let expires_at = Utc::now() + Duration::seconds(MFA_REMEMBERED_TTL_SECONDS as i64);
    let mut conn = get_conn(&state.diesel_db).await?;
    diesel::delete(
        user_mfa_remembered_devices::table
            .filter(user_mfa_remembered_devices::tenant_id.eq(user.tenant_id))
            .filter(user_mfa_remembered_devices::user_id.eq(user.id))
            .filter(user_mfa_remembered_devices::expires_at.le(Utc::now())),
    )
    .execute(&mut conn)
    .await?;
    diesel::insert_into(user_mfa_remembered_devices::table)
        .values((
            user_mfa_remembered_devices::tenant_id.eq(user.tenant_id),
            user_mfa_remembered_devices::user_id.eq(user.id),
            user_mfa_remembered_devices::token_hash.eq(token_hash),
            user_mfa_remembered_devices::user_agent_hash.eq(request_user_agent_hash(req)),
            user_mfa_remembered_devices::expires_at.eq(expires_at),
        ))
        .execute(&mut conn)
        .await?;
    Ok(token)
}

pub(crate) async fn verify_user_mfa_code(
    db: &DbPool,
    user: &UserRow,
    code: &str,
) -> anyhow::Result<Option<MfaVerificationMethod>> {
    let now = Utc::now();
    let tenant_id = nazo_identity::TenantId::new(user.tenant_id)?;
    let user_id = nazo_identity::UserId::new(user.id)?;
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
    user: &UserRow,
) -> anyhow::Result<Vec<String>> {
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
    let tenant_id = nazo_identity::TenantId::new(user.tenant_id)?;
    let user_id = nazo_identity::UserId::new(user.id)?;
    nazo_postgres::MfaRepository::new(db.clone())
        .replace_backup_code_hashes(tenant_id, user_id, hashes)
        .await
        .map_err(|error| anyhow::anyhow!("failed to replace backup codes: {error:?}"))?;
    Ok(codes)
}

pub(crate) async fn clear_user_mfa_state(db: &DbPool, user: &UserRow) -> anyhow::Result<()> {
    let tenant_id = nazo_identity::TenantId::new(user.tenant_id)?;
    let user_id = nazo_identity::UserId::new(user.id)?;
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
