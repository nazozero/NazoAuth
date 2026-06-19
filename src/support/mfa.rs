//! MFA helper functions.
//! TOTP follows RFC 6238 with SHA-1, 30-second steps, six digits, and one-step clock skew.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use chrono::Duration;
use diesel::dsl::now as diesel_now;

use super::prelude::*;
use super::{blake3_hex, hash_password, random_urlsafe_token, verify_password};

pub(crate) const MFA_REMEMBERED_COOKIE_NAME: &str = "nazo_oauth_mfa_remembered";
pub(crate) const MFA_REMEMBERED_TTL_SECONDS: u64 = 2_592_000;
pub(crate) const MFA_TOTP_PERIOD_SECONDS: i64 = 30;
pub(crate) const MFA_TOTP_DIGITS: usize = 6;
pub(crate) const MFA_BACKUP_CODE_COUNT: usize = 10;
const MFA_TOTP_SKEW_STEPS: i64 = 1;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MfaVerificationMethod {
    Totp,
    BackupCode,
}

impl MfaVerificationMethod {
    pub(crate) fn amr(self) -> &'static str {
        match self {
            Self::Totp => "otp",
            Self::BackupCode => "recovery_code",
        }
    }
}

pub(crate) fn generate_totp_secret_base32() -> String {
    base32_encode(&rand::random::<[u8; 20]>())
}

pub(crate) fn otpauth_uri(issuer: &str, account_name: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        urlencoding::encode(issuer),
        urlencoding::encode(account_name),
        secret_base32,
        urlencoding::encode(issuer),
        MFA_TOTP_DIGITS,
        MFA_TOTP_PERIOD_SECONDS
    )
}

pub(crate) fn verified_totp_step(
    secret_base32: &str,
    code: &str,
    now: i64,
    last_used_step: Option<i64>,
) -> Option<i64> {
    let candidate = code.trim();
    if candidate.len() != MFA_TOTP_DIGITS || !candidate.bytes().all(|value| value.is_ascii_digit())
    {
        return None;
    }
    let secret = base32_decode(secret_base32)?;
    let step = now.div_euclid(MFA_TOTP_PERIOD_SECONDS);
    (-MFA_TOTP_SKEW_STEPS..=MFA_TOTP_SKEW_STEPS).find_map(|offset| {
        let candidate_step = step.checked_add(offset)?;
        if last_used_step.is_some_and(|last| candidate_step <= last) {
            return None;
        }
        let expected = totp_for_step(&secret, candidate_step).ok()?;
        constant_time_eq(expected.as_bytes(), candidate.as_bytes()).then_some(candidate_step)
    })
}

pub(crate) fn generate_backup_code() -> String {
    const RANGE: u32 = 100_000;
    const LIMIT: u32 = u32::MAX - (u32::MAX % RANGE);

    fn chunk() -> u32 {
        loop {
            let value = u32::from_be_bytes(rand::random::<[u8; 4]>());
            if value < LIMIT {
                return value % RANGE;
            }
        }
    }

    format!("{:05}-{:05}", chunk(), chunk())
}

pub(crate) fn normalize_backup_code(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() == 10 && trimmed.bytes().all(|value| value.is_ascii_digit()) {
        return Some(trimmed.to_owned());
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() == 11
        && matches!(bytes[5], b'-' | b' ')
        && bytes[..5].iter().all(u8::is_ascii_digit)
        && bytes[6..].iter().all(u8::is_ascii_digit)
    {
        return Some(format!("{}{}", &trimmed[..5], &trimmed[6..]));
    }
    None
}

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
    let mut conn = get_conn(db).await?;
    let totp_credential = user_totp_credentials::table
        .filter(user_totp_credentials::tenant_id.eq(user.tenant_id))
        .filter(user_totp_credentials::user_id.eq(user.id))
        .filter(user_totp_credentials::confirmed_at.is_not_null())
        .select((
            user_totp_credentials::id,
            user_totp_credentials::secret_base32,
            user_totp_credentials::last_used_step,
        ))
        .first::<(Uuid, String, Option<i64>)>(&mut conn)
        .await
        .optional()?;
    if let Some((id, secret_base32, last_used_step)) = totp_credential
        && let Some(step) =
            verified_totp_step(&secret_base32, code, now.timestamp(), last_used_step)
    {
        let updated = diesel::update(
            user_totp_credentials::table.find(id).filter(
                user_totp_credentials::last_used_step
                    .is_null()
                    .or(user_totp_credentials::last_used_step.lt(step)),
            ),
        )
        .set((
            user_totp_credentials::last_used_step.eq(step),
            user_totp_credentials::updated_at.eq(diesel_now),
        ))
        .execute(&mut conn)
        .await?;
        if updated == 1 {
            return Ok(Some(MfaVerificationMethod::Totp));
        }
    }

    let Some(normalized) = normalize_backup_code(code) else {
        return Ok(None);
    };
    let candidates = user_mfa_backup_codes::table
        .filter(user_mfa_backup_codes::tenant_id.eq(user.tenant_id))
        .filter(user_mfa_backup_codes::user_id.eq(user.id))
        .filter(user_mfa_backup_codes::used_at.is_null())
        .select((user_mfa_backup_codes::id, user_mfa_backup_codes::code_hash))
        .limit(25)
        .load::<(Uuid, String)>(&mut conn)
        .await?;
    for (id, code_hash) in candidates {
        if verify_password(&normalized, &code_hash) {
            let updated = diesel::update(
                user_mfa_backup_codes::table
                    .find(id)
                    .filter(user_mfa_backup_codes::used_at.is_null()),
            )
            .set(user_mfa_backup_codes::used_at.eq(diesel_now))
            .execute(&mut conn)
            .await?;
            if updated == 1 {
                return Ok(Some(MfaVerificationMethod::BackupCode));
            }
            return Ok(None);
        }
    }
    Ok(None)
}

pub(crate) async fn replace_backup_codes(
    db: &DbPool,
    user: &UserRow,
) -> anyhow::Result<Vec<String>> {
    let mut codes = Vec::with_capacity(MFA_BACKUP_CODE_COUNT);
    let mut hashes = Vec::with_capacity(MFA_BACKUP_CODE_COUNT);
    for _ in 0..MFA_BACKUP_CODE_COUNT {
        let code = generate_backup_code();
        let normalized = normalize_backup_code(&code).expect("generated backup code is valid");
        let hash = hash_password(&normalized)
            .map_err(|error| anyhow::anyhow!("failed to hash backup code: {error}"))?;
        hashes.push(hash);
        codes.push(code);
    }
    let mut conn = get_conn(db).await?;
    diesel::delete(
        user_mfa_backup_codes::table
            .filter(user_mfa_backup_codes::tenant_id.eq(user.tenant_id))
            .filter(user_mfa_backup_codes::user_id.eq(user.id)),
    )
    .execute(&mut conn)
    .await?;
    for hash in hashes {
        diesel::insert_into(user_mfa_backup_codes::table)
            .values((
                user_mfa_backup_codes::tenant_id.eq(user.tenant_id),
                user_mfa_backup_codes::user_id.eq(user.id),
                user_mfa_backup_codes::code_hash.eq(hash),
            ))
            .execute(&mut conn)
            .await?;
    }
    Ok(codes)
}

pub(crate) async fn clear_user_mfa_state(db: &DbPool, user: &UserRow) -> anyhow::Result<()> {
    let mut conn = get_conn(db).await?;
    diesel::delete(
        user_mfa_backup_codes::table
            .filter(user_mfa_backup_codes::tenant_id.eq(user.tenant_id))
            .filter(user_mfa_backup_codes::user_id.eq(user.id)),
    )
    .execute(&mut conn)
    .await?;
    diesel::delete(
        user_mfa_remembered_devices::table
            .filter(user_mfa_remembered_devices::tenant_id.eq(user.tenant_id))
            .filter(user_mfa_remembered_devices::user_id.eq(user.id)),
    )
    .execute(&mut conn)
    .await?;
    diesel::delete(
        user_totp_credentials::table
            .filter(user_totp_credentials::tenant_id.eq(user.tenant_id))
            .filter(user_totp_credentials::user_id.eq(user.id)),
    )
    .execute(&mut conn)
    .await?;
    diesel::update(
        users::table
            .find(user.id)
            .filter(users::tenant_id.eq(user.tenant_id)),
    )
    .set((
        users::mfa_enabled.eq(false),
        users::updated_at.eq(diesel_now),
    ))
    .execute(&mut conn)
    .await?;
    Ok(())
}

fn request_user_agent_hash(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(blake3_hex)
}

pub(crate) fn totp_for_step(secret: &[u8], step: i64) -> anyhow::Result<String> {
    if step < 0 {
        anyhow::bail!("TOTP step must be non-negative");
    }
    let key = PKey::hmac(secret)?;
    let mut signer = Signer::new(MessageDigest::sha1(), &key)?;
    signer.update(&(step as u64).to_be_bytes())?;
    let digest = signer.sign_to_vec()?;
    let offset = digest
        .last()
        .map(|value| (value & 0x0f) as usize)
        .filter(|offset| offset + 4 <= digest.len())
        .ok_or_else(|| anyhow::anyhow!("TOTP HMAC digest is too short"))?;
    let binary = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    Ok(format!(
        "{:0width$}",
        binary % 10u32.pow(MFA_TOTP_DIGITS as u32),
        width = MFA_TOTP_DIGITS
    ))
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | (*byte as u32);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            output.push(BASE32_ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(BASE32_ALPHABET[index] as char);
    }
    output
}

fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut output = Vec::new();
    for ch in value.chars().filter(|ch| !ch.is_ascii_whitespace()) {
        let ch = ch.to_ascii_uppercase();
        let index = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            '=' => continue,
            _ => return None,
        };
        buffer = (buffer << 5) | index;
        bits += 5;
        if bits >= 8 {
            output.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    if output.is_empty() {
        None
    } else {
        Some(output)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/support/tests/mfa.rs"]
mod tests;
