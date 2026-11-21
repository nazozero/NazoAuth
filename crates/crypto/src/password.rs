//! Argon2id password hashing and PHC verification. Parameter policy and
//! concurrency limits remain with the host.

use argon2::{Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _};

use crate::CryptoError;

pub fn hash_argon2id(
    password: &[u8],
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> crate::Result<String> {
    let params = argon2::Params::new(memory_cost_kib, time_cost, parallelism, None)
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password(password)
            .map_err(|_| CryptoError::OperationFailed)?
            .to_string(),
    )
}

/// Validate a complete Argon2id v19 verifier against the host's work parameters
/// without running the password hash or allocating its memory-hard workspace.
pub fn validate_argon2id_phc(
    encoded: &str,
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> crate::Result<()> {
    // PHC decoding validates salt/output encodings and lengths, but its grammar
    // permits either field to be absent. A usable verifier requires both.
    let parsed = PasswordHash::new(encoded).map_err(|_| CryptoError::InvalidInput)?;
    argon2::Params::try_from(&parsed).map_err(|_| CryptoError::InvalidInput)?;
    if parsed.algorithm != argon2::Algorithm::Argon2id.ident()
        || parsed.version != Some(argon2::Version::V0x13.into())
        || parsed.params.iter().count() != 3
        || parsed.params.get_decimal("m") != Some(memory_cost_kib)
        || parsed.params.get_decimal("t") != Some(time_cost)
        || parsed.params.get_decimal("p") != Some(parallelism)
        || parsed.salt.is_none()
        || parsed.hash.is_none()
    {
        return Err(CryptoError::InvalidInput);
    }
    Ok(())
}

#[must_use]
pub fn verify_argon2_phc(encoded: &str, candidate: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(candidate, &parsed)
        .is_ok()
}
