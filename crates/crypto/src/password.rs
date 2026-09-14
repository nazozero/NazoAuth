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

#[must_use]
pub fn verify_argon2_phc(encoded: &str, candidate: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(candidate, &parsed)
        .is_ok()
}
