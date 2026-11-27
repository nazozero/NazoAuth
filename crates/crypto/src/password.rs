//! Argon2id password hashing and PHC verification. Parameter policy and
//! concurrency limits remain with the host.

use argon2_rust::{
    Algorithm, Argon2, Params, Version,
    params::{Memory, TagLen},
};
use password_hash::{phc::PasswordHash, try_generate_salt};

use crate::CryptoError;

pub fn hash_argon2id(
    password: &[u8],
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> crate::Result<String> {
    let params = work_params(memory_cost_kib, time_cost, parallelism, 32)?;
    let salt = try_generate_salt().map_err(|_| CryptoError::OperationFailed)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_encoded(password, &salt)
        .map_err(|_| CryptoError::OperationFailed)
}

fn work_params(
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    tag_bytes: usize,
) -> crate::Result<Params> {
    Params::builder()
        .memory(Memory::kib(memory_kib.into()))
        .passes(passes)
        .lanes(lanes)
        .tag_len(TagLen::bytes(tag_bytes as u64))
        .build()
        .map_err(|_| CryptoError::InvalidInput)
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
    work_params(memory_cost_kib, time_cost, parallelism, 32)?;
    if parsed.algorithm.as_str() != Algorithm::Argon2id.as_str()
        || parsed.version != Some(Version::V0x13.as_u32())
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
    // Preserve the stored verifier's PHC grammar, defaults and associated data.
    let (Some(salt), Some(tag)) = (&parsed.salt, &parsed.hash) else {
        return false;
    };
    let Some(algorithm) = Algorithm::ALL
        .into_iter()
        .find(|a| a.as_str() == parsed.algorithm.as_str())
    else {
        return false;
    };
    let Some(version) = Version::from_u32(parsed.version.unwrap_or(Version::V0x13.as_u32())) else {
        return false;
    };
    // RustCrypto defaulted omitted costs and accepted data and keyid in any order.
    // Only data is an Argon2 input. keyid is metadata, historically limited to 8 bytes.
    let mut builder = Params::builder().tag_len(TagLen::bytes(tag.len() as u64));
    let mut data = [0u8; 32];
    let mut data_len = 0;
    for (name, value) in parsed.params.iter() {
        match name.as_str() {
            "m" | "t" | "p" => {
                let Ok(cost) = value.decimal() else {
                    return false;
                };
                builder = match name.as_str() {
                    "m" => builder.memory(Memory::kib(cost.into())),
                    "t" => builder.passes(cost),
                    _ => builder.lanes(cost),
                };
            }
            "data" => {
                let Ok(bytes) = value.b64_decode(&mut data) else {
                    return false;
                };
                data_len = bytes.len();
            }
            "keyid" if value.b64_decode(&mut [0; 8]).is_ok() => {}
            _ => return false,
        }
    }
    let Ok(params) = builder.build() else {
        return false;
    };
    Argon2::new(algorithm, version, params)
        .verify_with_ad(candidate, salt, &[], &data[..data_len], tag.as_bytes())
        .is_ok()
}
