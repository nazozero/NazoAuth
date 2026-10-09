use nazo_openid4vci::CredentialStoreError;
use rand::Rng;
use uuid::Uuid;
pub(super) fn protect_payload(
    key: &[u8; 32],
    transaction_id: Uuid,
    plaintext: &[u8],
) -> Result<Vec<u8>, CredentialStoreError> {
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let mut protected = nonce.to_vec();
    protected.extend_from_slice(
        &nazo_crypto::aead::encrypt(key, &nonce, transaction_id.as_bytes(), plaintext)
            .map_err(|_| CredentialStoreError::Unavailable)?,
    );
    Ok(protected)
}

pub(super) fn unprotect_payload(
    key: &[u8; 32],
    transaction_id: Uuid,
    protected: &[u8],
) -> Result<Vec<u8>, diesel::result::Error> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or_else(corrupt_stored_credential)?;
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| corrupt_stored_credential())?;
    nazo_crypto::aead::decrypt(key, nonce, transaction_id.as_bytes(), ciphertext)
        .map_err(|_| corrupt_stored_credential())
}

#[derive(Debug)]
struct CorruptStoredCredential;

impl std::fmt::Display for CorruptStoredCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("stored credential data is invalid")
    }
}

impl std::error::Error for CorruptStoredCredential {}

pub(super) fn corrupt_stored_credential() -> diesel::result::Error {
    diesel::result::Error::DeserializationError(Box::new(CorruptStoredCredential))
}

pub(super) fn map_stored_credential_error(error: diesel::result::Error) -> CredentialStoreError {
    match error {
        diesel::result::Error::DeserializationError(cause)
            if cause.is::<CorruptStoredCredential>() =>
        {
            CredentialStoreError::InvalidTransition
        }
        _ => CredentialStoreError::Unavailable,
    }
}
