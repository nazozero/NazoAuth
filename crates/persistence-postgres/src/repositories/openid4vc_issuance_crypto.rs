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
    nazo_crypto::aead::encrypt_prefixed(key, &nonce, transaction_id.as_bytes(), plaintext, &nonce)
        .map_err(|_| CredentialStoreError::Unavailable)
}

pub(super) fn unprotect_payload<'a>(
    key: &[u8; 32],
    transaction_id: Uuid,
    protected: &'a mut [u8],
) -> Result<&'a [u8], diesel::result::Error> {
    nazo_crypto::aead::decrypt_nonce_prefixed(key, transaction_id.as_bytes(), protected)
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
