use crate::adapters::security::PasswordVerificationError;
use crate::adapters::security::verify_password_blocking_limited;

#[derive(Clone, Copy)]
pub(crate) struct LoginPasswordVerifier;

impl nazo_identity::ports::SecretVerifyPort for LoginPasswordVerifier {
    fn verify_secret(
        &self,
        secret: String,
        password_hash: nazo_identity::PasswordHash,
    ) -> nazo_identity::ports::SecretVerifyFuture<'_> {
        Box::pin(async move {
            verify_password_blocking_limited(secret, password_hash)
                .await
                .map_err(|error| match error {
                    PasswordVerificationError::Saturated => {
                        nazo_identity::ports::SecretVerifyError::Busy
                    }
                    PasswordVerificationError::WorkerFailed => {
                        nazo_identity::ports::SecretVerifyError::Failed
                    }
                })
        })
    }
}
