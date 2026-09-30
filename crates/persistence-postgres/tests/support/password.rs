pub struct BlockingSecretVerifier;

impl nazo_identity::ports::SecretVerifyPort for BlockingSecretVerifier {
    fn verify_secret(
        &self,
        secret: String,
        password_hash: nazo_identity::PasswordHash,
    ) -> nazo_identity::ports::SecretVerifyFuture<'_> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || password_hash.verify_password(&secret))
                .await
                .map_err(|_| nazo_identity::ports::SecretVerifyError::Failed)
        })
    }
}
