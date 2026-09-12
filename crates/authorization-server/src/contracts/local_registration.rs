use std::{future::Future, pin::Pin};

use nazo_identity::{
    RegisterLocalAccountError, RegisterLocalAccountInput, SendVerificationCodeError,
    SendVerificationCodeOutcome, registration::RegisteredAccount,
};

pub type LocalRegistrationFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait LocalRegistrationOperations: Send + Sync {
    fn send_verification_code<'a>(
        &'a self,
        normalized_email: &'a str,
        peer_subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<SendVerificationCodeOutcome, SendVerificationCodeError>>;

    fn register_local_account(
        &self,
        input: RegisterLocalAccountInput,
    ) -> LocalRegistrationFuture<'_, Result<RegisteredAccount, RegisterLocalAccountError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

pub trait AuthenticationRateLimit: Send + Sync {
    fn enforce<'a>(
        &'a self,
        subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>>;
}
