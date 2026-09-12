use std::{future::Future, pin::Pin};

use nazo_identity::{
    AuthenticatePasswordError, AuthenticatePasswordInput, authentication::PasswordLoginResult,
};

pub type PasswordLoginFuture<'a> = Pin<
    Box<dyn Future<Output = Result<PasswordLoginResult, AuthenticatePasswordError>> + Send + 'a>,
>;

pub trait PasswordLoginOperations: Send + Sync {
    fn authenticate_password(&self, input: AuthenticatePasswordInput) -> PasswordLoginFuture<'_>;
}
