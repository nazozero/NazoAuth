use nazo_identity::ports::RepositoryError;

use crate::repositories::audit::map_error;

/// Errors returned while a runtime-module transaction is being assembled.
///
/// Keeping this conversion at the transaction boundary lets the desired and
/// instance modules use `?` for Diesel failures without exposing a database
/// error type through the repository API.
#[derive(Debug)]
pub(super) enum RuntimeTransactionError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}

impl RuntimeTransactionError {
    pub(super) fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_error(error),
            Self::Repository(error) => error,
        }
    }
}

impl From<diesel::result::Error> for RuntimeTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}
