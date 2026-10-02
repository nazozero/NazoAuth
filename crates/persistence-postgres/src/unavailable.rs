//! Typed classification shared only by signing-key and migration boundaries.
use diesel::result::{DatabaseErrorKind, Error};
use diesel_async::pooled_connection::{PoolError as BackendError, deadpool::PoolError};

pub(crate) fn query_is_unavailable(error: &Error) -> bool {
    matches!(
        error,
        Error::DatabaseError(DatabaseErrorKind::ClosedConnection | DatabaseErrorKind::SerializationFailure, _)
    )
}

pub(crate) fn checkout_is_unavailable(error: &anyhow::Error) -> bool {
    match error.downcast_ref::<PoolError>() {
        Some(PoolError::Closed | PoolError::Timeout(_)) => true,
        Some(PoolError::Backend(BackendError::QueryError(error))) => query_is_unavailable(error),
        _ => false,
    }
}

pub(crate) fn signing_query(error: Error) -> anyhow::Error {
    if query_is_unavailable(&error) {
        nazo_key_management::SigningKeyRepositoryUnavailable(error.into()).into()
    } else {
        error.into()
    }
}

pub(crate) fn signing_checkout(error: anyhow::Error) -> anyhow::Error {
    if checkout_is_unavailable(&error) {
        nazo_key_management::SigningKeyRepositoryUnavailable(error).into()
    } else {
        error
    }
}

pub(crate) fn migration_query(error: Error) -> anyhow::Error {
    if query_is_unavailable(&error) {
        nazo_persistence::MigrationUnavailable(error.into()).into()
    } else {
        error.into()
    }
}

// Diesel 2.3's private RunMigrationsError does not expose the query through
// Error::source. Preserve that box intact; only a publicly identifiable query
// is classified here. Opaque harness failures retain their existing category.
pub(crate) fn migration_harness(error: Box<dyn std::error::Error + Send + Sync>) -> anyhow::Error {
    match error.downcast::<Error>() {
        Ok(error) => migration_query(*error),
        Err(opaque) => anyhow::Error::from_boxed(opaque),
    }
}

pub(crate) fn migration_outcome(
    primary: anyhow::Result<bool>,
    unlock: anyhow::Result<()>,
) -> anyhow::Result<bool> {
    match (primary, unlock) {
        (Ok(applied), Ok(())) => Ok(applied),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.context("migration advisory lock release failed")),
        (Err(error), Err(unlock_error)) => {
            tracing::warn!(error = %unlock_error, "migration advisory unlock also failed");
            Err(error)
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/unavailable.rs"]
mod tests;
