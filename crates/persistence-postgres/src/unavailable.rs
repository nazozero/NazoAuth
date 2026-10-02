//! Typed classification shared only by signing-key and migration boundaries.
use diesel::result::{DatabaseErrorKind, Error};
use diesel_async::pooled_connection::{PoolError as BackendError, deadpool::PoolError};

pub(crate) fn query_is_unavailable(error: &Error) -> bool {
    matches!(error, Error::ClosedConnection | Error::DatabaseError(DatabaseErrorKind::SerializationFailure, _))
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

pub(crate) fn migration_harness(error: Box<dyn std::error::Error + Send + Sync>) -> anyhow::Error {
    // RunMigrationsError does not expose its QueryError through Error::source.
    let unavailable = match error.downcast_ref::<diesel_migrations::RunMigrationsError>() {
        Some(diesel_migrations::RunMigrationsError::QueryError(_, query)) => query_is_unavailable(query),
        _ => error.downcast_ref::<Error>().is_some_and(query_is_unavailable),
    };
    let source = anyhow::Error::from_boxed(error);
    if unavailable {
        nazo_persistence::MigrationUnavailable(source).into()
    } else {
        source
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
