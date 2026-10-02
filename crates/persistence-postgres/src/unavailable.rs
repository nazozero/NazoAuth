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

// Diesel 2.3's private RunMigrationsError neither exports its type nor exposes
// the query as Error::source. Capture the owned cause at Migration::run before
// that wrapper, while leaving ordering, transactions and ledger writes to Diesel.
pub(crate) fn run_pending_migrations(
    harness: &mut impl diesel_migrations::MigrationHarness<diesel::pg::Pg>,
    source: impl diesel::migration::MigrationSource<diesel::pg::Pg>,
) -> anyhow::Result<bool> {
    let failure = std::sync::Arc::new(std::sync::Mutex::new(None));
    let migrations = source.migrations().map_err(anyhow::Error::from_boxed)?;
    let source = CapturedMigrationSource(migrations.into_iter().map(|migration| std::rc::Rc::new(CapturedMigration { migration, failure: failure.clone() })).collect());
    let result = harness.run_pending_migrations(source).map(|applied| !applied.is_empty());
    result.map_err(|fallback| {
        let error = failure.lock().expect("migration cause lock").take().unwrap_or_else(|| anyhow::Error::from_boxed(fallback));
        if error.downcast_ref::<Error>().is_some_and(query_is_unavailable) {
            nazo_persistence::MigrationUnavailable(error).into()
        } else { error }
    })
}

struct CapturedMigrationSource(Vec<std::rc::Rc<CapturedMigration>>);
impl diesel::migration::MigrationSource<diesel::pg::Pg> for CapturedMigrationSource {
    fn migrations(&self) -> diesel::migration::Result<Vec<Box<dyn diesel::migration::Migration<diesel::pg::Pg>>>> {
        // The embedded/file source was resolved once. Diesel asks for owned
        // migrations, so wrappers borrow nothing and share only the error slot.
        Ok(self.0.iter().map(|migration| Box::new(CapturedMigrationRef(migration.clone())) as Box<dyn diesel::migration::Migration<diesel::pg::Pg>>).collect())
    }
}

struct CapturedMigration {
    migration: Box<dyn diesel::migration::Migration<diesel::pg::Pg>>,
    failure: std::sync::Arc<std::sync::Mutex<Option<anyhow::Error>>>,
}
struct CapturedMigrationRef(std::rc::Rc<CapturedMigration>);
#[derive(Debug)]
struct MigrationCauseCaptured;
impl std::fmt::Display for MigrationCauseCaptured {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("migration query failed") }
}
impl std::error::Error for MigrationCauseCaptured {}
impl diesel::migration::Migration<diesel::pg::Pg> for CapturedMigrationRef {
    fn run(&self, connection: &mut dyn diesel::connection::BoxableConnection<diesel::pg::Pg>) -> diesel::migration::Result<()> {
        self.0.migration.run(connection).map_err(|error| {
            *self.0.failure.lock().expect("migration cause lock") = Some(anyhow::Error::from_boxed(error).context(format!("migration {} failed", self.0.migration.name())));
            Box::new(MigrationCauseCaptured) as Box<dyn std::error::Error + Send + Sync>
        })
    }
    fn revert(&self, connection: &mut dyn diesel::connection::BoxableConnection<diesel::pg::Pg>) -> diesel::migration::Result<()> { self.0.migration.revert(connection) }
    fn metadata(&self) -> &dyn diesel::migration::MigrationMetadata { self.0.migration.metadata() }
    fn name(&self) -> &dyn diesel::migration::MigrationName { self.0.migration.name() }
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
