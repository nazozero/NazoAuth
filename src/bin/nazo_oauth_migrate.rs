#![forbid(unsafe_code)]

use diesel::{Connection, PgConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use nazo_oauth_server::{config::ConfigSource, database_config::normalize_database_url};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

fn main() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let database_url = normalize_database_url(&config.string(
        "DATABASE_URL",
        "postgresql://postgres:postgres@127.0.0.1:5432/oauth",
    ));
    let mut connection = PgConnection::establish(&database_url)?;
    connection
        .run_pending_migrations(MIGRATIONS)
        .map_err(|error| anyhow::anyhow!("database migration failed: {error}"))?;
    Ok(())
}
