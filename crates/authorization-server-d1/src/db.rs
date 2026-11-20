//! D1 prepared statement execution. SQL remains private to this adapter.

use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Clone, Copy, Debug)]
pub(crate) enum DbError {
    Unavailable,
    CorruptData,
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "D1 storage is unavailable",
            Self::CorruptData => "D1 stored data is invalid",
        })
    }
}
impl std::error::Error for DbError {}

// Native builds without the offline SQLite feature expose the adapter's ports
// for composition checks, but deliberately have no SQL execution backend.
#[cfg_attr(
    all(not(target_arch = "wasm32"), not(feature = "local-sqlite")),
    allow(dead_code)
)]
pub(crate) struct Statement {
    pub(crate) sql: String,
    pub(crate) params: std::sync::Arc<[Value]>,
}
impl Statement {
    pub(crate) fn new(sql: impl Into<String>, params: impl Into<std::sync::Arc<[Value]>>) -> Self {
        Self {
            sql: sql.into(),
            params: params.into(),
        }
    }
}

pub(crate) struct Outcome {
    pub(crate) rows: Vec<Value>,
}

/// One primary database binding. Replicated sessions are deliberately unused:
/// authorization state and revocations must observe the primary authority.
#[derive(Clone)]
pub struct Database {
    #[cfg(target_arch = "wasm32")]
    inner: std::sync::Arc<worker::D1Database>,
    #[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
    inner: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
fn mfa_migration_already_applied(transaction: &rusqlite::Transaction<'_>) -> anyhow::Result<bool> {
    let definition: String = transaction.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='nazo_users'",
        [],
        |row| row.get(0),
    )?;
    let definition = definition
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase();
    if definition.contains("check(mfa_enabled=0)") {
        return Ok(false);
    }
    let tables: i64 = transaction.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table'
         AND name IN ('nazo_mfa_totp','nazo_mfa_backup_codes','nazo_mfa_devices')",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        definition.contains("check(mfa_enabledin(0,1))") && tables == 3,
        "unrecognized MFA schema without a migration receipt; refusing to reset MFA state",
    );
    Ok(true)
}

#[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
fn mtls_migration_already_applied(transaction: &rusqlite::Transaction<'_>) -> anyhow::Result<bool> {
    let columns: i64 = transaction.query_row(
        "SELECT count(*) FROM pragma_table_info('nazo_clients') WHERE name='require_mtls_bound_tokens'",
        [], |row| row.get(0),
    )?;
    let tables: i64 = transaction.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('nazo_mtls_trust_requests','nazo_mtls_trust_events')",
        [], |row| row.get(0),
    )?;
    if columns == 0 && tables == 0 {
        return Ok(false);
    }
    anyhow::ensure!(
        columns == 1 && tables == 2,
        "unrecognized mTLS schema without a migration receipt"
    );
    Ok(true)
}

impl Database {
    #[cfg(target_arch = "wasm32")]
    pub fn from_binding(database: worker::D1Database) -> Self {
        Self {
            inner: std::sync::Arc::new(database),
        }
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
    pub fn in_memory() -> anyhow::Result<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", true)?;
        Ok(Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(connection)),
        })
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
    pub fn open(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let connection = rusqlite::Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        Ok(Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(connection)),
        })
    }

    /// Apply the versioned deployment schema outside request handling.
    #[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
    pub fn execute_schema(&self) -> anyhow::Result<()> {
        use rusqlite::OptionalExtension as _;

        let mut connection = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("SQLite connection lock failed"))?;
        let transaction = connection.transaction()?;
        // This offline ledger is deliberately separate from Wrangler's
        // d1_migrations. A failed migration and its receipt roll back together.
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS nazo_local_migrations (name TEXT PRIMARY KEY,
             digest TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT, WITHOUT ROWID",
        )?;
        for (name, sql) in [
            ("0001.sql", include_str!("../migrations/0001.sql")),
            (
                "0002_state.sql",
                include_str!("../migrations/0002_state.sql"),
            ),
            (
                "0003_passkeys.sql",
                include_str!("../migrations/0003_passkeys.sql"),
            ),
            (
                "0004_dynamic_registration.sql",
                include_str!("../migrations/0004_dynamic_registration.sql"),
            ),
            (
                "0005_ciba_scim.sql",
                include_str!("../migrations/0005_ciba_scim.sql"),
            ),
            (
                "0006_accounts.sql",
                include_str!("../migrations/0006_accounts.sql"),
            ),
            (
                "0007_digital_credentials.sql",
                include_str!("../migrations/0007_digital_credentials.sql"),
            ),
            ("0008_mfa.sql", include_str!("../migrations/0008_mfa.sql")),
            (
                "0009_services.sql",
                include_str!("../migrations/0009_services.sql"),
            ),
            (
                "0010_federation_access.sql",
                include_str!("../migrations/0010_federation_access.sql"),
            ),
            (
                "0011_mtls_trust.sql",
                include_str!("../migrations/0011_mtls_trust.sql"),
            ),
            (
                "0012_grant_history.sql",
                include_str!("../migrations/0012_grant_history.sql"),
            ),
            (
                "0013_access_request_pending.sql",
                include_str!("../migrations/0013_access_request_pending.sql"),
            ),
        ] {
            let digest = blake3::hash(sql.as_bytes()).to_hex().to_string();
            let applied: Option<String> = transaction
                .query_row(
                    "SELECT digest FROM nazo_local_migrations WHERE name=?1",
                    [name],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(applied) = applied {
                anyhow::ensure!(applied == digest, "applied migration {name} changed");
                continue;
            }
            // Older offline stores and imported D1 databases have no local
            // ledger. CREATE IF NOT EXISTS migrations can be replayed; the
            // one-time MFA column replacement needs an explicit schema check.
            let already_applied = match name {
                "0008_mfa.sql" => mfa_migration_already_applied(&transaction)?,
                "0011_mtls_trust.sql" => mtls_migration_already_applied(&transaction)?,
                _ => false,
            };
            if !already_applied {
                transaction.execute_batch(sql)?;
            }
            transaction.execute(
                "INSERT INTO nazo_local_migrations(name,digest,applied_at) VALUES(?1,?2,unixepoch())",
                rusqlite::params![name, digest],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Offline provisioning and migration execution; never used by a Worker request.
    #[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
    pub fn execute_sql(&self, sql: &str) -> anyhow::Result<()> {
        self.inner
            .lock()
            .map_err(|_| anyhow::anyhow!("SQLite connection lock failed"))?
            .execute_batch(sql)?;
        Ok(())
    }

    /// Execute an offline fixture statement with data bound separately from SQL.
    /// Uses the same numeric checks, result draining and transaction as D1 tests.
    #[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
    pub async fn execute_statement(
        &self,
        sql: &'static str,
        params: Vec<Value>,
    ) -> anyhow::Result<()> {
        self.batch(vec![Statement::new(sql, params)]).await?;
        Ok(())
    }

    pub(crate) async fn query<T: DeserializeOwned>(
        &self,
        sql: &str,
        params: Vec<Value>,
    ) -> Result<Vec<T>, DbError> {
        #[cfg(target_arch = "wasm32")]
        {
            // Decode directly from the binding into the row projection: no SQL
            // allocation or intermediate JSON tree for the common single query.
            worker::send::SendFuture::new(async move {
                let params = params
                    .iter()
                    .map(parameter)
                    .collect::<Result<Vec<_>, _>>()?;
                let result = self
                    .inner
                    .prepare(sql)
                    .bind(&params)
                    .map_err(|_| DbError::Unavailable)?
                    .all()
                    .await
                    .map_err(|_| DbError::Unavailable)?;
                if !result.success() {
                    return Err(DbError::Unavailable);
                }
                result.results::<T>().map_err(|_| DbError::CorruptData)
            })
            .await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut outcomes = self.batch(vec![Statement::new(sql, params)]).await?;
            outcomes
                .pop()
                .ok_or(DbError::Unavailable)?
                .rows
                .into_iter()
                .map(|row| serde_json::from_value(row).map_err(|_| DbError::CorruptData))
                .collect()
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<Outcome>, DbError> {
        worker::send::SendFuture::new(async move {
            let prepared = statements
                .into_iter()
                .map(|statement| {
                    let params = statement
                        .params
                        .iter()
                        .map(parameter)
                        .collect::<Result<Vec<_>, _>>()?;
                    self.inner
                        .prepare(&statement.sql)
                        .bind(&params)
                        .map_err(|_| DbError::Unavailable)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let results = self
                .inner
                .batch(prepared)
                .await
                .map_err(|_| DbError::Unavailable)?;
            results
                .into_iter()
                .map(|result| {
                    if !result.success() {
                        return Err(DbError::Unavailable);
                    }
                    Ok(Outcome {
                        rows: result
                            .results::<Value>()
                            .map_err(|_| DbError::CorruptData)?,
                    })
                })
                .collect()
        })
        .await
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "local-sqlite"))]
    pub(crate) async fn batch(&self, statements: Vec<Statement>) -> Result<Vec<Outcome>, DbError> {
        let mut connection = self.inner.lock().map_err(|_| DbError::Unavailable)?;
        let transaction = connection.transaction().map_err(|_| DbError::Unavailable)?;
        let mut outcomes = Vec::with_capacity(statements.len());
        for statement in statements {
            let mut query = transaction
                .prepare_cached(&statement.sql)
                .map_err(|_| DbError::Unavailable)?;
            let names = query
                .column_names()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let params = statement
                .params
                .iter()
                .cloned()
                .map(|value| match value {
                    Value::Null => Ok(rusqlite::types::Value::Null),
                    Value::Bool(value) => Ok(rusqlite::types::Value::Integer(i64::from(value))),
                    Value::Number(value) => {
                        checked_number(&value)?;
                        value
                            .as_i64()
                            .map(rusqlite::types::Value::Integer)
                            .or_else(|| value.as_f64().map(rusqlite::types::Value::Real))
                            .ok_or(DbError::CorruptData)
                    }
                    Value::String(value) => Ok(rusqlite::types::Value::Text(value)),
                    _ => Err(DbError::CorruptData),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut cursor = query
                .query(rusqlite::params_from_iter(params))
                .map_err(|_| DbError::Unavailable)?;
            let mut rows = Vec::new();
            while let Some(row) = cursor.next().map_err(|_| DbError::Unavailable)? {
                let mut object = serde_json::Map::with_capacity(names.len());
                for (index, name) in names.iter().enumerate() {
                    let value = match row.get_ref(index).map_err(|_| DbError::CorruptData)? {
                        rusqlite::types::ValueRef::Null => Value::Null,
                        rusqlite::types::ValueRef::Integer(value) => Value::from(value),
                        rusqlite::types::ValueRef::Real(value) => Value::from(value),
                        rusqlite::types::ValueRef::Text(value) => Value::String(
                            std::str::from_utf8(value)
                                .map_err(|_| DbError::CorruptData)?
                                .to_owned(),
                        ),
                        rusqlite::types::ValueRef::Blob(value) => {
                            Value::Array(value.iter().copied().map(Value::from).collect())
                        }
                    };
                    object.insert(name.clone(), value);
                }
                rows.push(Value::Object(object));
            }
            drop(cursor);
            drop(query);
            outcomes.push(Outcome { rows });
        }
        transaction.commit().map_err(|_| DbError::Unavailable)?;
        Ok(outcomes)
    }

    #[cfg(all(not(target_arch = "wasm32"), not(feature = "local-sqlite")))]
    pub(crate) async fn batch(&self, _statements: Vec<Statement>) -> Result<Vec<Outcome>, DbError> {
        Err(DbError::Unavailable)
    }
}

#[cfg(target_arch = "wasm32")]
fn parameter(value: &Value) -> Result<worker::wasm_bindgen::JsValue, DbError> {
    use worker::wasm_bindgen::JsValue;
    match value {
        Value::Null => Ok(JsValue::NULL),
        Value::Bool(value) => Ok(JsValue::from_f64(u8::from(*value).into())),
        Value::String(value) => Ok(JsValue::from_str(value)),
        Value::Number(value) => checked_number(value).map(JsValue::from_f64),
        _ => Err(DbError::CorruptData),
    }
}

// D1 bindings cross the JavaScript Number boundary. Reject integer rounding
// before SQL so epochs, deadlines and compare-and-swap revisions stay exact.
#[cfg(any(target_arch = "wasm32", feature = "local-sqlite"))]
fn checked_number(value: &serde_json::Number) -> Result<f64, DbError> {
    const MAX_EXACT: u64 = 9_007_199_254_740_991;
    if value
        .as_i64()
        .is_some_and(|value| value.unsigned_abs() > MAX_EXACT)
        || value.as_u64().is_some_and(|value| value > MAX_EXACT)
    {
        return Err(DbError::CorruptData);
    }
    value
        .as_f64()
        .filter(|number| number.is_finite())
        .ok_or(DbError::CorruptData)
}
