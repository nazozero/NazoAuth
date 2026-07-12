use diesel_async::{
    AsyncPgConnection,
    pooled_connection::{AsyncDieselConnectionManager, deadpool::Object, deadpool::Pool},
};
use serde::Serialize;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

pub(crate) type DbPool = Pool<AsyncPgConnection>;
pub(crate) type DbConnection = Object<AsyncPgConnection>;

static DB_POOL_ACQUIRE_COUNT: AtomicU64 = AtomicU64::new(0);
static DB_POOL_WAIT_NANOS_TOTAL: AtomicU64 = AtomicU64::new(0);
static DB_POOL_WAIT_NANOS_MAX: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
pub(crate) struct DbPoolMetrics {
    pub(crate) acquire_count: u64,
    pub(crate) wait_nanos_total: u64,
    pub(crate) wait_nanos_max: u64,
}

pub(crate) fn create_pool(database_url: String, max_connections: usize) -> anyhow::Result<DbPool> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
    Ok(Pool::builder(manager).max_size(max_connections).build()?)
}

pub(crate) async fn get_conn(pool: &DbPool) -> anyhow::Result<DbConnection> {
    let started = Instant::now();
    let connection = pool.get().await;
    let wait_nanos = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    DB_POOL_ACQUIRE_COUNT.fetch_add(1, Ordering::Relaxed);
    DB_POOL_WAIT_NANOS_TOTAL.fetch_add(wait_nanos, Ordering::Relaxed);
    let _ = DB_POOL_WAIT_NANOS_MAX.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (wait_nanos > current).then_some(wait_nanos)
    });
    Ok(connection?)
}

pub(crate) fn db_pool_metrics() -> DbPoolMetrics {
    DbPoolMetrics {
        acquire_count: DB_POOL_ACQUIRE_COUNT.load(Ordering::Relaxed),
        wait_nanos_total: DB_POOL_WAIT_NANOS_TOTAL.load(Ordering::Relaxed),
        wait_nanos_max: DB_POOL_WAIT_NANOS_MAX.load(Ordering::Relaxed),
    }
}
