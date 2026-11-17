//! Common native fixtures for ordinary regressions and standalone HTTP measurement.
use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
};

pub(crate) fn persisted_runtime_modules_fixture() -> BTreeSet<nazo_runtime_modules::ModuleId> {
    use nazo_runtime_modules::ModuleId;

    BTreeSet::from([
        ModuleId::DeviceAuthorization,
        ModuleId::TokenExchange,
        ModuleId::JwtBearerGrant,
        ModuleId::Ciba,
        ModuleId::RequestObjects,
        ModuleId::Jarm,
        ModuleId::Scim,
        ModuleId::FrontchannelLogout,
        ModuleId::SessionManagement,
    ])
}

/// Shared infrastructure used to compose focused endpoint handles in tests.
#[derive(Clone)]
pub(crate) struct TestInfrastructure {
    pub(crate) diesel_db: nazo_postgres::DbPool,
    pub(crate) valkey: nazo_valkey::test_support::Client,
    pub(crate) settings: Arc<crate::settings::Settings>,
    pub(crate) keyset: nazo_key_management::KeyManager,
}

pub(crate) fn initialize_audit_dependencies(_pool: &nazo_postgres::DbPool) {
    static PROCESS_AUDIT_POOL: OnceLock<(tokio::runtime::Runtime, nazo_postgres::DbPool)> =
        OnceLock::new();

    // The production audit sink is process-lifetime state.  Some endpoint tests
    // intentionally use a pool whose search_path points at a small isolated
    // schema, so allowing the first such test to install that pool makes all
    // later required-audit calls depend on tables the isolated fixture does not
    // own.  Keep the process-lifetime test sink on the canonical public test
    // database; focused repositories continue to use their caller-provided
    // pool below.
    let (runtime, audit_pool) = PROCESS_AUDIT_POOL.get_or_init(|| {
        let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("database-backed tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
        // The shared sink outlives each test's runtime. Its connection
        // drivers need the same process lifetime as the pool itself.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("process audit fixture runtime should build");
        let pool = {
            let _entered = runtime.enter();
            nazo_postgres::create_pool(database_url, 4)
                .expect("test durable audit database pool should build")
        };
        (runtime, pool)
    });
    let preflight = crate::adapters::audit_anchor::AuditAnchorPreflight::new(
        crate::adapters::audit_anchor::AuditAnchorPreflightConfig {
            mode: crate::adapters::audit_anchor::config::AuditAnchorMode::Disabled,
            deployment_id: "unit-test".to_owned(),
            freshness: std::time::Duration::from_secs(1),
            max_lag: std::time::Duration::from_secs(1),
        },
    )
    .expect("test audit anchor preflight config is valid");
    // The process-lifetime sink's workers must survive the installing test,
    // just like the pool's connection drivers above.
    let _entered = runtime.enter();
    crate::adapters::audit::install_persistent_audit_sink(
        std::sync::Arc::new(nazo_postgres::AuditLedgerRepository::new(
            audit_pool.clone(),
        )),
        false,
        preflight,
    )
    .expect("test durable audit repository should install");
}
