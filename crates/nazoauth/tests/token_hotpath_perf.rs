//! Hot-path latency/throughput benchmark for token issuance
//! (verification/03 §6). A real `nazoauth server` process serves a
//! provisioned tenant while blocking HTTP workers drive each grant path at
//! the configured concurrencies and record client-observed latency,
//! throughput, error rate, and PostgreSQL statement counts
//! (pg_stat_statements).
//!
//! The harness is gated on `NAZO_PERF_HOTPATH=1` and requires
//! `NAZO_TEST_DATABASE_URL`/`DATABASE_URL`, `NAZO_TEST_VALKEY_URL`/`VALKEY_URL`,
//! plus `NAZO_PERF_OUTPUT` for the JSONL results file. Optional knobs:
//! `NAZO_PERF_OPS` (default 2000 measured ops per E2E group-run),
//! `NAZO_PERF_RUNS` (default 3), `NAZO_PERF_WARMUP` (default 200),
//! `NAZO_PERF_CONCURRENCIES` (default "1,8,32", E2E only),
//! `NAZO_PERF_SENS_OPS`/`NAZO_PERF_SENS_WARMUP` (defaults 3000/300,
//! algorithm-sensitivity phase at fixed concurrency 8).
//!
//! One-time inputs (authorization codes) are prepared independently per op —
//! codes are seeded into Valkey under the same state shape the authorize flow
//! writes — and refresh/native-SSO chains are bootstrapped through real code
//! redemptions, so measured successes are never replayed errors. Subject-bound
//! paths (userinfo/token-exchange) redeem a fresh subject access token through
//! a real code redemption before every group-run's warmup; the provisioning
//! bootstrap token only proves the tenant's signing algorithm.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::Engine as _;
use chrono::Utc;
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection as _,
};
use nazo_auth::{AuthorizationCodeState, CodePayload, empty_authorization_details};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantId};
use nazo_key_management::{SigningKeyWrappingKeyRing, test_support::create_database_keyset};
use nazo_oauth_server::crypto::{blake3_hex, client_secret_digest, pkce_s256};
use nazo_postgres::{
    SigningKeysetRepository, TenantBoundaryDefinition, TenantDirectoryRepository,
    TenantProvisioningRequest, create_pool, run_pending_migrations,
};
use nazo_valkey::{AuthorizationStore, ValkeyConnection};
use uuid::Uuid;

const READINESS_WINDOW: Duration = Duration::from_secs(60);
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const DEPLOYMENT_ID: &str = "perf-hotpath";
const MIGRATION_RUNTIME_ROLE: &str = "nazoauth_perf_runtime";
const CLIENT_SECRET: &str = "perf-hotpath-client-secret";

/// Per-run generated secrets the fixture writes into the spawned server's
/// config; nothing hard-coded is persisted or checked in. The wrapping ring
/// is derived once so the test can pre-seed tenant keysets through the same
/// sealing path the server uses at startup.
struct BenchSecrets {
    client_secret_pepper: String,
    pairwise_subject_secret: String,
    signing_key_encryption_key: String,
    wrapping_keys: SigningKeyWrappingKeyRing,
}

impl BenchSecrets {
    fn generate() -> Self {
        let mut material = [0_u8; 32];
        material[..16].copy_from_slice(Uuid::now_v7().as_bytes());
        material[16..].copy_from_slice(Uuid::now_v7().as_bytes());
        let signing_key_encryption_key =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(material);
        let wrapping_keys = SigningKeyWrappingKeyRing::new("perf-signing-root", material, None)
            .expect("generated wrapping key ring is valid");
        Self {
            client_secret_pepper: format!("perf-pepper-{}", Uuid::now_v7().simple()),
            pairwise_subject_secret: format!("perf-pairwise-{}", Uuid::now_v7().simple()),
            signing_key_encryption_key,
            wrapping_keys,
        }
    }
}
const PKCE_VERIFIER: &str = "perf-pkce-verifier-0123456789abcdef0123456789abcdef";
/// The system tenant created by `migrate` binds the configured ISSUER host;
/// it must differ from every benchmark tenant host so both resolve.
const SYSTEM_ISSUER: &str = "https://system.perf.example";
const SYSTEM_HOST: &str = "system.perf.example";
const DEFAULT_AUDIENCE: &str = "resource://t1";
const DEVICE_SSO_SCOPE: &str = "device_sso";
const CODE_TTL_SECONDS: i64 = 900;
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

struct BenchConfig {
    database_url: String,
    valkey_url: String,
    output: PathBuf,
    /// Measured ops per E2E group-run.
    ops: usize,
    runs: usize,
    /// Warmup ops per E2E group-run.
    warmup: usize,
    /// E2E concurrency levels; the sensitivity phase is fixed at 8.
    concurrencies: Vec<usize>,
    /// Measured ops per sensitivity group-run (concurrency 8).
    sens_ops: usize,
    /// Warmup ops per sensitivity group-run.
    sens_warmup: usize,
}

const SENSITIVITY_CONCURRENCY: usize = 8;

fn bench_config() -> Option<BenchConfig> {
    if std::env::var("NAZO_PERF_HOTPATH").as_deref() != Ok("1") {
        return None;
    }
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("perf benchmark requires NAZO_TEST_DATABASE_URL or DATABASE_URL");
    let valkey_url = std::env::var("NAZO_TEST_VALKEY_URL")
        .or_else(|_| std::env::var("VALKEY_URL"))
        .expect("perf benchmark requires NAZO_TEST_VALKEY_URL or VALKEY_URL");
    let output = std::env::var("NAZO_PERF_OUTPUT")
        .map(PathBuf::from)
        .expect("perf benchmark requires NAZO_PERF_OUTPUT");
    let concurrencies = std::env::var("NAZO_PERF_CONCURRENCIES")
        .unwrap_or_else(|_| "1,8,32".to_owned())
        .split(',')
        .filter_map(|item| item.trim().parse::<usize>().ok())
        .collect::<Vec<_>>();
    assert!(
        !concurrencies.is_empty(),
        "NAZO_PERF_CONCURRENCIES must not be empty"
    );
    Some(BenchConfig {
        database_url,
        valkey_url,
        output,
        ops: env_usize("NAZO_PERF_OPS", 2_000),
        runs: env_usize("NAZO_PERF_RUNS", 3),
        warmup: env_usize("NAZO_PERF_WARMUP", 200),
        concurrencies,
        sens_ops: env_usize("NAZO_PERF_SENS_OPS", 3_000),
        sens_warmup: env_usize("NAZO_PERF_SENS_WARMUP", 300),
    })
}

// ---------------------------------------------------------------------------
// Fixture helpers (mirrors token_issuance_simplification.rs conventions)
// ---------------------------------------------------------------------------

fn temporary_directory(tag: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("nazoauth-perf-{tag}-{}", Uuid::now_v7().simple()));
    std::fs::create_dir_all(&root).expect("temp directory should create");
    root
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("probe listener should bind")
        .local_addr()
        .expect("probe listener address should resolve")
        .port()
}

fn server_config_yaml(
    port: u16,
    database_url: &str,
    valkey_url: &str,
    data_dir: &Path,
    state_epoch: Uuid,
    secrets: &BenchSecrets,
) -> String {
    let BenchSecrets {
        client_secret_pepper,
        pairwise_subject_secret,
        signing_key_encryption_key,
        wrapping_keys: _,
    } = secrets;
    format!(
        r#"BIND: "127.0.0.1:{port}"
DATA_DIR: "{}"
DEPLOYMENT_ID: "{DEPLOYMENT_ID}"
DATABASE_URL: "{database_url}"
VALKEY_URL: "{valkey_url}"
VALKEY_STATE_EPOCH: "{state_epoch}"
VALKEY_COMMAND_TIMEOUT_MS: 2000
ISSUER: "{SYSTEM_ISSUER}"
TRANSPORT_MODE: "trusted-proxy"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
MTLS_CERTIFICATE_SOURCE: "rfc9440"
CLIENT_IP_HEADER_MODE: "x-forwarded-for"
CLIENT_SECRET_PEPPER: "{client_secret_pepper}"
PAIRWISE_SUBJECT_SECRET: "{pairwise_subject_secret}"
SIGNING_KEY_ENCRYPTION_KEY_ID: "perf-signing-root"
SIGNING_KEY_ENCRYPTION_KEY: "{signing_key_encryption_key}"
COOKIE_SECURE: true
SESSION_COOKIE_NAME: "perf_session"
CSRF_COOKIE_NAME: "perf_csrf"
DEFAULT_AUDIENCE: "{DEFAULT_AUDIENCE}"
SUBJECT_TYPE: "public"
SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE: false
TOKEN_RATE_LIMIT_MAX_REQUESTS: 1000000000
AUTH_RATE_LIMIT_MAX_REQUESTS: 1000000000
TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS: 1000000000
RUST_LOG: "info"
"#,
        data_dir.display().to_string().replace('\\', "/")
    )
}

fn write_config(path: &Path, yaml: &str) {
    std::fs::write(path, yaml).expect("server config should write");
}

struct ServerProcess {
    child: Child,
    port: u16,
    log_path: PathBuf,
}

impl ServerProcess {
    fn wait_until_ready(&mut self, host: &str) {
        let started = Instant::now();
        loop {
            if http_status(self.port, host, "GET", DISCOVERY_PATH, None, &[]) == 200 {
                return;
            }
            if let Some(exit) = self
                .child
                .try_wait()
                .expect("server process status should be readable")
            {
                let log = std::fs::read_to_string(&self.log_path).unwrap_or_default();
                panic!(
                    "server on port {} exited with {exit} before readiness:\n{log}",
                    self.port
                );
            }
            assert!(
                started.elapsed() < READINESS_WINDOW,
                "server on port {} did not become ready within the startup window",
                self.port
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const OVERRIDING_ENV_KEYS: &[&str] = &[
    "DATABASE_URL",
    "VALKEY_URL",
    "VALKEY_STATE_EPOCH",
    "ISSUER",
    "PUBLIC_BASE_URL",
    "BIND",
    "DATA_DIR",
    "AVATAR_STORAGE_DIR",
    "TRANSPORT_MODE",
    "DEPLOYMENT_ID",
    "TRUSTED_PROXY_CIDRS",
    "CLIENT_IP_HEADER_MODE",
    "CLIENT_SECRET_PEPPER",
    "PAIRWISE_SUBJECT_SECRET",
    "COOKIE_SECURE",
    "SESSION_COOKIE_NAME",
    "CSRF_COOKIE_NAME",
    "DEFAULT_AUDIENCE",
    "SUBJECT_TYPE",
    "TOKEN_RATE_LIMIT_MAX_REQUESTS",
    "AUTH_RATE_LIMIT_MAX_REQUESTS",
    "TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS",
    "SIGNING_KEY_ENCRYPTION_KEY",
    "SIGNING_KEY_ENCRYPTION_KEY_ID",
    "SIGNING_KEY_ENCRYPTION_KEY_FILE",
    "SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY",
    "SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_FILE",
    "SIGNING_KEY_PREVIOUS_ENCRYPTION_KEY_ID",
];

fn child_command(subcommand: &str, config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nazoauth"));
    command
        .arg(subcommand)
        .env("NAZOAUTH_SERVER_CONFIG_FILE", config);
    for key in OVERRIDING_ENV_KEYS {
        command.env_remove(key);
    }
    command
}

fn spawn_server(config: &Path, port: u16) -> ServerProcess {
    let log_path = config
        .parent()
        .expect("config has a parent")
        .join("server.log");
    let log = std::fs::File::create(&log_path).expect("server log file should create");
    let error_log = log.try_clone().expect("server error log file should clone");
    let child = child_command("server", config)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log))
        .spawn()
        .expect("server process should spawn");
    ServerProcess {
        child,
        port,
        log_path,
    }
}

fn run_cli(command: &str, config: &Path) {
    let output = child_command(command, config)
        .env("NAZOAUTH_MIGRATION_RUNTIME_ROLE", MIGRATION_RUNTIME_ROLE)
        .output()
        .expect("nazoauth CLI should run");
    assert!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Raw synchronous HTTP/1.1 exchange for readiness probes — safe to call from
/// any thread because it never touches an async runtime.
fn http_status(
    port: u16,
    host: &str,
    method: &str,
    path: &str,
    body: Option<String>,
    extra_headers: &[(&str, &str)],
) -> u16 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut stream =
            std::net::TcpStream::connect(("127.0.0.1", port)).expect("probe should connect");
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        if let Some(ref payload) = body {
            request.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
            request.push_str(&format!("Content-Length: {}\r\n", payload.len()));
        }
        for (name, value) in extra_headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        if let Some(payload) = body {
            request.push_str(&payload);
        }
        stream
            .write_all(request.as_bytes())
            .expect("probe should write");
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .expect("probe should read to end");
        let text = String::from_utf8_lossy(&raw).into_owned();
        text.split_whitespace()
            .nth(1)
            .and_then(|status| status.parse::<u16>().ok())
            .unwrap_or(0)
    }))
    .unwrap_or(0)
}

fn provisioning_request(slug: &str, host: &str, issuer: &str) -> TenantProvisioningRequest {
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("tenant id is non-nil");
    let realm_id = RealmId::new(Uuid::now_v7()).expect("realm id is non-nil");
    let organization_id = OrganizationId::new(Uuid::now_v7()).expect("organization id is non-nil");
    fn boundary<Id>(id: Id, slug: &str, suffix: &str) -> TenantBoundaryDefinition<Id> {
        TenantBoundaryDefinition {
            id,
            slug: format!("{slug}-{suffix}"),
            display_name: format!("{slug} {suffix}"),
        }
    }
    TenantProvisioningRequest {
        tenant: boundary(tenant_id, slug, "tenant"),
        realm: boundary(realm_id, slug, "realm"),
        organization: boundary(organization_id, slug, "organization"),
        binding: TenantDirectoryBinding {
            tenant: TenantContext {
                tenant_id,
                realm_id,
                organization_id,
            },
            runtime_revision: 1,
            issuer: issuer.to_owned(),
            external_host: host.to_owned(),
        },
    }
}

/// Resources a run must not leave behind: the isolated `perf_hot_*` database
/// and the bootstrap/server temp directories (config files carry generated
/// secrets, plus server.log). Declared last on `IssuanceFixture` so it drops
/// after the server child, connection pool, and stores are gone.
struct FixtureCleanup {
    admin_url: String,
    database_name: String,
    temp_dirs: Vec<PathBuf>,
}

/// `Drop` cannot await on the caller's runtime, so the DROP DATABASE runs on
/// a dedicated thread owning a single-threaded runtime.
fn drop_isolated_database(admin_url: String, statement: String) {
    let _ = std::thread::Builder::new()
        .name("perf-db-cleanup".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("cleanup runtime should build");
            runtime.block_on(async move {
                if let Ok(mut connection) = AsyncPgConnection::establish(&admin_url).await {
                    let _ = connection.batch_execute(&statement).await;
                }
            });
        })
        .map(|handle| handle.join());
}

impl Drop for FixtureCleanup {
    fn drop(&mut self) {
        if !self.database_name.is_empty() {
            drop_isolated_database(
                self.admin_url.clone(),
                format!(
                    "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
                    self.database_name
                ),
            );
        }
        for dir in self.temp_dirs.drain(..) {
            if let Err(error) = std::fs::remove_dir_all(&dir) {
                eprintln!("perf cleanup could not remove {}: {error}", dir.display());
            }
        }
    }
}

struct IssuanceFixture {
    server: ServerProcess,
    isolated_url: String,
    pool: nazo_postgres::DbPool,
    state_epoch: Uuid,
    secrets: BenchSecrets,
    _cleanup: FixtureCleanup,
}

/// One benchmark tenant whose keyset was seeded with `at_algorithm` as the
/// active signing algorithm, so every grant path on this tenant produces
/// access tokens under that algorithm.
struct AlgorithmTenant {
    at_algorithm_name: &'static str,
    host: String,
    issuer: String,
    user_id: Uuid,
    store: AuthorizationStore,
}

async fn start_issuance_fixture(database_url: &str, valkey_url: &str) -> IssuanceFixture {
    // A per-run state epoch namespaces every Valkey key — the directory
    // snapshot cache and transient grant state — so no earlier benchmark
    // run can poison this fixture's tenant view.
    let state_epoch = Uuid::now_v7();
    let database_name = format!("perf_hot_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE DATABASE \"{database_name}\";"))
        .await
        .expect("isolated database should create");
    drop(coordinator);
    let isolated_url = with_database_name(database_url, &database_name);
    run_pending_migrations(&isolated_url)
        .await
        .expect("isolated database migrations should apply");

    {
        let mut role_coordinator = AsyncPgConnection::establish(database_url)
            .await
            .expect("test database should connect for role preparation");
        role_coordinator
            .batch_execute(&format!(
                "SELECT pg_advisory_lock(564196923451771043);\
                 DO $$ BEGIN \
                   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATION_RUNTIME_ROLE}') THEN \
                     CREATE ROLE {MIGRATION_RUNTIME_ROLE} NOSUPERUSER NOBYPASSRLS NOINHERIT; \
                   END IF; \
                 END $$;\
                 SELECT pg_advisory_unlock(564196923451771043);"
            ))
            .await
            .expect("migration runtime role fixture should exist");
        drop(role_coordinator);
    }

    let mut cleanup = FixtureCleanup {
        admin_url: database_url.to_owned(),
        database_name: database_name.clone(),
        temp_dirs: Vec::new(),
    };
    let secrets = BenchSecrets::generate();

    let bootstrap_dir = temporary_directory("bootstrap");
    cleanup.temp_dirs.push(bootstrap_dir.clone());
    let bootstrap_config = bootstrap_dir.join(".env.yaml");
    write_config(
        &bootstrap_config,
        &server_config_yaml(
            free_port(),
            &isolated_url,
            valkey_url,
            &bootstrap_dir,
            state_epoch,
            &secrets,
        ),
    );
    run_cli("migrate", &bootstrap_config);

    let process_dir = temporary_directory("server");
    cleanup.temp_dirs.push(process_dir.clone());
    let port = free_port();
    let config = process_dir.join(".env.yaml");
    write_config(
        &config,
        &server_config_yaml(
            port,
            &isolated_url,
            valkey_url,
            &process_dir,
            state_epoch,
            &secrets,
        ),
    );
    let mut server = spawn_server(&config, port);
    server.wait_until_ready(SYSTEM_HOST);

    let pool = create_pool(isolated_url.clone(), 4).expect("directory pool should build");

    IssuanceFixture {
        server,
        isolated_url,
        pool,
        state_epoch,
        secrets,
        _cleanup: cleanup,
    }
}

struct TenantProvisionRequest<'a> {
    slug: &'a str,
    host: &'a str,
    at_algorithm_name: &'static str,
    at_algorithm: nazo_crypto::jwt::Algorithm,
}

/// Provision one tenant, seed its signing keyset with `at_algorithm` as the
/// active rotation key before the tenant runtime first builds, wait for the
/// runtime to serve, then seed the benchmark clients/user and prove the
/// effective algorithm from a real bootstrap redemption.
async fn provision_algorithm_tenant(
    fixture: &IssuanceFixture,
    connection: &mut AsyncPgConnection,
    valkey_url: &str,
    request: &TenantProvisionRequest<'_>,
    wrapping_keys: &SigningKeyWrappingKeyRing,
) -> AlgorithmTenant {
    let &TenantProvisionRequest {
        slug,
        host,
        at_algorithm_name,
        at_algorithm,
    } = request;
    let repository = TenantDirectoryRepository::new(fixture.pool.clone());
    let revision = repository
        .current_revision()
        .await
        .expect("directory revision should read");
    let issuer = format!("https://{host}");
    let request = provisioning_request(slug, host, &issuer);
    let tenant = request.binding.tenant;
    repository
        .provision_tenant_binding(revision, request)
        .await
        .expect("tenant should provision");
    // The tenant runtime creates its keyset on first load; writing the row
    // before that load wins deterministically because the directory
    // reconciler only observes the committed binding after this point.
    create_database_keyset(
        tenant.tenant_id.as_uuid(),
        std::sync::Arc::new(SigningKeysetRepository::for_tenant(
            fixture.pool.clone(),
            tenant.tenant_id.as_uuid(),
        )),
        wrapping_keys,
        at_algorithm,
    )
    .await
    .expect("tenant signing keyset should seed");

    let port = fixture.server.port;
    let started = Instant::now();
    loop {
        if http_status(port, host, "GET", DISCOVERY_PATH, None, &[]) == 200 {
            break;
        }
        assert!(
            started.elapsed() < READINESS_WINDOW,
            "tenant {host} did not route within the convergence window"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // Discovery routes on the directory index; the tenant runtime finishes
    // building slightly later. An invalid /token request returning a protocol
    // error (not 502) proves the tenant pipeline is serving before one-time
    // codes are spent.
    let started = Instant::now();
    loop {
        let status = http_status(
            port,
            host,
            "POST",
            "/token",
            Some("grant_type=authorization_code".to_owned()),
            &[],
        );
        if status != 0 && status != 502 {
            break;
        }
        assert!(
            started.elapsed() < READINESS_WINDOW,
            "tenant {host} runtime did not start serving /token within the convergence window"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    let user_id = Uuid::now_v7();
    seed_user(connection, &tenant, user_id).await;
    let web_grants = "[\"authorization_code\",\"refresh_token\",\"client_credentials\",\"urn:ietf:params:oauth:grant-type:token-exchange\"]";
    let web_scopes = "[\"openid\",\"offline_access\",\"api:read\"]";
    let sso_grants = "[\"authorization_code\",\"refresh_token\",\"urn:ietf:params:oauth:grant-type:token-exchange\"]";
    let sso_scopes = "[\"openid\",\"offline_access\",\"device_sso\"]";
    let pepper = &fixture.secrets.client_secret_pepper;
    seed_client(
        connection,
        &tenant,
        "bench-web",
        web_scopes,
        web_grants,
        "RS256",
        pepper,
    )
    .await;
    seed_client(
        connection,
        &tenant,
        "bench-sso",
        sso_scopes,
        sso_grants,
        "RS256",
        pepper,
    )
    .await;

    let store = authorization_store(valkey_url, &tenant, fixture.state_epoch).await;

    // A real bootstrap redemption proves the seeded keyset's algorithm is the
    // one signing — a lost provisioning race fails here, never silently. The
    // token is not reused: subject-bound paths redeem a fresh one per
    // group-run.
    let codes = seed_codes(
        &store,
        "bench-web",
        user_id,
        &["openid", "api:read"],
        1,
        None,
    )
    .await;
    let host_owned = host.to_owned();
    let access_token = tokio::task::block_in_place(move || {
        let worker = Worker::new(port, &host_owned, "bench-web", None);
        redeem_code(&worker, &codes[0])["access_token"]
            .as_str()
            .expect("access_token")
            .to_owned()
    });
    assert_eq!(
        decode_alg(&access_token).as_deref(),
        Some(at_algorithm_name),
        "tenant {host} issued its bootstrap access token under the wrong algorithm"
    );
    assert_eq!(
        decode_iss(&access_token),
        issuer,
        "tenant {host} issued its bootstrap access token under the wrong issuer"
    );

    AlgorithmTenant {
        at_algorithm_name,
        host: host.to_owned(),
        issuer,
        user_id,
        store,
    }
}

fn with_database_name(database_url: &str, name: &str) -> String {
    let separator = database_url.rfind('/').expect("database URL has a path");
    format!("{}/{}", &database_url[..separator], name)
}

async fn sql(connection: &mut AsyncPgConnection, statement: &str) {
    diesel::sql_query(statement.to_owned())
        .execute(connection)
        .await
        .unwrap_or_else(|error| panic!("statement failed: {error}\n{statement}"));
}

async fn seed_client(
    connection: &mut AsyncPgConnection,
    tenant: &TenantContext,
    client_id: &str,
    scopes: &str,
    grant_types: &str,
    id_token_alg: &str,
    client_secret_pepper: &str,
) {
    sql(
        connection,
        &format!(
            "INSERT INTO oauth_clients (\
                tenant_id, realm_id, organization_id, client_id, client_name, client_type,\
                redirect_uris, scopes, allowed_audiences, grant_types, token_endpoint_auth_method,\
                client_secret_hash, subject_type, sector_identifier_host, id_token_signed_response_alg,\
                tls_client_auth_subject_dn, require_dpop_bound_tokens, require_mtls_bound_tokens,\
                tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip, tls_client_auth_san_email,\
                allow_client_assertion_audience_array, allow_client_assertion_endpoint_audience,\
                require_par_request_object, is_active, security_policy, post_logout_redirect_uris,\
                backchannel_logout_session_required)\
             VALUES ('{}','{}','{}','{client_id}','perf client','confidential',\
                '[\"https://app.example/cb\"]','{scopes}','[\"{DEFAULT_AUDIENCE}\"]','{grant_types}',\
                'client_secret_basic','{}','pairwise','app.example','{id_token_alg}',\
                NULL,false,false,'[]','[]','[]','[]',false,false,false,true,\
                '{{\"version\":1,\"assurance\":\"baseline\",\"require_signed_authorization_request\":false,\"require_signed_authorization_response\":false,\"require_signed_introspection_response\":false,\"session_management\":false,\"allow_cross_device_flows\":true,\"allow_confidential_oidc_without_pkce\":false}}',\
                '[]',false)",
            tenant.tenant_id.as_uuid(),
            tenant.realm_id.as_uuid(),
            tenant.organization_id.as_uuid(),
            client_secret_digest(
                CLIENT_SECRET,
                client_secret_pepper,
                &Uuid::now_v7().simple().to_string(),
            ),
        ),
    )
    .await;
}

async fn seed_user(connection: &mut AsyncPgConnection, tenant: &TenantContext, user_id: Uuid) {
    sql(
        connection,
        &format!(
            "INSERT INTO users (\
                id, tenant_id, realm_id, organization_id, username, email, password_hash,\
                is_active, mfa_enabled, email_verified, role, admin_level)\
             VALUES ('{user_id}','{}','{}','{}','perf-user-{user_id}',\
                'perf-user-{user_id}@example.test','perf-password-hash',\
                TRUE, FALSE, TRUE, 'user', 0)",
            tenant.tenant_id.as_uuid(),
            tenant.realm_id.as_uuid(),
            tenant.organization_id.as_uuid(),
        ),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Valkey authorization-code seeding — written through the production
// AuthorizationStore with the same AuthorizationCodeState shape the authorize
// endpoint persists, so redemption takes the real atomic path.
// ---------------------------------------------------------------------------

async fn authorization_store(
    valkey_url: &str,
    tenant: &TenantContext,
    state_epoch: Uuid,
) -> AuthorizationStore {
    let connection = ValkeyConnection::connect(
        valkey_url,
        Duration::from_secs(2),
        DEPLOYMENT_ID,
        state_epoch,
        tenant.tenant_id,
    )
    .await
    .expect("tenant-scoped valkey connection should establish");
    AuthorizationStore::new(&connection)
}

/// Seed `count` pending authorization codes; returns the raw codes in order.
async fn seed_codes(
    store: &AuthorizationStore,
    client_id: &str,
    user_id: Uuid,
    scopes: &[&str],
    count: usize,
    oidc_sid: Option<&str>,
) -> Vec<String> {
    let now = Utc::now();
    let mut entries = Vec::with_capacity(count);
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let code = format!("{}.{}", Uuid::now_v7().simple(), Uuid::now_v7().simple());
        let state = AuthorizationCodeState::Pending {
            payload: CodePayload {
                code_id: Uuid::now_v7().to_string(),
                user_id,
                client_id: client_id.to_owned(),
                redirect_uri: "https://app.example/cb".to_owned(),
                redirect_uri_was_supplied: false,
                scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
                resource_indicators: Vec::new(),
                authorization_details: empty_authorization_details(),
                nonce: None,
                auth_time: now.timestamp(),
                amr: vec!["pwd".to_owned()],
                oidc_sid: oidc_sid.map(str::to_owned),
                acr: None,
                userinfo_claims: Vec::new(),
                userinfo_claim_requests: Vec::new(),
                id_token_claims: Vec::new(),
                id_token_claim_requests: Vec::new(),
                code_challenge: Some(pkce_s256(PKCE_VERIFIER)),
                code_challenge_method: Some("S256".to_owned()),
                dpop_jkt: None,
                mtls_x5t_s256: None,
                issued_at: now,
                expires_at: now + chrono::Duration::seconds(CODE_TTL_SECONDS),
            },
        };
        entries.push((blake3_hex(&code), state));
        codes.push(code);
    }
    for chunk in entries.chunks(256) {
        for result in futures_util::future::join_all(chunk.iter().map(|(hash, state)| {
            store.store_authorization_code_hash(hash, state, CODE_TTL_SECONDS as u64)
        }))
        .await
        {
            result.expect("authorization code seed should store");
        }
    }
    codes
}

// ---------------------------------------------------------------------------
// HTTP worker — one reqwest blocking client per OS thread (keep-alive).
// ---------------------------------------------------------------------------

struct Worker {
    client: reqwest_012::blocking::Client,
    port: u16,
    host: String,
    basic: String,
    mtls_header: Option<String>,
}

impl Worker {
    fn new(port: u16, host: &str, client_id: &str, mtls_header: Option<String>) -> Self {
        use base64::engine::general_purpose::STANDARD;
        let client = reqwest_012::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(2)
            // The measurement target is always loopback; ambient HTTP(S)_PROXY
            // settings must never reroute benchmark traffic.
            .no_proxy()
            .build()
            .expect("worker http client should build");
        Self {
            client,
            port,
            host: host.to_owned(),
            basic: format!(
                "Basic {}",
                STANDARD.encode(format!("{client_id}:{CLIENT_SECRET}"))
            ),
            mtls_header,
        }
    }

    fn post_token(&self, form: &str) -> (u16, String) {
        let mut request = self
            .client
            .post(format!("http://127.0.0.1:{}/token", self.port))
            .header("Host", &self.host)
            .header("Authorization", &self.basic)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form.to_owned());
        if let Some(header) = &self.mtls_header {
            request = request.header("Client-Cert", header);
        }
        match request.send() {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().unwrap_or_default();
                (status, body)
            }
            Err(_) => (0, String::new()),
        }
    }

    fn get_userinfo(&self, access_token: &str) -> u16 {
        self.client
            .get(format!("http://127.0.0.1:{}/userinfo", self.port))
            .header("Host", &self.host)
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map(|response| response.status().as_u16())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Benchmark driver
// ---------------------------------------------------------------------------

struct RunResult {
    ops: usize,
    errors: usize,
    first_error: String,
    wall_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    /// Per-worker input state after the run — refresh chains carry rotated
    /// tokens forward between warmup and measured phases.
    final_inputs: Vec<Vec<String>>,
}

fn percentile(sorted: &[u64], quantile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() as f64 - 1.0) * quantile).round() as usize;
    sorted[index.min(sorted.len() - 1)] as f64 / 1_000_000.0
}

/// Spawn `workers` OS threads; each runs `per_worker_ops` operations against
/// its own input slice and returns its (possibly mutated) inputs.
fn run_group<F>(
    workers: usize,
    per_worker_ops: usize,
    inputs: Vec<Vec<String>>,
    make_worker: &(dyn Fn(usize) -> Worker + Sync),
    op: &F,
) -> RunResult
where
    F: Fn(&Worker, &mut Vec<String>, usize) -> bool + Sync,
{
    let barrier = Arc::new(std::sync::Barrier::new(workers));
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(per_worker_ops * workers);
    let mut errors = 0usize;
    let mut first_error = String::new();
    let mut final_inputs = Vec::with_capacity(workers);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for index in 0..workers {
            let mut worker_inputs = inputs.get(index).cloned().unwrap_or_default();
            let barrier = barrier.clone();
            handles.push(scope.spawn(move || {
                let worker = make_worker(index);
                let mut latencies = Vec::with_capacity(per_worker_ops);
                let mut errors = 0usize;
                let mut first_error = String::new();
                barrier.wait();
                for slot in 0..per_worker_ops {
                    let started = Instant::now();
                    let ok = op(&worker, &mut worker_inputs, slot);
                    let elapsed = started.elapsed();
                    if ok {
                        latencies.push(elapsed.as_nanos() as u64);
                    } else {
                        errors += 1;
                        if first_error.is_empty() {
                            first_error = format!("worker {index} op {slot} failed");
                        }
                    }
                }
                (latencies, errors, first_error, worker_inputs)
            }));
        }
        for handle in handles {
            let (mut worker_latencies, worker_errors, worker_first, worker_inputs) =
                handle.join().expect("worker should join");
            latencies.append(&mut worker_latencies);
            errors += worker_errors;
            if first_error.is_empty() {
                first_error = worker_first;
            }
            final_inputs.push(worker_inputs);
        }
    });
    let wall = started.elapsed();
    latencies.sort_unstable();
    RunResult {
        ops: latencies.len(),
        errors,
        first_error,
        wall_ms: wall.as_secs_f64() * 1000.0,
        p50_ms: percentile(&latencies, 0.50),
        p95_ms: percentile(&latencies, 0.95),
        p99_ms: percentile(&latencies, 0.99),
        final_inputs,
    }
}

// ---------------------------------------------------------------------------
// pg_stat_statements accounting
// ---------------------------------------------------------------------------

type StatementSnapshot = HashMap<String, (String, i64)>;

async fn statement_snapshot(connection: &mut AsyncPgConnection) -> StatementSnapshot {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Text)]
        queryid: String,
        #[diesel(sql_type = diesel::sql_types::Text)]
        query: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        calls: i64,
    }
    diesel::sql_query(
        "SELECT queryid::text AS queryid, query, calls \
         FROM pg_stat_statements \
         WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .load::<Row>(connection)
    .await
    .expect(
        "pg_stat_statements snapshot must load — a failed or missing extension produces \
         empty statistics that would masquerade as zero SQL work",
    )
    .into_iter()
    .map(|row| (row.queryid, (row.query, row.calls)))
    .collect()
}

/// Statement executions between snapshots, excluding fixed background traffic
/// (module reconciler, harness probes) so the delta approximates the measured
/// path's SQL work. Residual maintenance-job queries may still be included;
/// they are bounded per interval tick.
fn statement_delta(before: &StatementSnapshot, after: &StatementSnapshot) -> (i64, i64) {
    let mut total = 0i64;
    let mut attributed = 0i64;
    for (queryid, (query, calls)) in after {
        let delta = calls - before.get(queryid).map(|(_, calls)| *calls).unwrap_or(0);
        if delta <= 0 {
            continue;
        }
        total += delta;
        let noise = [
            "runtime_module",
            "pg_stat_statements",
            "pg_database",
            "pg_catalog",
            "information_schema",
            "pg_advisory_lock(564196923451771043)",
        ]
        .iter()
        .any(|marker| query.contains(marker));
        if !noise {
            attributed += delta;
        }
    }
    (total, attributed)
}

// ---------------------------------------------------------------------------
// Bootstrap helpers — real code redemptions
// ---------------------------------------------------------------------------

fn redeem_code(worker: &Worker, code: &str) -> serde_json::Value {
    let form = format!("grant_type=authorization_code&code={code}&code_verifier={PKCE_VERIFIER}");
    let (status, body) = worker.post_token(&form);
    assert_eq!(status, 200, "bootstrap code redemption failed: {body}");
    serde_json::from_str(&body).expect("token response should parse")
}

fn mtls_client_cert_header() -> String {
    let certified = rcgen::generate_simple_self_signed(vec!["perf-device.example".to_owned()])
        .expect("self-signed client certificate should generate");
    format!(
        ":{}:",
        base64::engine::general_purpose::STANDARD.encode(certified.cert.der().as_ref())
    )
}

fn decode_iss(jwt: &str) -> String {
    jwt.split('.')
        .nth(1)
        .and_then(|segment| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segment)
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|claims| claims["iss"].as_str().map(str::to_owned))
        .expect("issued token payload should decode and carry iss")
}

fn decode_alg(jwt: &str) -> Option<String> {
    jwt.split('.')
        .next()
        .and_then(|segment| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segment)
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|header| header["alg"].as_str().map(str::to_owned))
}

fn split_inputs(codes: Vec<String>, workers: usize) -> Vec<Vec<String>> {
    let mut inputs = vec![Vec::new(); workers];
    for (index, code) in codes.into_iter().enumerate() {
        inputs[index % workers].push(code);
    }
    inputs
}

// ---------------------------------------------------------------------------
// Main benchmark
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct GroupRecord {
    path: String,
    signing_algorithms: String,
    concurrency: usize,
    run: usize,
    warmup_ops: usize,
    measured_ops: usize,
    errors: usize,
    first_error: String,
    wall_ms: f64,
    throughput_ops_s: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    sql_calls_total: i64,
    sql_calls_attributed: i64,
    sql_per_op: f64,
}

#[derive(Clone, Copy)]
enum PathKind {
    ClientCredentials,
    AuthorizationCode,
    Refresh,
    Userinfo,
    TokenExchange,
    NativeSso,
}

struct BenchPath {
    name: &'static str,
    algs: String,
    client_id: &'static str,
    needs_mtls: bool,
    kind: PathKind,
}

#[test]
fn token_hotpath_benchmark() {
    let Some(bench) = bench_config() else {
        eprintln!("NAZO_PERF_HOTPATH not set; skipping token hotpath benchmark");
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime should build");
    runtime.block_on(run_benchmark(bench));
}

async fn run_benchmark(bench: BenchConfig) {
    let fixture = start_issuance_fixture(&bench.database_url, &bench.valkey_url).await;
    let port = fixture.server.port;
    let mut connection = AsyncPgConnection::establish(&fixture.isolated_url)
        .await
        .expect("perf database should connect");
    sql(
        &mut connection,
        "CREATE EXTENSION IF NOT EXISTS pg_stat_statements",
    )
    .await;
    sql(&mut connection, "SELECT pg_stat_statements_reset()").await;

    // The fixture generated the deployment's wrapping key for the spawned
    // server; reuse the same ring to pre-seed each tenant's keyset through
    // the same payload construction and sealing the startup path uses.
    let wrapping_keys = &fixture.secrets.wrapping_keys;

    // One tenant per access-token signing algorithm — the access token always
    // carries the keyset's active algorithm, so algorithm coverage is a
    // per-tenant property. Each tenant's keyset row is written before its
    // runtime can build, then proven from a real issued token.
    let mut tenants = Vec::new();
    for (name, algorithm) in [
        ("RS256", nazo_crypto::jwt::Algorithm::RS256),
        ("PS256", nazo_crypto::jwt::Algorithm::PS256),
        ("ES256", nazo_crypto::jwt::Algorithm::ES256),
        ("EdDSA", nazo_crypto::jwt::Algorithm::EdDSA),
    ] {
        let host = format!("perf-{}.example", name.to_ascii_lowercase());
        tenants.push(
            provision_algorithm_tenant(
                &fixture,
                &mut connection,
                &bench.valkey_url,
                &TenantProvisionRequest {
                    slug: &format!("perf-{name}"),
                    host: &host,
                    at_algorithm_name: name,
                    at_algorithm: algorithm,
                },
                wrapping_keys,
            )
            .await,
        );
    }

    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&bench.output)
        .expect("benchmark output file should open");
    let mut emit = |record: &GroupRecord| {
        let line = serde_json::to_string(record).expect("record should serialize");
        println!("{line}");
        writeln!(out, "{line}").expect("record should write");
        out.flush().expect("record should flush");
    };

    // E2E hot paths on the representative RS256 tenant; ID-token-issuing
    // paths use the representative RS256 id-token client configuration — no
    // id-token algorithm cross-product.
    let rs256_tenant = tenants
        .iter()
        .find(|tenant| tenant.at_algorithm_name == "RS256")
        .expect("the RS256 tenant is provisioned");
    let e2e_paths = [
        BenchPath {
            name: "client_credentials",
            algs: "at=RS256".to_owned(),
            client_id: "bench-web",
            needs_mtls: false,
            kind: PathKind::ClientCredentials,
        },
        BenchPath {
            name: "authorization_code",
            algs: "at=RS256,id_token=RS256".to_owned(),
            client_id: "bench-web",
            needs_mtls: false,
            kind: PathKind::AuthorizationCode,
        },
        BenchPath {
            name: "refresh_token",
            algs: "at=RS256,id_token=RS256".to_owned(),
            client_id: "bench-web",
            needs_mtls: false,
            kind: PathKind::Refresh,
        },
        BenchPath {
            name: "userinfo_pairwise",
            algs: "at=RS256".to_owned(),
            client_id: "bench-web",
            needs_mtls: false,
            kind: PathKind::Userinfo,
        },
        BenchPath {
            name: "token_exchange",
            algs: "at=RS256".to_owned(),
            client_id: "bench-web",
            needs_mtls: false,
            kind: PathKind::TokenExchange,
        },
        BenchPath {
            name: "native_sso_fresh",
            algs: "at=RS256,id_token=RS256".to_owned(),
            client_id: "bench-sso",
            needs_mtls: true,
            kind: PathKind::NativeSso,
        },
    ];

    for path in &e2e_paths {
        for &concurrency in &bench.concurrencies {
            for run in 0..bench.runs {
                measure_group_run(
                    &GroupRun {
                        path,
                        tenant: rs256_tenant,
                        concurrency,
                        run,
                        warmup_ops: bench.warmup,
                        measured_ops: bench.ops,
                    },
                    &mut connection,
                    port,
                    &mut emit,
                )
                .await;
            }
        }
    }

    // Algorithm sensitivity: two representative paths (signing via
    // client_credentials, verification + PG ownership via userinfo) across
    // all four access-token algorithms at a fixed concurrency.
    for tenant in &tenants {
        let at = tenant.at_algorithm_name;
        let sensitivity_paths = [
            BenchPath {
                name: "client_credentials",
                algs: format!("at={at}"),
                client_id: "bench-web",
                needs_mtls: false,
                kind: PathKind::ClientCredentials,
            },
            BenchPath {
                name: "userinfo_pairwise",
                algs: format!("at={at}"),
                client_id: "bench-web",
                needs_mtls: false,
                kind: PathKind::Userinfo,
            },
        ];
        for path in &sensitivity_paths {
            for run in 0..bench.runs {
                measure_group_run(
                    &GroupRun {
                        path,
                        tenant,
                        concurrency: SENSITIVITY_CONCURRENCY,
                        run,
                        warmup_ops: bench.sens_warmup,
                        measured_ops: bench.sens_ops,
                    },
                    &mut connection,
                    port,
                    &mut emit,
                )
                .await;
            }
        }
    }

    println!("benchmark complete");
}

/// One (path, tenant, concurrency, run) measurement group.
struct GroupRun<'a> {
    path: &'a BenchPath,
    tenant: &'a AlgorithmTenant,
    concurrency: usize,
    run: usize,
    warmup_ops: usize,
    measured_ops: usize,
}

/// Execute one group: redeem a fresh subject token for subject-bound paths,
/// warm up, measure, emit the record, and fail the benchmark on any error or
/// success shortfall.
async fn measure_group_run(
    group: &GroupRun<'_>,
    connection: &mut AsyncPgConnection,
    port: u16,
    emit: &mut dyn FnMut(&GroupRecord),
) {
    let &GroupRun {
        path,
        tenant,
        concurrency,
        run,
        warmup_ops,
        measured_ops,
    } = group;
    // Subject-bound paths present a fresh access token per group-run —
    // redeemed through the production store + real /token redemption, never
    // the provisioning bootstrap token.
    let subject_at = match path.kind {
        PathKind::Userinfo | PathKind::TokenExchange => {
            fresh_subject_token(tenant, port, path.client_id).await
        }
        _ => String::new(),
    };

    let host_for_workers = tenant.host.clone();
    let mtls_header = path.needs_mtls.then(mtls_client_cert_header);
    let client_id = path.client_id;
    let worker_mtls = mtls_header.clone();
    let make_worker =
        move |_index: usize| Worker::new(port, &host_for_workers, client_id, worker_mtls.clone());

    let warmup_per_worker = warmup_ops.div_ceil(concurrency).max(1);
    let measured_per_worker = measured_ops.div_ceil(concurrency).max(1);

    // Fresh inputs for every run — runs are independent executions, not
    // continuations of earlier state.
    let warmup_inputs = prepare_run_inputs(
        path,
        tenant,
        RunInputRequest {
            port,
            workers: concurrency,
            ops_per_worker: warmup_per_worker,
            mtls_header: mtls_header.clone(),
        },
    )
    .await;

    let warmup = execute(
        path,
        concurrency,
        warmup_per_worker,
        warmup_inputs,
        &make_worker,
        &subject_at,
        &tenant.issuer,
    );
    assert_eq!(
        warmup.errors,
        0,
        "warmup errors for {} c={concurrency} run={} — fixture broken: {}",
        path.name,
        run + 1,
        warmup.first_error
    );

    let measured_inputs: Vec<Vec<String>> = match path.kind {
        PathKind::AuthorizationCode => {
            let codes = seed_codes(
                &tenant.store,
                path.client_id,
                tenant.user_id,
                &["openid", "offline_access", "api:read"],
                measured_per_worker * concurrency,
                None,
            )
            .await;
            split_inputs(codes, concurrency)
        }
        // Refresh chains / SSO pairs continue from warmup state.
        _ => warmup.final_inputs,
    };

    let before = statement_snapshot(connection).await;
    let result = execute(
        path,
        concurrency,
        measured_per_worker,
        measured_inputs,
        &make_worker,
        &subject_at,
        &tenant.issuer,
    );
    let after = statement_snapshot(connection).await;
    assert!(
        !after.is_empty(),
        "pg_stat_statements produced an empty snapshot for {} c={concurrency} run={} \
         — SQL-call evidence would be fabricated as zero",
        path.name,
        run + 1,
    );
    let (sql_total, sql_attributed) = statement_delta(&before, &after);
    emit(&GroupRecord {
        path: path.name.to_owned(),
        signing_algorithms: path.algs.to_owned(),
        concurrency,
        run: run + 1,
        warmup_ops: warmup_per_worker * concurrency,
        measured_ops: result.ops,
        errors: result.errors,
        first_error: result.first_error.clone(),
        wall_ms: result.wall_ms,
        throughput_ops_s: if result.wall_ms > 0.0 {
            result.ops as f64 / (result.wall_ms / 1000.0)
        } else {
            0.0
        },
        p50_ms: result.p50_ms,
        p95_ms: result.p95_ms,
        p99_ms: result.p99_ms,
        sql_calls_total: sql_total,
        sql_calls_attributed: sql_attributed,
        sql_per_op: if result.ops > 0 {
            sql_attributed as f64 / result.ops as f64
        } else {
            0.0
        },
    });
    // The record is evidence, not a pass: any measured error or shortfall in
    // successful operations fails the benchmark.
    assert_eq!(
        result.errors,
        0,
        "{} c={concurrency} run={} recorded {} measured errors: {}",
        path.name,
        run + 1,
        result.errors,
        result.first_error
    );
    assert_eq!(
        result.ops,
        measured_per_worker * concurrency,
        "{} c={concurrency} run={} measured {} successful ops, expected {}",
        path.name,
        run + 1,
        result.ops,
        measured_per_worker * concurrency
    );
}

/// Seed one pending code and redeem it through the real /token exchange —
/// a fresh subject access token for one group-run.
async fn fresh_subject_token(tenant: &AlgorithmTenant, port: u16, client_id: &str) -> String {
    let codes = seed_codes(
        &tenant.store,
        client_id,
        tenant.user_id,
        &["openid", "api:read"],
        1,
        None,
    )
    .await;
    let host = tenant.host.clone();
    let client_id = client_id.to_owned();
    let code = codes.into_iter().next().expect("one subject code seeded");
    tokio::task::block_in_place(move || {
        let worker = Worker::new(port, &host, &client_id, None);
        redeem_code(&worker, &code)["access_token"]
            .as_str()
            .expect("fresh subject access token")
            .to_owned()
    })
}

struct RunInputRequest {
    port: u16,
    workers: usize,
    ops_per_worker: usize,
    mtls_header: Option<String>,
}

/// Fresh per-run warmup inputs for `path` on `tenant` — one-time grants are
/// seeded independently per op; refresh/native-SSO chains bootstrap through
/// real code redemptions. Reusable subject tokens live on the tenant.
async fn prepare_run_inputs(
    path: &BenchPath,
    tenant: &AlgorithmTenant,
    request: RunInputRequest,
) -> Vec<Vec<String>> {
    let RunInputRequest {
        port,
        workers: concurrency,
        ops_per_worker: warmup_per_worker,
        mtls_header,
    } = request;
    match path.kind {
        PathKind::AuthorizationCode => {
            let codes = seed_codes(
                &tenant.store,
                path.client_id,
                tenant.user_id,
                &["openid", "offline_access", "api:read"],
                warmup_per_worker * concurrency,
                None,
            )
            .await;
            split_inputs(codes, concurrency)
        }
        PathKind::Refresh => {
            let codes = seed_codes(
                &tenant.store,
                path.client_id,
                tenant.user_id,
                &["openid", "offline_access", "api:read"],
                concurrency,
                None,
            )
            .await;
            let client_id = path.client_id.to_owned();
            let host = tenant.host.clone();
            tokio::task::block_in_place(move || {
                let worker = Worker::new(port, &host, &client_id, None);
                codes
                    .iter()
                    .map(|code| {
                        vec![
                            redeem_code(&worker, code)["refresh_token"]
                                .as_str()
                                .expect("refresh_token")
                                .to_owned(),
                        ]
                    })
                    .collect::<Vec<_>>()
            })
        }
        PathKind::NativeSso => {
            let codes = seed_codes(
                &tenant.store,
                path.client_id,
                tenant.user_id,
                &["openid", "offline_access", DEVICE_SSO_SCOPE],
                concurrency,
                Some("perf-sso-sid"),
            )
            .await;
            let client_id = path.client_id.to_owned();
            let host = tenant.host.clone();
            tokio::task::block_in_place(move || {
                // The measured workers present this same certificate — the
                // sender-constraint binding recorded at bootstrap must match.
                let worker = Worker::new(port, &host, &client_id, mtls_header);
                codes
                    .iter()
                    .map(|code| {
                        let body = redeem_code(&worker, code);
                        vec![
                            body["id_token"].as_str().expect("id_token").to_owned(),
                            body["device_secret"]
                                .as_str()
                                .expect("device_secret")
                                .to_owned(),
                        ]
                    })
                    .collect::<Vec<_>>()
            })
        }
        PathKind::Userinfo | PathKind::TokenExchange | PathKind::ClientCredentials => {
            vec![Vec::new(); concurrency]
        }
    }
}

/// Drive `per_worker_ops` operations per worker on the given path kind.
fn execute(
    path: &BenchPath,
    concurrency: usize,
    per_worker_ops: usize,
    phase_inputs: Vec<Vec<String>>,
    make_worker: &(dyn Fn(usize) -> Worker + Sync),
    subject_at: &str,
    issuer: &str,
) -> RunResult {
    match path.kind {
        PathKind::ClientCredentials => run_group(
            concurrency,
            per_worker_ops,
            phase_inputs,
            make_worker,
            &|worker: &Worker, _inputs: &mut Vec<String>, _slot: usize| {
                let (status, body) =
                    worker.post_token("grant_type=client_credentials&scope=api:read");
                status == 200 || {
                    eprintln!("client_credentials error {status}: {body}");
                    false
                }
            },
        ),
        PathKind::AuthorizationCode => run_group(
            concurrency,
            per_worker_ops,
            phase_inputs,
            make_worker,
            &|worker: &Worker, slot_inputs: &mut Vec<String>, slot: usize| {
                let Some(code) = slot_inputs.get(slot).cloned() else {
                    eprintln!("auth_code input exhausted at slot {slot}");
                    return false;
                };
                let (status, body) = worker.post_token(&format!(
                    "grant_type=authorization_code&code={code}&code_verifier={PKCE_VERIFIER}"
                ));
                status == 200 || {
                    eprintln!("auth_code error {status}: {body}");
                    false
                }
            },
        ),
        PathKind::Refresh => run_group(
            concurrency,
            per_worker_ops,
            phase_inputs,
            make_worker,
            &|worker: &Worker, slot_inputs: &mut Vec<String>, _slot: usize| {
                let Some(current) = slot_inputs.as_slice().first().cloned() else {
                    return false;
                };
                let (status, body) = worker.post_token(&format!(
                    "grant_type=refresh_token&refresh_token={}",
                    urlencoding::encode(&current)
                ));
                if status != 200 {
                    eprintln!("refresh error {status}: {body}");
                    return false;
                }
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                let Some(next) = parsed["refresh_token"].as_str().map(str::to_owned) else {
                    eprintln!("refresh response missing token: {body}");
                    return false;
                };
                slot_inputs[0] = next;
                true
            },
        ),
        PathKind::Userinfo => run_group(
            concurrency,
            per_worker_ops,
            phase_inputs,
            make_worker,
            &|worker: &Worker, _inputs: &mut Vec<String>, _slot: usize| {
                worker.get_userinfo(subject_at) == 200
            },
        ),
        PathKind::TokenExchange => run_group(
            concurrency,
            per_worker_ops,
            phase_inputs,
            make_worker,
            &|worker: &Worker, _inputs: &mut Vec<String>, _slot: usize| {
                let (status, body) = worker.post_token(&format!(
                    "grant_type={TOKEN_EXCHANGE_GRANT}\
                     &subject_token_type=urn:ietf:params:oauth:token-type:access_token\
                     &subject_token={}&audience={}&scope=api:read",
                    urlencoding::encode(subject_at),
                    urlencoding::encode(DEFAULT_AUDIENCE),
                ));
                status == 200 || {
                    eprintln!("token_exchange error {status}: {body}");
                    false
                }
            },
        ),
        PathKind::NativeSso => run_group(
            concurrency,
            per_worker_ops,
            phase_inputs,
            make_worker,
            &|worker: &Worker, slot_inputs: &mut Vec<String>, _slot: usize| {
                let (Some(id_token), Some(secret)) =
                    (slot_inputs.as_slice().first(), slot_inputs.get(1))
                else {
                    return false;
                };
                let (status, body) = worker.post_token(&format!(
                    "grant_type={TOKEN_EXCHANGE_GRANT}\
                     &subject_token_type=urn:ietf:params:oauth:token-type:id_token\
                     &actor_token_type=urn:openid:params:token-type:device-secret\
                     &subject_token={}&actor_token={}&audience={}",
                    urlencoding::encode(id_token),
                    urlencoding::encode(secret),
                    urlencoding::encode(issuer),
                ));
                status == 200 || {
                    eprintln!("native_sso error {status}: {body}");
                    false
                }
            },
        ),
    }
}
