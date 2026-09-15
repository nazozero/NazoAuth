//! Process-level evidence for the token-issuance simplification: a real
//! `nazoauth server` process serves a provisioned tenant, and repeated
//! `/token` requests prove the generic endpoint no longer restores stored
//! responses while PostgreSQL remains the single-use authority.
//!
//! Without `NAZO_TEST_DATABASE_URL`/`DATABASE_URL` and
//! `NAZO_TEST_VALKEY_URL`/`VALKEY_URL` the tests skip so plain `cargo test`
//! stays hermetic; in CI their absence is a hard failure.

use std::{
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Barrier,
    time::{Duration, Instant},
};

use base64::Engine as _;
use chrono::Utc;
use diesel::sql_types::{Nullable, Text as SqlText};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection as _,
};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantId};
use nazo_postgres::{
    TenantBoundaryDefinition, TenantDirectoryRepository, TenantProvisioningRequest, create_pool,
    run_pending_migrations,
};
use uuid::Uuid;

const READINESS_WINDOW: Duration = Duration::from_secs(30);
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const DEPLOYMENT_ID: &str = "t1-issuance-simplification";
const STATE_EPOCH: &str = "0198f7d1-0000-7000-8000-000000000002";
const MIGRATION_RUNTIME_ROLE: &str = "nazoauth_t1_issuance_runtime";
const CLIENT_SECRET_PEPPER: &str = "t1-issuance-client-secret-pepper-00000000";

fn test_databases() -> Option<(String, String)> {
    let database = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    let valkey = std::env::var("NAZO_TEST_VALKEY_URL")
        .or_else(|_| std::env::var("VALKEY_URL"))
        .ok();
    if (database.is_none() || valkey.is_none()) && std::env::var_os("CI").is_some() {
        panic!("CI issuance simplification tests require database and valkey URLs");
    }
    database.zip(valkey)
}

fn with_database_name(database_url: &str, name: &str) -> String {
    let separator = database_url.rfind('/').expect("database URL has a path");
    format!("{}/{}", &database_url[..separator], name)
}

fn temporary_directory(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "nazoauth-issuance-{tag}-{}",
        Uuid::now_v7().simple()
    ));
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

fn server_config_yaml(port: u16, database_url: &str, valkey_url: &str, data_dir: &Path) -> String {
    format!(
        r#"BIND: "127.0.0.1:{port}"
DATA_DIR: "{}"
DEPLOYMENT_ID: "{DEPLOYMENT_ID}"
DATABASE_URL: "{database_url}"
VALKEY_URL: "{valkey_url}"
VALKEY_STATE_EPOCH: "{STATE_EPOCH}"
VALKEY_COMMAND_TIMEOUT_MS: 1000
ISSUER: "http://127.0.0.1:{port}"
TRANSPORT_MODE: "trusted-proxy"
TRUSTED_PROXY_CIDRS: "127.0.0.1/32"
MTLS_CERTIFICATE_SOURCE: "rfc9440"
CLIENT_IP_HEADER_MODE: "x-forwarded-for"
CLIENT_SECRET_PEPPER: "{CLIENT_SECRET_PEPPER}"
COOKIE_SECURE: true
SESSION_COOKIE_NAME: "t1_session"
CSRF_COOKIE_NAME: "t1_csrf"
DEFAULT_AUDIENCE: "resource://t1"
SUBJECT_TYPE: "public"
SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE: false
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
    "COOKIE_SECURE",
    "SESSION_COOKIE_NAME",
    "CSRF_COOKIE_NAME",
    "DEFAULT_AUDIENCE",
    "SUBJECT_TYPE",
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

/// Raw synchronous HTTP/1.1 exchange against the real dispatcher. Returns
/// (status, headers, body).
fn http_request(
    port: u16,
    host: &str,
    method: &str,
    path: &str,
    body: Option<String>,
    extra_headers: &[(&str, &str)],
) -> (u16, String, String) {
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("test client should connect");
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
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
        .expect("request should write");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("response should read to end");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .map(|(head, body)| (head.to_owned(), body.to_owned()))
        .unwrap_or_else(|| (text.clone(), String::new()));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    (status, head, body)
}

fn http_status(
    port: u16,
    host: &str,
    method: &str,
    path: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> u16 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        http_request(port, host, method, path, body, headers)
    })) {
        Ok((status, _, _)) => status,
        Err(_) => 0,
    }
}

fn post_token(
    port: u16,
    host: &str,
    form: &str,
    extra_headers: &[(&str, &str)],
) -> (u16, String, String) {
    http_request(
        port,
        host,
        "POST",
        "/token",
        Some(form.to_owned()),
        extra_headers,
    )
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    let name = name.to_ascii_lowercase();
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().eq_ignore_ascii_case(&name)).then(|| value.trim())
    })
}

fn provisioning_request(slug: &str, host: &str) -> TenantProvisioningRequest {
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
            issuer: format!("https://{host}"),
            external_host: host.to_owned(),
        },
    }
}

/// Isolated database + migration install chain + running server + one routed
/// tenant. Returns everything the test body needs.
struct IssuanceFixture {
    server: ServerProcess,
    isolated_url: String,
    host: String,
    tenant: TenantContext,
}

async fn start_issuance_fixture(
    database_url: &str,
    valkey_url: &str,
    slug: &str,
) -> IssuanceFixture {
    let database_name = format!("issuance_{}_{}", slug, Uuid::now_v7().simple());
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

    let bootstrap_dir = temporary_directory("bootstrap");
    let bootstrap_config = bootstrap_dir.join(".env.yaml");
    write_config(
        &bootstrap_config,
        &server_config_yaml(free_port(), &isolated_url, valkey_url, &bootstrap_dir),
    );
    run_cli("migrate", &bootstrap_config);

    let process_dir = temporary_directory("server");
    let port = free_port();
    let config = process_dir.join(".env.yaml");
    write_config(
        &config,
        &server_config_yaml(port, &isolated_url, valkey_url, &process_dir),
    );
    let mut server = spawn_server(&config, port);
    server.wait_until_ready("127.0.0.1");

    let pool = create_pool(isolated_url.clone(), 4).expect("directory pool should build");
    let repository = TenantDirectoryRepository::new(pool);
    let revision = repository
        .current_revision()
        .await
        .expect("directory revision should read");
    let host = format!("{slug}.example");
    let request = provisioning_request(slug, &host);
    let tenant = request.binding.tenant;
    repository
        .provision_tenant_binding(revision, request)
        .await
        .expect("tenant should provision");

    let started = Instant::now();
    loop {
        if http_status(port, &host, "GET", DISCOVERY_PATH, None, &[]) == 200 {
            break;
        }
        assert!(
            started.elapsed() < READINESS_WINDOW,
            "tenant {host} did not route within the convergence window"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    IssuanceFixture {
        server,
        isolated_url,
        host,
        tenant,
    }
}

impl Drop for IssuanceFixture {
    fn drop(&mut self) {
        let _ = self.server.child.kill();
        let _ = self.server.child.wait();
        if let Ok(log) = std::fs::read_to_string(&self.server.log_path) {
            println!("--- server log ---\n{log}");
        }
    }
}

async fn sql(connection: &mut AsyncPgConnection, statement: &str) {
    diesel::sql_query(statement.to_owned())
        .execute(connection)
        .await
        .unwrap_or_else(|error| panic!("statement failed: {error}\n{statement}"));
}

/// Confidential client allowed to run `client_credentials` (the grant rejects
/// public clients) — authenticated with `client_secret_basic`.
async fn seed_confidential_client(
    connection: &mut AsyncPgConnection,
    tenant: &TenantContext,
    client_id: &str,
    secret: &str,
) {
    sql(
        connection,
        &format!(
            "INSERT INTO oauth_clients (                tenant_id, realm_id, organization_id, client_id, client_name, client_type,                redirect_uris, scopes, allowed_audiences, grant_types, token_endpoint_auth_method,                client_secret_hash,                tls_client_auth_subject_dn, require_dpop_bound_tokens, require_mtls_bound_tokens,                tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip, tls_client_auth_san_email,                allow_client_assertion_audience_array, allow_client_assertion_endpoint_audience,                require_par_request_object, is_active, security_policy, post_logout_redirect_uris,                backchannel_logout_session_required)             VALUES ('{}','{}','{}','{client_id}','T01 client','confidential','[]','[\"api:read\"]','[\"resource://t1\"]',                '[\"client_credentials\"]','client_secret_basic',                '{}',                NULL,false,false,'[]','[]','[]','[]',false,false,false,true,                '{{\"version\":1,\"assurance\":\"baseline\",\"require_signed_authorization_request\":false,\"require_signed_authorization_response\":false,\"require_signed_introspection_response\":false,\"session_management\":false,\"allow_cross_device_flows\":true,\"allow_confidential_oidc_without_pkce\":false}}',                '[]',false)",
            tenant.tenant_id.as_uuid(),
            tenant.realm_id.as_uuid(),
            tenant.organization_id.as_uuid(),
            client_secret_hash(secret),
        ),
    )
    .await;
}

/// `client-secret-v1:{salt}:{digest}` — the same persisted format the server
/// verifies, computed with the fixture's configured pepper.
fn client_secret_hash(secret: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let salt = Uuid::now_v7().simple().to_string();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(CLIENT_SECRET_PEPPER.as_bytes())
        .expect("HMAC accepts any key");
    mac.update(salt.as_bytes());
    mac.update(b":");
    mac.update(secret.as_bytes());
    format!(
        "client-secret-v1:{salt}:{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// Public client allowed to run the device grant.
async fn seed_public_client(
    connection: &mut AsyncPgConnection,
    tenant: &TenantContext,
    client_id: &str,
) {
    sql(
        connection,
        &format!(
            "INSERT INTO oauth_clients (\
                tenant_id, realm_id, organization_id, client_id, client_name, client_type,\
                redirect_uris, scopes, allowed_audiences, grant_types, token_endpoint_auth_method,\
                tls_client_auth_subject_dn, require_dpop_bound_tokens, require_mtls_bound_tokens,\
                tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip, tls_client_auth_san_email,\
                allow_client_assertion_audience_array, allow_client_assertion_endpoint_audience,\
                require_par_request_object, is_active, security_policy, post_logout_redirect_uris,\
                backchannel_logout_session_required)\
             VALUES ('{}','{}','{}','{client_id}','T01 client','public','[]','[\"openid\"]','[\"resource://t1\"]',\
                '[\"client_credentials\",\"urn:ietf:params:oauth:grant-type:device_code\",\"refresh_token\"]','none',\
                NULL,false,false,'[]','[]','[]','[]',false,false,false,true,\
                '{{\"version\":1,\"assurance\":\"baseline\",\"require_signed_authorization_request\":false,\"require_signed_authorization_response\":false,\"require_signed_introspection_response\":false,\"session_management\":false,\"allow_cross_device_flows\":true,\"allow_confidential_oidc_without_pkce\":false}}',\
                '[]',false)",
            tenant.tenant_id.as_uuid(),
            tenant.realm_id.as_uuid(),
            tenant.organization_id.as_uuid(),
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
             VALUES ('{user_id}','{}','{}','{}','issuance-user-{user_id}',\
                'issuance-user-{user_id}@example.test','issuance-test-password-hash',\
                TRUE, FALSE, TRUE, 'user', 0)",
            tenant.tenant_id.as_uuid(),
            tenant.realm_id.as_uuid(),
            tenant.organization_id.as_uuid(),
        ),
    )
    .await;
}

#[derive(diesel::QueryableByName)]
struct IssuanceRow {
    #[diesel(sql_type = Nullable<diesel::sql_types::Bytea>)]
    single_use_key_blake3: Option<Vec<u8>>,
    #[diesel(sql_type = SqlText)]
    access_token_jti: String,
}

async fn issuance_rows(
    connection: &mut AsyncPgConnection,
    tenant: &TenantContext,
) -> Vec<IssuanceRow> {
    diesel::sql_query(format!(
        "SELECT single_use_key_blake3, access_token_jti FROM oauth_token_issuances \
         WHERE tenant_id = '{}' ORDER BY access_token_jti",
        tenant.tenant_id.as_uuid()
    ))
    .load::<IssuanceRow>(connection)
    .await
    .expect("issuance rows should query")
}

async fn issuance_column_names(connection: &mut AsyncPgConnection) -> Vec<String> {
    #[derive(diesel::QueryableByName)]
    struct ColumnName {
        #[diesel(sql_type = SqlText)]
        column_name: String,
    }
    diesel::sql_query(
        "SELECT column_name::text AS column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'oauth_token_issuances' \
         ORDER BY ordinal_position",
    )
    .load::<ColumnName>(connection)
    .await
    .expect("column list should query")
    .into_iter()
    .map(|row| row.column_name)
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_idempotency_key_issues_fresh_tokens_through_the_real_dispatcher() {
    let Some((database_url, valkey_url)) = test_databases() else {
        return;
    };
    let fixture = start_issuance_fixture(&database_url, &valkey_url, "fresh").await;
    let mut connection = AsyncPgConnection::establish(&fixture.isolated_url)
        .await
        .expect("isolated database should connect");
    seed_confidential_client(
        &mut connection,
        &fixture.tenant,
        "fresh-client",
        "fresh-client-secret",
    )
    .await;

    // The issuance table contract is exactly the simplified eight columns —
    // no response envelope, digest, or saga columns survive.
    assert_eq!(
        issuance_column_names(&mut connection).await,
        vec![
            "issuance_id",
            "tenant_id",
            "client_id",
            "user_id",
            "single_use_key_blake3",
            "access_token_jti",
            "access_token_expires_at",
            "retain_until",
        ],
        "oauth_token_issuances must carry only the simplified columns"
    );

    // TOK-01/TOK-11: the same inbound Idempotency-Key on two requests yields
    // two independent, fully-formed token responses.
    // `client_id` in the body alongside HTTP Basic counts as a second
    // authentication method — the dispatcher rejects that combination.
    let form = "grant_type=client_credentials";
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("fresh-client:fresh-client-secret")
    );
    let idempotency_headers = [
        ("Idempotency-Key", "t1-repeated-key"),
        ("Authorization", basic.as_str()),
    ];
    let (status_a, head_a, body_a) = post_token(
        fixture.server.port,
        &fixture.host,
        form,
        &idempotency_headers,
    );
    let (status_b, head_b, body_b) = post_token(
        fixture.server.port,
        &fixture.host,
        form,
        &idempotency_headers,
    );

    for (status, head, body) in [(status_a, &head_a, &body_a), (status_b, &head_b, &body_b)] {
        assert_eq!(status, 200, "token request should succeed: {body}");
        assert_eq!(
            header_value(head, "cache-control"),
            Some("no-store"),
            "token response must be no-store: {head}"
        );
        assert_eq!(
            header_value(head, "pragma"),
            Some("no-cache"),
            "token response must carry the no-cache pragma: {head}"
        );
        assert!(
            header_value(head, "content-type")
                .is_some_and(|value| value.starts_with("application/json")),
            "token response must be JSON: {head}"
        );
    }
    let first: serde_json::Value =
        serde_json::from_str(&body_a).expect("first token response should parse");
    let second: serde_json::Value =
        serde_json::from_str(&body_b).expect("second token response should parse");
    for body in [&first, &second] {
        assert!(body["access_token"].is_string());
        assert_eq!(body["token_type"], "Bearer");
        assert!(body["expires_in"].is_number());
    }
    assert_ne!(
        first["access_token"], second["access_token"],
        "a repeated Idempotency-Key must never replay a stored response"
    );

    // TOK-05: both issuances are Fresh — NULL single-use keys, distinct JTIs.
    let rows = issuance_rows(&mut connection, &fixture.tenant).await;
    assert_eq!(
        rows.len(),
        2,
        "each request must persist its own issuance row"
    );
    assert!(
        rows.iter().all(|row| row.single_use_key_blake3.is_none()),
        "client_credentials issuance must not store a single-use key"
    );
    assert_ne!(
        rows[0].access_token_jti, rows[1].access_token_jti,
        "each response must carry its own committed access-token JTI"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_code_consumes_exactly_once_under_concurrent_polling() {
    let Some((database_url, valkey_url)) = test_databases() else {
        return;
    };
    let fixture = start_issuance_fixture(&database_url, &valkey_url, "device").await;
    let mut connection = AsyncPgConnection::establish(&fixture.isolated_url)
        .await
        .expect("isolated database should connect");
    seed_public_client(&mut connection, &fixture.tenant, "device-client").await;
    let user_id = Uuid::now_v7();
    seed_user(&mut connection, &fixture.tenant, user_id).await;

    // Seed an approved device authorization straight into the tenant-scoped
    // state store, exactly as the approval path would leave it.
    let tenant_valkey = nazo_valkey::ValkeyConnection::connect(
        &valkey_url,
        Duration::from_secs(1),
        DEPLOYMENT_ID,
        Uuid::parse_str(STATE_EPOCH).expect("state epoch parses"),
        fixture.tenant.tenant_id,
    )
    .await
    .expect("tenant valkey connection should open");
    let device_code = format!("t1-device-{}", Uuid::now_v7().simple());
    let approved = nazo_auth::DeviceAuthorizationState::Approved {
        payload: nazo_auth::DeviceAuthorizationPayload {
            client_id: "device-client".to_owned(),
            client_name: "T01 client".to_owned(),
            scopes: vec!["openid".to_owned()],
            resource_indicators: Vec::new(),
            authorization_details: serde_json::json!([]),
            interval_seconds: 5,
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        },
        approval: nazo_auth::DeviceAuthorizationApproval {
            user_id,
            subject: user_id.to_string(),
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            oidc_sid: None,
        },
        approved_at: Utc::now(),
    };
    let store = nazo_valkey::DeviceStore::new(&tenant_valkey);
    assert_eq!(
        store
            .create(&device_code, "T01USRCD", &approved, 600)
            .await
            .expect("approved device state should store"),
        nazo_valkey::DeviceCreateResult::Applied
    );

    // TOK-06/SEC-03: two concurrent polls against the same approved grant —
    // exactly one commits, the other loses the single-use fence.
    let form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code\
         &device_code={device_code}&client_id=device-client"
    );
    let barrier = std::sync::Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = barrier.clone();
        let form = form.clone();
        let host = fixture.host.clone();
        let port = fixture.server.port;
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            post_token(port, &host, &form, &[])
        }));
    }
    let responses: Vec<(u16, String, String)> = handles
        .into_iter()
        .map(|handle| handle.join().expect("polling thread should join"))
        .collect();
    let successes = responses
        .iter()
        .filter(|(status, _, _)| *status == 200)
        .count();
    let failures = responses
        .iter()
        .filter(|(status, _, body)| *status == 400 && body.contains("invalid_grant"))
        .count();
    assert_eq!(
        (successes, failures),
        (1, 1),
        "exactly one concurrent device poll may succeed: {responses:?}"
    );

    // The consumed grant keeps its fence row; a late retry still fails closed.
    let rows = issuance_rows(&mut connection, &fixture.tenant).await;
    assert_eq!(
        rows.len(),
        1,
        "the winning poll leaves exactly one issuance"
    );
    assert_eq!(
        rows[0].single_use_key_blake3.as_deref().map(<[u8]>::len),
        Some(32),
        "the consumed grant must retain its 32-byte single-use key"
    );
    let (retry_status, _, retry_body) = post_token(fixture.server.port, &fixture.host, &form, &[]);
    assert_eq!(
        retry_status, 400,
        "replaying the consumed device_code must fail: {retry_body}"
    );
    assert!(retry_body.contains("invalid_grant"));
    assert_eq!(
        issuance_rows(&mut connection, &fixture.tenant).await.len(),
        1,
        "the consumed grant must not mint a second issuance"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_device_grant_fails_closed_without_an_issuance_row() {
    let Some((database_url, valkey_url)) = test_databases() else {
        return;
    };
    let fixture = start_issuance_fixture(&database_url, &valkey_url, "expired").await;
    let mut connection = AsyncPgConnection::establish(&fixture.isolated_url)
        .await
        .expect("isolated database should connect");
    seed_public_client(&mut connection, &fixture.tenant, "expired-client").await;
    let user_id = Uuid::now_v7();
    seed_user(&mut connection, &fixture.tenant, user_id).await;

    let tenant_valkey = nazo_valkey::ValkeyConnection::connect(
        &valkey_url,
        Duration::from_secs(1),
        DEPLOYMENT_ID,
        Uuid::parse_str(STATE_EPOCH).expect("state epoch parses"),
        fixture.tenant.tenant_id,
    )
    .await
    .expect("tenant valkey connection should open");
    let device_code = format!("t1-expired-{}", Uuid::now_v7().simple());
    // The state-store entry is still alive while the grant deadline has
    // already passed — the commit fence must refuse it.
    let stale_approved = nazo_auth::DeviceAuthorizationState::Approved {
        payload: nazo_auth::DeviceAuthorizationPayload {
            client_id: "expired-client".to_owned(),
            client_name: "T01 client".to_owned(),
            scopes: vec!["openid".to_owned()],
            resource_indicators: Vec::new(),
            authorization_details: serde_json::json!([]),
            interval_seconds: 5,
            issued_at: Utc::now() - chrono::Duration::minutes(10),
            expires_at: Utc::now() - chrono::Duration::seconds(5),
        },
        approval: nazo_auth::DeviceAuthorizationApproval {
            user_id,
            subject: user_id.to_string(),
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            oidc_sid: None,
        },
        approved_at: Utc::now() - chrono::Duration::minutes(5),
    };
    let store = nazo_valkey::DeviceStore::new(&tenant_valkey);
    assert_eq!(
        store
            .create(&device_code, "T01XPRD", &stale_approved, 600)
            .await
            .expect("stale approved device state should store"),
        nazo_valkey::DeviceCreateResult::Applied
    );

    // TOK-09/TOK-10: the stale grant deadline fails closed at the endpoint,
    // leaves no issuance fact, and a late retry still cannot mint a token.
    let form = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code\
         &device_code={device_code}&client_id=expired-client"
    );
    let (status, _, body) = post_token(fixture.server.port, &fixture.host, &form, &[]);
    assert_eq!(status, 400, "the expired grant must fail: {body}");
    assert!(
        body.contains("expired_token"),
        "expected expired_token: {body}"
    );
    assert!(
        issuance_rows(&mut connection, &fixture.tenant)
            .await
            .is_empty(),
        "a rejected grant must not persist an issuance fact"
    );
    let (retry_status, _, retry_body) = post_token(fixture.server.port, &fixture.host, &form, &[]);
    assert_eq!(
        retry_status, 400,
        "a late retry against the stale grant still fails: {retry_body}"
    );
    assert!(retry_body.contains("expired_token"));
}
