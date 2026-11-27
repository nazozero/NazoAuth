//! The same authorization-code and refresh-rotation owner calls on both adapters.
//! Run through scripts/bench-rocksdb-postgres.py for process-tree CPU/PSS sampling.

use anyhow::{Context, Result, ensure};
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AuthorizationCodeClientAuthentication, AuthorizationCodeHolderEvidence, CommitTokenIssuance,
    CommitTokenIssuanceResult, DynamicRegistrationClientStore, NewRefreshToken,
    PreparedClientRegistration, RefreshContract, RefreshToken, RefreshTokenAuthenticationContext,
    RefreshTokenCommit, TokenIssuanceMode, TokenIssuedAuditFields, TokenPrincipalState,
    TokenRepositoryPort,
};
use nazo_identity::{
    TenantContext,
    ports::{NewUser, PasswordHashInput, RegistrationAccountRepositoryPort},
};
use nazo_rocksdb::RocksDb;
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use tokio::sync::Barrier;
use uuid::Uuid;

#[path = "../tests/support/clients.rs"]
mod clients;

struct Options {
    backend: String,
    path: Option<PathBuf>,
    flows: usize,
    concurrency: usize,
    warmup: usize,
}

fn options() -> Result<Options> {
    let mut options = Options {
        backend: String::new(),
        path: None,
        flows: 10_000,
        concurrency: 8,
        warmup: 16,
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(name) = arguments.next() {
        let value = arguments
            .next()
            .with_context(|| format!("missing value for {name}"))?;
        match name.as_str() {
            "--backend" => options.backend = value,
            "--rocksdb-path" => options.path = Some(value.into()),
            "--flows" => options.flows = value.parse()?,
            "--concurrency" => options.concurrency = value.parse()?,
            "--warmup-per-worker" => options.warmup = value.parse()?,
            _ => anyhow::bail!("unknown option {name}"),
        }
    }
    ensure!(
        matches!(options.backend.as_str(), "rocksdb" | "postgres"),
        "--backend must be rocksdb or postgres"
    );
    ensure!(
        options.flows > 0 && options.concurrency > 0 && options.concurrency <= options.flows,
        "flows must be positive and at least concurrency"
    );
    Ok(options)
}

struct Fixture {
    repository: Arc<dyn TokenRepositoryPort>,
    tenant: Uuid,
    client: Uuid,
    public_id: String,
    user: Uuid,
    subject: String,
    subject_hash: String,
}

async fn fixtures(options: &Options) -> Result<Vec<Arc<Fixture>>> {
    let (repository, accounts, registrations): (
        Arc<dyn TokenRepositoryPort>,
        Arc<dyn RegistrationAccountRepositoryPort>,
        Arc<dyn DynamicRegistrationClientStore>,
    ) = match options.backend.as_str() {
        "rocksdb" => {
            let path = options
                .path
                .as_ref()
                .context("--rocksdb-path is required")?;
            let store = Arc::new(RocksDb::open(path)?);
            (store.clone(), store.clone(), store)
        }
        "postgres" => {
            let url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
            nazo_postgres::run_pending_migrations(&url).await?;
            let pool = nazo_postgres::create_pool(url, options.concurrency)?;
            (
                Arc::new(nazo_postgres::TokenIssuanceRepository::new(pool.clone())),
                Arc::new(nazo_postgres::UserRepository::new(pool.clone())),
                Arc::new(nazo_postgres::OAuthClientRepository::new(pool)),
            )
        }
        _ => unreachable!(),
    };
    let context = TenantContext::default_system();
    let name = format!("bench-{}", Uuid::new_v4().simple());
    let client = clients::client(context, &name);
    let client = registrations
        .insert(
            PreparedClientRegistration {
                tenant: context,
                registration: client.registration,
                require_mtls_bound_tokens: false,
                issued_secret: None::<String>.into(),
                client_secret_hash: Some("client-secret-v1:benchmark:benchmark".into()),
                registration_access_token_blake3: None,
            },
            "benchmark-source-hash",
        )
        .await
        .map_err(|error| anyhow::anyhow!("registration failed: {error:?}"))?;
    let mut fixtures = Vec::with_capacity(options.concurrency);
    // Each worker has one in-flight user flow. Shared-client concurrency must
    // not turn the normal per-user live-family cap into artificial reuse errors.
    for worker in 0..options.concurrency {
        let username = format!("{name}-{worker}");
        let user = accounts
            .create_user(NewUser {
                tenant: context,
                email: format!("{username}@example.test"),
                username,
                password_hash: PasswordHashInput::new("benchmark-verifier")?,
                email_verified: true,
            })
            .await?
            .id();
        fixtures.push(Arc::new(Fixture {
            repository: repository.clone(),
            tenant: context.tenant_id.as_uuid(),
            client: client.id,
            public_id: client.registration.client_id.clone(),
            user,
            subject: user.to_string(),
            subject_hash: blake3::hash(user.as_bytes()).to_hex().to_string(),
        }));
    }
    Ok(fixtures)
}

impl Fixture {
    fn input(
        &self,
        family: Uuid,
        mode: TokenIssuanceMode,
        refresh: RefreshTokenCommit,
    ) -> CommitTokenIssuance {
        CommitTokenIssuance {
            authorization_id: Some(family),
            principal_state: TokenPrincipalState {
                client_epoch: 0,
                user_epoch: Some(0),
                subject_bound: false,
            },
            subject: self.subject.clone(),
            issuance_id: Uuid::now_v7(),
            tenant_id: self.tenant,
            client_id: self.client,
            user_id: Some(self.user),
            mode,
            access_token_jti: Uuid::new_v4().to_string(),
            access_token_expires_at: Timestamp::now().as_second() + 300,
            refresh_token: Some(refresh),
            native_sso_source: None,
            audit_fields: TokenIssuedAuditFields {
                client_id: self.public_id.clone(),
                subject_hash: self.subject_hash.clone(),
                scope: "openid".into(),
                audience: vec!["resource://default".into()],
            },
        }
    }

    fn member(&self, family: Uuid, raw: String, source: Option<&RefreshToken>) -> NewRefreshToken {
        let now = Timestamp::now();
        NewRefreshToken {
            raw_token: raw,
            member_id: Uuid::now_v7(),
            tenant_id: self.tenant,
            family_id: family,
            rotated_from_id: source.map(|s| s.id),
            lost_response_retry: None,
            client_id: self.client,
            user_id: Some(self.user),
            audiences: vec!["resource://default".into()],
            issued_at: now,
            expires_at: now + SignedDuration::from_secs(900),
            id_token_sid: Some(family.to_string()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
            client_attestation_jkt: None,
        }
    }

    async fn flow(&self) -> Result<Timing> {
        let started = Instant::now();
        let now = Timestamp::now();
        let family = Uuid::now_v7();
        let raw = Uuid::new_v4().to_string();
        let initial = self.input(
            family,
            TokenIssuanceMode::AuthorizationCode {
                code_identity: format!("authorization_code:v2:{}", Uuid::new_v4()),
                grant_expires_at: now + SignedDuration::from_secs(120),
                holder: AuthorizationCodeHolderEvidence::from_verified_requirements(
                    AuthorizationCodeClientAuthentication::Authenticated,
                    Some("benchmark-verified-pkce-s256".into()),
                    None,
                    None,
                    None,
                )
                .context("invalid benchmark holder requirements")?,
            },
            RefreshTokenCommit::IssueNew {
                token: self.member(family, raw.clone(), None),
                contract: RefreshContract {
                    subject: self.subject.clone(),
                    scopes: vec!["openid".into()],
                    audiences: vec!["resource://default".into()],
                    authorization_details: json!([]),
                    authentication_context: RefreshTokenAuthenticationContext {
                        version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
                        issuer: "https://benchmark.example.test".into(),
                        audience: self.public_id.clone(),
                        auth_time: now.as_second() - 10,
                        amr: vec!["pwd".into()],
                        oidc_sid: None,
                        acr: None,
                        userinfo_claim_requests: Default::default(),
                        id_token_claim_requests: Default::default(),
                    },
                },
            },
        );
        let phase = Instant::now();
        ensure!(
            self.repository.commit_token_issuance(initial).await?
                == CommitTokenIssuanceResult::Committed,
            "authorization-code commit rejected"
        );
        let code = phase.elapsed().as_nanos() as u64;
        let phase = Instant::now();
        let snapshot = self
            .repository
            .refresh_token_snapshot(self.tenant, &raw, self.client, Timestamp::now(), true)
            .await?
            .context("committed refresh member missing")?;
        ensure!(
            snapshot.prepared_subject.is_some(),
            "OIDC subject projection missing"
        );
        ensure!(
            snapshot.successor?.is_none(),
            "fresh member already rotated"
        );
        let lookup = phase.elapsed().as_nanos() as u64;
        let rotation = self.input(
            family,
            TokenIssuanceMode::Fresh,
            RefreshTokenCommit::UseExisting {
                authority: snapshot.presented.authority(),
                rotation: Some(self.member(
                    family,
                    Uuid::new_v4().to_string(),
                    Some(&snapshot.presented),
                )),
            },
        );
        let phase = Instant::now();
        ensure!(
            self.repository.commit_token_issuance(rotation).await?
                == CommitTokenIssuanceResult::Committed,
            "refresh rotation commit rejected"
        );
        Ok(Timing {
            flow: started.elapsed().as_nanos() as u64,
            code,
            lookup,
            refresh: phase.elapsed().as_nanos() as u64,
        })
    }
}

struct Timing {
    flow: u64,
    code: u64,
    lookup: u64,
    refresh: u64,
}

fn distribution(mut samples: Vec<u64>) -> Value {
    samples.sort_unstable();
    if samples.is_empty() {
        return json!({"count":0});
    }
    let percentile =
        |per_mille: usize| samples[(samples.len() * per_mille).div_ceil(1000) - 1] as f64 / 1000.0;
    json!({"count":samples.len(), "p50_us":percentile(500), "p95_us":percentile(950), "p99_us":percentile(990), "p99_9_us":percentile(999)})
}

fn emit(value: Value) -> Result<()> {
    println!("{value}");
    io::stdout().flush()?;
    Ok(())
}

// The launcher samples /proc before releasing each boundary. EOF also permits
// standalone execution when process sampling is not needed.
fn monitor_boundary() -> Result<()> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let options = options()?;
    let fixtures = fixtures(&options).await?;
    let mut warmup = tokio::task::JoinSet::new();
    for fixture in &fixtures {
        let fixture = fixture.clone();
        let iterations = options.warmup;
        warmup.spawn(async move {
            for _ in 0..iterations {
                fixture.flow().await?;
            }
            Result::<()>::Ok(())
        });
    }
    while let Some(result) = warmup.join_next().await {
        result??;
    }
    let barrier = Arc::new(Barrier::new(options.concurrency + 1));
    let mut workers = tokio::task::JoinSet::new();
    for (worker, fixture) in fixtures.iter().cloned().enumerate() {
        let barrier = barrier.clone();
        let concurrency = options.concurrency;
        let flows = options.flows;
        workers.spawn(async move {
            barrier.wait().await;
            let mut timings = Vec::new();
            let mut errors = 0;
            let mut first_error = None;
            for _ in (worker..flows).step_by(concurrency) {
                match fixture.flow().await {
                    Ok(timing) => timings.push(timing),
                    Err(error) => {
                        errors += 1;
                        first_error.get_or_insert_with(|| error.to_string());
                    }
                }
            }
            (timings, errors, first_error)
        });
    }
    emit(json!({"phase":"ready", "backend":options.backend, "pid":std::process::id()}))?;
    monitor_boundary()?;
    let started = Instant::now();
    barrier.wait().await;
    let mut timings = Vec::with_capacity(options.flows);
    let mut errors = 0;
    let mut first_error = None;
    while let Some(result) = workers.join_next().await {
        let (mut worker, failed, error) = result?;
        timings.append(&mut worker);
        errors += failed;
        first_error = first_error.or(error);
    }
    let seconds = started.elapsed().as_secs_f64();
    emit(json!({"phase":"measured", "elapsed_seconds":seconds}))?;
    monitor_boundary()?;
    emit(json!({
        "phase":"result", "backend":options.backend, "workload":"authorization_code_and_refresh_rotation", "runtime_threads":4,
        "concurrency":options.concurrency, "warmup_flows":options.warmup * options.concurrency,
        "requested_flows":options.flows, "completed_flows":timings.len(), "errors":errors, "first_error":first_error,
        "elapsed_seconds":seconds, "successful_flows_per_second":timings.len() as f64 / seconds,
        "successful_commits_per_second":2.0 * timings.len() as f64 / seconds,
        "flow_latency":distribution(timings.iter().map(|t| t.flow).collect()),
        "authorization_code_commit_latency":distribution(timings.iter().map(|t| t.code).collect()),
        "refresh_snapshot_latency":distribution(timings.iter().map(|t| t.lookup).collect()),
        "refresh_rotation_commit_latency":distribution(timings.iter().map(|t| t.refresh).collect()),
    }))?;
    ensure!(errors == 0, "benchmark flows failed");
    Ok(())
}
