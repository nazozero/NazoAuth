use super::{
    config::{AuditAnchorMode, AuditAnchorPreflightConfig, AuditAnchorWorkerConfig},
    preflight::{AuditAnchorPreflight, validate_health},
    protocol::{
        AnchorReceipt, CHECKPOINT_SCHEMA_VERSION, RECEIPT_SCHEMA_VERSION, ReceiptVerdict,
        batch_body, batch_expectation, encode_hash, genesis_body, genesis_expectation,
        receipt_signing_body, sign_body, verify_receipt,
    },
    status::{AnchorCheckpoint, age_seconds, duration_seconds},
    transport::{AnchorPushError, PushOutcome, send_batch, send_genesis_checkpoint},
    worker::{
        AuditAnchorRepository, IterationOutcome, batch_lag_seconds, retry_delay, run_iteration,
    },
};
use chrono::{Duration as ChronoDuration, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use nazo_crypto::ed25519::VerifyingKey;
use nazo_identity::ports::{RepositoryError, RepositoryFuture};
use nazo_persistence::{
    SecurityAuditAnchorHealth, SecurityAuditBatch, SecurityAuditBatchAck, SecurityAuditBatchClaim,
    SecurityAuditBatchLease, SecurityAuditOutboxDelivery, audit_chain::security_audit_batch_digest,
};
use nazo_postgres::AuditLedgerRepository;
use serde_json::{Value, json};
use std::{collections::VecDeque, sync::Mutex, time::Duration};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;
use uuid::Uuid;

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn test_verify_key() -> VerifyingKey {
    VerifyingKey::from_bytes(&test_signing_key().verifying_key().to_bytes()).unwrap()
}

fn valid_worker_config(endpoint: Url) -> AuditAnchorWorkerConfig {
    AuditAnchorWorkerConfig {
        preflight: required_config(),
        endpoint,
        auth_secret: b"anchor-secret-that-is-long-enough".to_vec(),
        receipt_verify_key: test_verify_key(),
        ca_bundle_pem: None,
        poll_interval: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        batch_size: 1,
        max_envelope_bytes: 1024 * 1024,
        lock_timeout_seconds: 1,
    }
}

fn health_snapshot() -> SecurityAuditAnchorHealth {
    SecurityAuditAnchorHealth {
        head_sequence: 7,
        head_hash: vec![2; 32],
        pending_exists: false,
        pending_estimate: 0,
        pending_orphan_exists: false,
        oldest_pending_occurred_at: None,
        last_exported_sequence: Some(7),
        last_exported_hash: Some(vec![2; 32]),
        last_exported_occurred_at: Some(Utc::now() - ChronoDuration::seconds(2)),
        last_exported_at: Some(Utc::now() - ChronoDuration::seconds(1)),
        deployment_id: Some("deployment-1".to_owned()),
        observed_at: Some(Utc::now()),
        batch: None,
    }
}

fn delivery(sequence: i64) -> SecurityAuditOutboxDelivery {
    SecurityAuditOutboxDelivery {
        event_id: Uuid::from_u128(sequence as u128),
        sequence,
        event_type: "admin_user_updated".to_owned(),
        event_category: "administration".to_owned(),
        payload_canonical: "{\"user_id\":\"user-1\"}".to_owned(),
        occurred_at: Utc::now() - ChronoDuration::seconds(4),
        previous_hash: vec![sequence as u8; 32],
        event_hash: vec![(sequence + 1) as u8; 32],
    }
}

fn batch(deliveries: Vec<SecurityAuditOutboxDelivery>) -> SecurityAuditBatch {
    let first = deliveries.first().expect("batch has events");
    let last = deliveries.last().expect("batch has events");
    let event_hashes: Vec<[u8; 32]> = deliveries
        .iter()
        .map(|delivery| delivery.event_hash.as_slice().try_into().unwrap())
        .collect();
    let digest = security_audit_batch_digest(
        "deployment-1",
        first.sequence,
        last.sequence,
        deliveries.len() as i64,
        &first.previous_hash,
        &last.event_hash,
        &event_hashes,
    );
    SecurityAuditBatch {
        generation: 3,
        first_sequence: first.sequence,
        last_sequence: last.sequence,
        previous_hash: first.previous_hash.clone(),
        last_hash: last.event_hash.clone(),
        digest: digest.to_vec(),
        attempts: 0,
        deliveries,
    }
}

/// Build a signed receipt body exactly as the reference receiver would.
#[allow(clippy::too_many_arguments)]
fn signed_receipt(
    status: &str,
    kind: &str,
    deployment_id: &str,
    first_sequence: i64,
    last_sequence: i64,
    event_count: i64,
    last_hash: String,
    batch_digest: String,
    reject_reason: Option<&str>,
    permanent: bool,
    signing_key: &SigningKey,
) -> Vec<u8> {
    let mut receipt = AnchorReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
        checkpoint_kind: kind.to_owned(),
        status: status.to_owned(),
        deployment_id: deployment_id.to_owned(),
        first_sequence,
        last_sequence,
        event_count,
        last_hash,
        batch_digest,
        received_at: Utc::now(),
        reject_reason: reject_reason.map(str::to_owned),
        permanent,
        signature: String::new(),
    };
    let body = receipt_signing_body(&receipt).expect("receipt serializes");
    receipt.signature = encode_hash(&signing_key.sign(&body).to_bytes());
    serde_json::to_vec(&receipt).expect("receipt serializes")
}

fn accepted_batch_receipt(batch: &SecurityAuditBatch) -> Vec<u8> {
    signed_receipt(
        "accepted",
        "batch",
        "deployment-1",
        batch.first_sequence,
        batch.last_sequence,
        batch.event_count(),
        encode_hash(&batch.last_hash),
        encode_hash(&batch.digest),
        None,
        false,
        &test_signing_key(),
    )
}

fn accepted_genesis_receipt(head_hash: &[u8]) -> Vec<u8> {
    let expectation = genesis_expectation("deployment-1", head_hash);
    signed_receipt(
        "accepted",
        "genesis",
        "deployment-1",
        0,
        0,
        0,
        expectation.last_hash,
        expectation.batch_digest,
        None,
        false,
        &test_signing_key(),
    )
}

#[derive(Default)]
struct ScriptedRepository {
    health: Mutex<VecDeque<Result<SecurityAuditAnchorHealth, RepositoryError>>>,
    observations: Mutex<VecDeque<Result<(), RepositoryError>>>,
    genesis_records: Mutex<VecDeque<Result<(), RepositoryError>>>,
    claims: Mutex<VecDeque<Result<SecurityAuditBatchClaim, RepositoryError>>>,
    acknowledgements: Mutex<VecDeque<Result<(), RepositoryError>>>,
    failures: Mutex<Vec<(i64, String, bool)>>,
    acked: Mutex<Vec<SecurityAuditBatchAck>>,
    fail_call_fails: bool,
}

impl ScriptedRepository {
    fn with_health(
        health: Result<SecurityAuditAnchorHealth, RepositoryError>,
        claim: Result<SecurityAuditBatchClaim, RepositoryError>,
    ) -> Self {
        Self {
            health: Mutex::new(VecDeque::from([health])),
            claims: Mutex::new(VecDeque::from([claim])),
            ..Self::default()
        }
    }

    fn with_acknowledgement(self, acknowledgement: Result<(), RepositoryError>) -> Self {
        self.acknowledgements
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .push_back(acknowledgement);
        self
    }

    fn with_observation(self, observation: Result<(), RepositoryError>) -> Self {
        self.observations
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .push_back(observation);
        self
    }

    fn with_genesis_record(self, record: Result<(), RepositoryError>) -> Self {
        self.genesis_records
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .push_back(record);
        self
    }

    fn with_fail_failure(mut self) -> Self {
        self.fail_call_fails = true;
        self
    }

    fn failures(&self) -> Vec<(i64, String, bool)> {
        self.failures
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .clone()
    }

    fn acked(&self) -> Vec<SecurityAuditBatchAck> {
        self.acked
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .clone()
    }
}

impl AuditAnchorRepository for ScriptedRepository {
    fn check_available(&self) -> RepositoryFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn anchor_health(&self) -> RepositoryFuture<'_, SecurityAuditAnchorHealth> {
        Box::pin(async move {
            self.health
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(RepositoryError::Unexpected(
                        "health script exhausted".to_owned(),
                    ))
                })
        })
    }

    fn observe_anchor<'a>(&'a self, _deployment_id: &'a str) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.observations
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .pop_front()
                .unwrap_or(Ok(()))
        })
    }

    fn record_genesis<'a>(
        &'a self,
        _deployment_id: &'a str,
        _head_hash: &'a [u8],
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.genesis_records
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .pop_front()
                .unwrap_or(Ok(()))
        })
    }

    fn claim_batch<'a>(
        &'a self,
        _deployment_id: &'a str,
        _limit: i64,
        _max_envelope_bytes: i64,
        _lock_timeout_seconds: i32,
    ) -> RepositoryFuture<'a, SecurityAuditBatchClaim> {
        Box::pin(async move {
            self.claims
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(RepositoryError::Unexpected(
                        "claim script exhausted".to_owned(),
                    ))
                })
        })
    }

    fn ack_batch<'a>(&'a self, ack: SecurityAuditBatchAck) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let result = self
                .acknowledgements
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .pop_front()
                .unwrap_or(Ok(()));
            if result.is_ok() {
                self.acked
                    .lock()
                    .expect("scripted repository mutex is not poisoned")
                    .push(ack);
            }
            result
        })
    }

    fn fail_batch<'a>(
        &'a self,
        generation: i64,
        _available_at: chrono::DateTime<Utc>,
        last_error: &'a str,
        blocked: bool,
    ) -> RepositoryFuture<'a, ()> {
        let last_error = last_error.to_owned();
        Box::pin(async move {
            self.failures
                .lock()
                .expect("scripted repository mutex is not poisoned")
                .push((generation, last_error, blocked));
            if self.fail_call_fails {
                Err(RepositoryError::Unexpected("fail_batch failed".to_owned()))
            } else {
                Ok(())
            }
        })
    }
}

fn iteration_config(endpoint: Url) -> AuditAnchorWorkerConfig {
    let mut config = valid_worker_config(endpoint);
    config.poll_interval = Duration::from_millis(1);
    config
}

fn genesis_snapshot() -> SecurityAuditAnchorHealth {
    let mut snapshot = health_snapshot();
    snapshot.head_sequence = 0;
    snapshot.head_hash = vec![9; 32];
    snapshot.last_exported_sequence = None;
    snapshot.last_exported_hash = None;
    snapshot.last_exported_occurred_at = None;
    snapshot.last_exported_at = None;
    snapshot
}

fn repository_error(message: &str) -> RepositoryError {
    RepositoryError::Unexpected(message.to_owned())
}

async fn local_anchor_endpoint_with_body(
    status: u16,
    response_body: Vec<u8>,
) -> (Url, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback address is available");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request arrives");
        let request = read_anchor_request(&mut stream).await;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response_body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("response headers are writable");
        stream
            .write_all(&response_body)
            .await
            .expect("response body is writable");
        request
    });
    (
        Url::parse(&format!("http://{address}/checkpoint")).unwrap(),
        task,
    )
}

async fn local_anchor_endpoint(status: u16) -> (Url, tokio::task::JoinHandle<Vec<u8>>) {
    local_anchor_endpoint_with_body(status, Vec::new()).await
}

async fn local_disconnect_endpoint() -> (Url, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback address is available");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request arrives");
        stream
            .shutdown()
            .await
            .expect("connection can close without an HTTP response");
    });
    (
        Url::parse(&format!("http://{address}/checkpoint")).unwrap(),
        task,
    )
}

async fn read_anchor_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    loop {
        let mut chunk = [0_u8; 256];
        let size = stream.read(&mut chunk).await.expect("request is readable");
        if size == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..size]);
        let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim().to_owned())
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        if request.len() >= header_end + 4 + content_length {
            break;
        }
    }
    request
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("test HTTP client builds")
}

fn required_config() -> AuditAnchorPreflightConfig {
    AuditAnchorPreflightConfig {
        mode: AuditAnchorMode::Required,
        deployment_id: "deployment-1".to_owned(),
        freshness: Duration::from_secs(60),
        max_lag: Duration::from_secs(300),
    }
}

#[tokio::test]
async fn worker_iteration_anchors_genesis_before_polling_empty_outbox() {
    let snapshot = genesis_snapshot();
    let receipt = accepted_genesis_receipt(&snapshot.head_hash);
    let (endpoint, server) = local_anchor_endpoint_with_body(200, receipt).await;
    let config = iteration_config(endpoint);
    let repository =
        ScriptedRepository::with_health(Ok(snapshot), Ok(SecurityAuditBatchClaim::Empty))
            .with_observation(Err(repository_error(
                "an incomplete checkpoint must not be observed",
            )));
    let client = test_client();
    let mut last_anchored = None;
    let mut last_blocked = None;

    let outcome = run_iteration(
        &repository,
        &client,
        &config,
        &mut last_anchored,
        &mut last_blocked,
    )
    .await;

    assert_eq!(outcome, IterationOutcome::Poll(config.poll_interval));
    let checkpoint = last_anchored.expect("genesis checkpoint is retained");
    assert_eq!(checkpoint.sequence, 0);
    assert_eq!(checkpoint.hash, encode_hash(&[9; 32]));
    let request = server.await.expect("genesis endpoint completes");
    let header_end = request
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .expect("request has headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body: Value = serde_json::from_slice(&request[header_end + 4..]).unwrap();
    assert!(
        header_value(&headers, "idempotency-key")
            .is_some_and(|key| { key.starts_with("genesis:deployment-1:") })
    );
    assert_eq!(body["checkpoint_kind"], "genesis");
    assert_eq!(body["sequence"], 0);
    assert_eq!(
        repository
            .observations
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .len(),
        1,
        "genesis must establish the complete checkpoint before observation"
    );
}

#[tokio::test]
async fn worker_iteration_retries_failed_genesis_without_claiming_deliveries() {
    let (endpoint, server) = local_anchor_endpoint(503).await;
    let config = iteration_config(endpoint);
    let repository =
        ScriptedRepository::with_health(Ok(genesis_snapshot()), Ok(SecurityAuditBatchClaim::Empty));
    let mut last_anchored = None;

    let outcome = run_iteration(
        &repository,
        &test_client(),
        &config,
        &mut last_anchored,
        &mut None,
    )
    .await;

    assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
    assert!(last_anchored.is_none());
    assert_eq!(
        repository
            .claims
            .lock()
            .expect("scripted repository mutex is not poisoned")
            .len(),
        1,
        "failed genesis must not claim durable deliveries"
    );
    server.await.expect("failed genesis endpoint completes");
}

#[tokio::test]
async fn worker_iteration_retries_genesis_rejection_and_bad_receipts() {
    let snapshot = genesis_snapshot();
    let rejected = signed_receipt(
        "rejected",
        "genesis",
        "deployment-1",
        0,
        0,
        0,
        encode_hash(&snapshot.head_hash),
        genesis_expectation("deployment-1", &snapshot.head_hash).batch_digest,
        Some("genesis_mismatch"),
        true,
        &test_signing_key(),
    );
    let (endpoint, server) = local_anchor_endpoint_with_body(200, rejected).await;
    let config = iteration_config(endpoint);
    let repository =
        ScriptedRepository::with_health(Ok(snapshot.clone()), Ok(SecurityAuditBatchClaim::Empty));
    let mut last_anchored = None;
    let outcome = run_iteration(
        &repository,
        &test_client(),
        &config,
        &mut last_anchored,
        &mut None,
    )
    .await;
    assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
    assert!(last_anchored.is_none());
    assert!(repository.acked().is_empty());
    server.await.expect("rejected genesis endpoint completes");

    let (endpoint, server) = local_anchor_endpoint_with_body(200, b"not-json".to_vec()).await;
    let repository =
        ScriptedRepository::with_health(Ok(snapshot), Ok(SecurityAuditBatchClaim::Empty));
    let outcome = run_iteration(
        &repository,
        &test_client(),
        &iteration_config(endpoint),
        &mut last_anchored,
        &mut None,
    )
    .await;
    assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
    server
        .await
        .expect("bad-receipt genesis endpoint completes");
}

#[tokio::test]
async fn worker_iteration_retries_database_observation_and_genesis_failures() {
    let config =
        iteration_config(Url::parse("https://unused-anchor.example.test/checkpoint").unwrap());
    let observation_failure =
        ScriptedRepository::with_health(Ok(health_snapshot()), Ok(SecurityAuditBatchClaim::Empty))
            .with_observation(Err(repository_error("observation failed")));
    assert_eq!(
        run_iteration(
            &observation_failure,
            &test_client(),
            &config,
            &mut None,
            &mut None,
        )
        .await,
        IterationOutcome::Retry(Duration::from_secs(1))
    );

    let snapshot = genesis_snapshot();
    let receipt = accepted_genesis_receipt(&snapshot.head_hash);
    let (endpoint, server) = local_anchor_endpoint_with_body(200, receipt).await;
    let config = iteration_config(endpoint);
    let genesis_failure =
        ScriptedRepository::with_health(Ok(snapshot), Ok(SecurityAuditBatchClaim::Empty))
            .with_genesis_record(Err(repository_error("genesis record failed")));
    let mut last_anchored = None;
    assert_eq!(
        run_iteration(
            &genesis_failure,
            &test_client(),
            &config,
            &mut last_anchored,
            &mut None,
        )
        .await,
        IterationOutcome::Retry(Duration::from_secs(1))
    );
    assert!(last_anchored.is_none());
    server.await.expect("genesis endpoint completes");
}

#[tokio::test]
async fn worker_iteration_reuses_current_genesis_and_tolerates_health_publish_failure() {
    let config =
        iteration_config(Url::parse("https://unused-anchor.example.test/checkpoint").unwrap());
    let snapshot = genesis_snapshot();
    let expected = AnchorCheckpoint::genesis(encode_hash(&snapshot.head_hash));
    let repository =
        ScriptedRepository::with_health(Ok(snapshot), Ok(SecurityAuditBatchClaim::Empty));
    let mut last_anchored = Some(expected.clone());

    let outcome = run_iteration(
        &repository,
        &test_client(),
        &config,
        &mut last_anchored,
        &mut None,
    )
    .await;

    assert_eq!(outcome, IterationOutcome::Poll(config.poll_interval));
    assert_eq!(last_anchored, Some(expected));
}

#[tokio::test]
async fn worker_iteration_pushes_batch_and_acknowledges_it() {
    let batch = batch(vec![delivery(7)]);
    let receipt = accepted_batch_receipt(&batch);
    let (endpoint, server) = local_anchor_endpoint_with_body(200, receipt).await;
    let config = iteration_config(endpoint);
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(SecurityAuditBatchClaim::Claimed(batch.clone())),
    )
    .with_acknowledgement(Ok(()));
    let client = test_client();
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &client, &config, &mut last_anchored, &mut None).await;

    assert_eq!(outcome, IterationOutcome::Continue);
    let acked = repository.acked();
    assert_eq!(acked.len(), 1);
    assert_eq!(acked[0].generation, batch.generation);
    assert_eq!(acked[0].first_sequence, batch.first_sequence);
    assert_eq!(acked[0].last_sequence, batch.last_sequence);
    assert_eq!(acked[0].event_count, batch.event_count());
    assert_eq!(acked[0].last_hash, batch.last_hash);
    assert_eq!(acked[0].batch_digest, batch.digest);
    assert!(repository.failures().is_empty());
    let checkpoint = last_anchored.expect("acknowledged checkpoint is retained");
    assert_eq!(checkpoint.sequence, batch.last_sequence);
    server.await.expect("checkpoint endpoint completes");
}

#[tokio::test]
async fn worker_iteration_acknowledges_duplicate_receipt_after_response_loss() {
    let batch = batch(vec![delivery(7)]);
    let receipt = signed_receipt(
        "duplicate",
        "batch",
        "deployment-1",
        batch.first_sequence,
        batch.last_sequence,
        batch.event_count(),
        encode_hash(&batch.last_hash),
        encode_hash(&batch.digest),
        None,
        false,
        &test_signing_key(),
    );
    let (endpoint, server) = local_anchor_endpoint_with_body(200, receipt).await;
    let config = iteration_config(endpoint);
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(SecurityAuditBatchClaim::Claimed(batch)),
    )
    .with_acknowledgement(Ok(()));

    let outcome = run_iteration(&repository, &test_client(), &config, &mut None, &mut None).await;

    assert_eq!(outcome, IterationOutcome::Continue);
    assert_eq!(repository.acked().len(), 1);
    assert!(repository.failures().is_empty());
    server.await.expect("duplicate receipt endpoint completes");
}

#[tokio::test]
async fn worker_iteration_reschedules_http_failures() {
    let (endpoint, server) = local_anchor_endpoint(503).await;
    let config = iteration_config(endpoint);
    let batch = batch(vec![delivery(7)]);
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(SecurityAuditBatchClaim::Claimed(batch.clone())),
    );
    let client = test_client();
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &client, &config, &mut last_anchored, &mut None).await;

    assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
    assert!(repository.acked().is_empty());
    assert_eq!(
        repository.failures(),
        vec![(batch.generation, "http_5xx".to_owned(), false)]
    );
    server.await.expect("failed checkpoint endpoint completes");
}

#[tokio::test]
async fn worker_iteration_reschedules_invalid_receipts_without_acknowledging() {
    for response_body in [
        b"{}".to_vec(),
        signed_receipt(
            "accepted",
            "batch",
            "other-deployment",
            7,
            7,
            1,
            encode_hash(&[8; 32]),
            encode_hash(&[9; 32]),
            None,
            false,
            &test_signing_key(),
        ),
        signed_receipt(
            "accepted",
            "batch",
            "deployment-1",
            7,
            7,
            1,
            encode_hash(&[8; 32]),
            encode_hash(&[0xaa; 32]),
            None,
            false,
            &SigningKey::from_bytes(&[77; 32]),
        ),
    ] {
        let (endpoint, server) = local_anchor_endpoint_with_body(200, response_body).await;
        let config = iteration_config(endpoint);
        let batch = batch(vec![delivery(7)]);
        let repository = ScriptedRepository::with_health(
            Ok(health_snapshot()),
            Ok(SecurityAuditBatchClaim::Claimed(batch.clone())),
        );
        let outcome =
            run_iteration(&repository, &test_client(), &config, &mut None, &mut None).await;
        assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
        assert!(
            repository.acked().is_empty(),
            "invalid receipt must never ack"
        );
        assert_eq!(
            repository.failures(),
            vec![(batch.generation, "invalid_receipt".to_owned(), false)]
        );
        server.await.expect("invalid receipt endpoint completes");
    }
}

#[tokio::test]
async fn worker_iteration_blocks_permanent_rejection_and_reschedules_transient() {
    let batch = batch(vec![delivery(7)]);
    let permanent = signed_receipt(
        "rejected",
        "batch",
        "deployment-1",
        batch.first_sequence,
        batch.last_sequence,
        batch.event_count(),
        encode_hash(&batch.last_hash),
        encode_hash(&batch.digest),
        Some("chain_digest_mismatch"),
        true,
        &test_signing_key(),
    );
    let (endpoint, server) = local_anchor_endpoint_with_body(200, permanent).await;
    let config = iteration_config(endpoint);
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(SecurityAuditBatchClaim::Claimed(batch.clone())),
    );
    let mut last_blocked = None;

    let outcome = run_iteration(
        &repository,
        &test_client(),
        &config,
        &mut None,
        &mut last_blocked,
    )
    .await;

    assert_eq!(outcome, IterationOutcome::Poll(config.poll_interval));
    assert_eq!(last_blocked.as_deref(), Some("chain_digest_mismatch"));
    assert_eq!(
        repository.failures(),
        vec![(batch.generation, "chain_digest_mismatch".to_owned(), true)]
    );
    assert!(repository.acked().is_empty());
    server.await.expect("rejected endpoint completes");

    let transient = signed_receipt(
        "rejected",
        "batch",
        "deployment-1",
        batch.first_sequence,
        batch.last_sequence,
        batch.event_count(),
        encode_hash(&batch.last_hash),
        encode_hash(&batch.digest),
        Some("receiver_overloaded"),
        false,
        &test_signing_key(),
    );
    let (endpoint, server) = local_anchor_endpoint_with_body(200, transient).await;
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(SecurityAuditBatchClaim::Claimed(batch.clone())),
    );
    let outcome = run_iteration(
        &repository,
        &test_client(),
        &iteration_config(endpoint),
        &mut None,
        &mut None,
    )
    .await;
    assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
    assert_eq!(
        repository.failures(),
        vec![(batch.generation, "receiver_overloaded".to_owned(), false)]
    );
    server.await.expect("transient reject endpoint completes");
}

#[tokio::test]
async fn worker_iteration_reports_blocked_claims_and_recovers() {
    let config =
        iteration_config(Url::parse("https://unused-anchor.example.test/checkpoint").unwrap());
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(SecurityAuditBatchClaim::Blocked {
            reason: "chain_digest_mismatch".to_owned(),
        }),
    );
    let mut last_blocked = None;

    let outcome = run_iteration(
        &repository,
        &test_client(),
        &config,
        &mut None,
        &mut last_blocked,
    )
    .await;

    assert_eq!(outcome, IterationOutcome::Poll(config.poll_interval));
    assert_eq!(last_blocked.as_deref(), Some("chain_digest_mismatch"));
    assert!(repository.acked().is_empty());
    assert!(repository.failures().is_empty());
}

#[tokio::test]
async fn worker_iteration_reschedules_ack_failure() {
    let batch = batch(vec![delivery(7)]);
    let receipt = accepted_batch_receipt(&batch);
    let (endpoint, server) = local_anchor_endpoint_with_body(200, receipt).await;
    let config = iteration_config(endpoint);
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(SecurityAuditBatchClaim::Claimed(batch.clone())),
    )
    .with_acknowledgement(Err(repository_error("ack failed")));
    let client = test_client();
    let mut last_anchored = None;

    let outcome = run_iteration(&repository, &client, &config, &mut last_anchored, &mut None).await;

    assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
    assert!(repository.acked().is_empty());
    assert_eq!(
        repository.failures(),
        vec![(batch.generation, "ack_database_error".to_owned(), false)]
    );
    server.await.expect("checkpoint endpoint completes");
}

#[tokio::test]
async fn worker_iteration_tolerates_lease_release_failure() {
    let (endpoint, server) = local_anchor_endpoint(503).await;
    let config = iteration_config(endpoint);
    let batch = batch(vec![delivery(7)]);
    let repository = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Ok(SecurityAuditBatchClaim::Claimed(batch.clone())),
    )
    .with_fail_failure();
    let mut last_anchored = None;

    let outcome = run_iteration(
        &repository,
        &test_client(),
        &config,
        &mut last_anchored,
        &mut None,
    )
    .await;

    assert_eq!(outcome, IterationOutcome::Retry(Duration::from_secs(1)));
    assert_eq!(
        repository.failures(),
        vec![(batch.generation, "http_5xx".to_owned(), false)]
    );
    server.await.expect("failed checkpoint endpoint completes");
}

#[tokio::test]
async fn worker_iteration_retries_health_and_claim_failures() {
    let config = iteration_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    let client = test_client();
    let health_failure = ScriptedRepository::with_health(
        Err(repository_error("health failed")),
        Ok(SecurityAuditBatchClaim::Empty),
    );
    assert_eq!(
        run_iteration(&health_failure, &client, &config, &mut None, &mut None).await,
        IterationOutcome::Retry(Duration::from_secs(1))
    );

    let claim_failure = ScriptedRepository::with_health(
        Ok(health_snapshot()),
        Err(repository_error("claim failed")),
    );
    assert_eq!(
        run_iteration(&claim_failure, &client, &config, &mut None, &mut None).await,
        IterationOutcome::Retry(Duration::from_secs(1))
    );

    let busy =
        ScriptedRepository::with_health(Ok(health_snapshot()), Ok(SecurityAuditBatchClaim::Busy));
    assert_eq!(
        run_iteration(&busy, &client, &config, &mut None, &mut None).await,
        IterationOutcome::Poll(config.poll_interval)
    );
}

#[tokio::test]
async fn worker_outer_rejects_invalid_config_before_repository_preflight() {
    let pool = nazo_postgres::create_pool("not a postgres url", 1).unwrap();
    let repository = AuditLedgerRepository::new(pool);
    let config = AuditAnchorWorkerConfig {
        preflight: required_config(),
        endpoint: Url::parse("http://anchor.example.test/checkpoint").unwrap(),
        auth_secret: vec![0; 15],
        receipt_verify_key: test_verify_key(),
        ca_bundle_pem: None,
        poll_interval: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        batch_size: 1,
        max_envelope_bytes: 1024 * 1024,
        lock_timeout_seconds: 1,
    };

    let error = super::worker::run_worker(repository, config)
        .await
        .expect_err("invalid worker configuration must fail before preflight");
    assert!(error.to_string().contains("HTTPS"));
}

#[tokio::test]
async fn worker_outer_rejects_repository_preflight_failure() {
    let pool = nazo_postgres::create_pool("not a postgres url", 1).unwrap();
    let repository = AuditLedgerRepository::new(pool);
    let config = iteration_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());

    let error = super::worker::run_worker(repository, config)
        .await
        .expect_err("repository preflight failure must stop the worker");
    assert_eq!(
        error.to_string(),
        "audit anchor exporter capability preflight failed"
    );
}

#[test]
fn batch_envelope_is_stable_and_binds_the_committed_range() {
    let batch = batch(vec![delivery(7), delivery(8)]);
    let first = batch_body("deployment-1", &batch).unwrap();
    let second = batch_body("deployment-1", &batch).unwrap();
    assert_eq!(first, second);

    let Value::Object(fields) = serde_json::from_slice(&first).unwrap() else {
        panic!("batch envelope must be a JSON object");
    };
    assert_eq!(fields["schema_version"], CHECKPOINT_SCHEMA_VERSION);
    assert_eq!(fields["checkpoint_kind"], "batch");
    assert_eq!(fields["deployment_id"], "deployment-1");
    assert_eq!(fields["first_sequence"], 7);
    assert_eq!(fields["last_sequence"], 8);
    assert_eq!(fields["event_count"], 2);
    assert_eq!(
        fields["batch_digest"].as_str().unwrap(),
        encode_hash(&batch.digest)
    );
    let events = fields["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["sequence"], 7);
    assert_eq!(
        events[0]["payload_canonical"].as_str().unwrap(),
        "{\"user_id\":\"user-1\"}"
    );
}

#[test]
fn receipt_verification_requires_signature_schema_and_binding() {
    let batch = batch(vec![delivery(7)]);
    let expectation = batch_expectation("deployment-1", &batch);
    let good = accepted_batch_receipt(&batch);
    assert_eq!(
        verify_receipt(&good, &test_verify_key(), &expectation).unwrap(),
        ReceiptVerdict::Accepted { duplicate: false }
    );

    let wrong_key = signed_receipt(
        "accepted",
        "batch",
        "deployment-1",
        batch.first_sequence,
        batch.last_sequence,
        batch.event_count(),
        encode_hash(&batch.last_hash),
        encode_hash(&batch.digest),
        None,
        false,
        &SigningKey::from_bytes(&[77; 32]),
    );
    assert!(verify_receipt(&wrong_key, &test_verify_key(), &expectation).is_err());

    let mut tampered: Value = serde_json::from_slice(&good).unwrap();
    tampered["event_count"] = json!(2);
    assert!(
        verify_receipt(
            &serde_json::to_vec(&tampered).unwrap(),
            &test_verify_key(),
            &expectation
        )
        .is_err()
    );

    let rejected = signed_receipt(
        "rejected",
        "batch",
        "deployment-1",
        batch.first_sequence,
        batch.last_sequence,
        batch.event_count(),
        encode_hash(&batch.last_hash),
        encode_hash(&batch.digest),
        Some("fork_detected"),
        true,
        &test_signing_key(),
    );
    assert_eq!(
        verify_receipt(&rejected, &test_verify_key(), &expectation).unwrap(),
        ReceiptVerdict::Rejected {
            reason: "fork_detected".to_owned(),
            permanent: true
        }
    );
}

#[test]
fn checkpoint_signature_is_deterministic_and_url_safe() {
    let body = br#"{"sequence":7,"event_hash":"abc"}"#;
    let first = sign_body(b"anchor-secret-that-is-long-enough", body);
    let second = sign_body(b"anchor-secret-that-is-long-enough", body);

    assert_eq!(first, second);
    assert!(!first.is_empty());
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
}

#[test]
fn retry_backoff_is_bounded() {
    assert_eq!(retry_delay(1), Duration::from_secs(1));
    assert_eq!(retry_delay(2), Duration::from_secs(2));
    assert_eq!(retry_delay(9), Duration::from_secs(256));
    assert_eq!(retry_delay(i32::MAX), Duration::from_secs(300));
}

#[test]
fn mode_parser_and_preflight_configuration_reject_invalid_values() {
    assert_eq!(
        AuditAnchorMode::parse("disabled").unwrap(),
        AuditAnchorMode::Disabled
    );
    assert_eq!(
        AuditAnchorMode::parse("optional").unwrap(),
        AuditAnchorMode::Optional
    );
    assert_eq!(
        AuditAnchorMode::parse("required").unwrap(),
        AuditAnchorMode::Required
    );
    assert!(AuditAnchorMode::parse("unexpected").is_err());

    let invalid_identity = AuditAnchorPreflightConfig {
        mode: AuditAnchorMode::Required,
        deployment_id: "deployment/with-slash".to_owned(),
        freshness: Duration::from_secs(60),
        max_lag: Duration::from_secs(300),
    };
    assert!(invalid_identity.validate().is_err());
}

#[test]
fn worker_configuration_rejects_non_https_and_weak_secret() {
    let config = AuditAnchorWorkerConfig {
        preflight: required_config(),
        endpoint: Url::parse("http://anchor.example.test").unwrap(),
        auth_secret: vec![0; 15],
        receipt_verify_key: test_verify_key(),
        ca_bundle_pem: None,
        poll_interval: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        batch_size: 1,
        max_envelope_bytes: 1024 * 1024,
        lock_timeout_seconds: 1,
    };
    assert!(config.validate().is_err());
}

#[test]
fn mode_helpers_and_deployment_id_boundaries_are_explicit() {
    assert!(!AuditAnchorMode::Disabled.is_enabled());
    assert!(AuditAnchorMode::Optional.is_enabled());
    assert!(AuditAnchorMode::Required.is_enabled());
    assert!(!AuditAnchorMode::Disabled.is_required());
    assert!(!AuditAnchorMode::Optional.is_required());
    assert!(AuditAnchorMode::Required.is_required());

    for value in ["a", "deployment-1", "a.b_c-9"] {
        super::config::validate_deployment_id(value).unwrap();
    }
    let valid_max = "a".repeat(255);
    super::config::validate_deployment_id(&valid_max).unwrap();
    for value in [
        "",
        "deployment/with-slash",
        "deployment with spaces",
        "部署-1",
    ] {
        assert!(
            super::config::validate_deployment_id(value).is_err(),
            "{value:?}"
        );
    }
    let invalid_max = "a".repeat(256);
    assert!(super::config::validate_deployment_id(&invalid_max).is_err());
}

#[test]
fn preflight_source_uses_safe_defaults_and_requires_identity_when_enabled() {
    let disabled = crate::config::ConfigSource::default();
    let disabled_config = super::config::preflight_config_from_source(&disabled)
        .expect("disabled mode has a safe default identity");
    assert_eq!(disabled_config.mode, AuditAnchorMode::Disabled);
    assert_eq!(disabled_config.deployment_id, "audit-anchor-disabled");

    let source = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "optional"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_FRESHNESS_SECONDS", "9"),
        ("AUDIT_ANCHOR_MAX_LAG_SECONDS", "11"),
    ]);
    let config = super::config::preflight_config_from_source(&source)
        .expect("explicit preflight values should parse");
    assert_eq!(config.mode, AuditAnchorMode::Optional);
    assert_eq!(config.deployment_id, "deployment-test");
    assert_eq!(config.freshness, Duration::from_secs(9));
    assert_eq!(config.max_lag, Duration::from_secs(11));

    let missing_identity =
        crate::config::ConfigSource::from_pairs_for_test([("AUDIT_ANCHOR_MODE", "required")]);
    assert!(super::config::preflight_config_from_source(&missing_identity).is_err());
    let invalid_freshness = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_FRESHNESS_SECONDS", "0"),
    ]);
    assert!(super::config::preflight_config_from_source(&invalid_freshness).is_err());
}

#[test]
fn worker_source_loads_sidecar_only_values_and_rejects_invalid_inputs() {
    let verify_key: &'static str =
        Box::leak(encode_hash(&test_verify_key().to_bytes()).into_boxed_str());
    let source = crate::config::ConfigSource::from_pairs_for_test([
        ("DATA_DIR", "runtime"),
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "https://anchor.example.test/checkpoint"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_RECEIPT_VERIFY_KEY", verify_key),
        ("AUDIT_ANCHOR_POLL_INTERVAL_SECONDS", "2"),
        ("AUDIT_ANCHOR_REQUEST_TIMEOUT_SECONDS", "3"),
        ("AUDIT_ANCHOR_BATCH_SIZE", "5"),
        ("AUDIT_ANCHOR_MAX_ENVELOPE_BYTES", "262144"),
        ("AUDIT_ANCHOR_LOCK_TIMEOUT_SECONDS", "7"),
        ("AUDIT_ANCHOR_DATABASE_URL", "postgres://exporter@db/audit"),
        ("AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS", "8"),
    ]);
    let (database_url, max_connections, config) =
        super::config::worker_config_from_source(&source).expect("worker source should parse");
    assert_eq!(database_url, "postgres://exporter@db/audit");
    assert_eq!(max_connections, 8);
    assert_eq!(config.batch_size, 5);
    assert_eq!(config.max_envelope_bytes, 262_144);
    assert_eq!(config.lock_timeout_seconds, 7);
    assert_eq!(config.receipt_verify_key, test_verify_key());

    let invalid_url = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "not a url"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_RECEIPT_VERIFY_KEY", verify_key),
        ("AUDIT_ANCHOR_DATABASE_URL", "postgres://exporter@db/audit"),
    ]);
    assert!(super::config::worker_config_from_source(&invalid_url).is_err());

    let no_key = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "https://anchor.example.test/checkpoint"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_DATABASE_URL", "postgres://exporter@db/audit"),
    ]);
    assert!(super::config::worker_config_from_source(&no_key).is_err());

    let bad_key = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "https://anchor.example.test/checkpoint"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_RECEIPT_VERIFY_KEY", "not-a-key"),
        ("AUDIT_ANCHOR_DATABASE_URL", "postgres://exporter@db/audit"),
    ]);
    assert!(super::config::worker_config_from_source(&bad_key).is_err());

    let no_database = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "https://anchor.example.test/checkpoint"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_RECEIPT_VERIFY_KEY", verify_key),
    ]);
    assert!(super::config::worker_config_from_source(&no_database).is_err());

    let bad_envelope = crate::config::ConfigSource::from_pairs_for_test([
        ("AUDIT_ANCHOR_MODE", "required"),
        ("DEPLOYMENT_ID", "deployment-test"),
        ("AUDIT_ANCHOR_URL", "https://anchor.example.test/checkpoint"),
        ("AUDIT_ANCHOR_TOKEN", "anchor-secret-that-is-long-enough"),
        ("AUDIT_ANCHOR_RECEIPT_VERIFY_KEY", verify_key),
        ("AUDIT_ANCHOR_MAX_ENVELOPE_BYTES", "64"),
        ("AUDIT_ANCHOR_DATABASE_URL", "postgres://exporter@db/audit"),
    ]);
    assert!(super::config::worker_config_from_source(&bad_envelope).is_err());
}

#[test]
fn worker_configuration_validates_each_boundary_without_combining_errors() {
    let mut config =
        valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());

    config.preflight.mode = AuditAnchorMode::Disabled;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());

    config.endpoint = Url::parse("https://user:pass@anchor.example.test/checkpoint").unwrap();
    assert!(config.validate().is_err());
    config.endpoint = Url::parse("https://anchor.example.test/checkpoint?tenant=1").unwrap();
    assert!(config.validate().is_err());
    config.endpoint = Url::parse("https://anchor.example.test/checkpoint#fragment").unwrap();
    assert!(config.validate().is_err());
    config.endpoint = Url::parse("http://anchor.example.test/checkpoint").unwrap();
    assert!(config.validate().is_err());

    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.auth_secret.clear();
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.poll_interval = Duration::ZERO;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.request_timeout = Duration::ZERO;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.batch_size = 0;
    assert!(config.validate().is_err());
    config.batch_size = 257;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.max_envelope_bytes = 1024;
    assert!(config.validate().is_err());
    config.max_envelope_bytes = 2 * 1024 * 1024;
    assert!(config.validate().is_err());
    config = valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap());
    config.lock_timeout_seconds = 0;
    assert!(config.validate().is_err());
    config.lock_timeout_seconds = 3_601;
    assert!(config.validate().is_err());
    assert!(
        valid_worker_config(Url::parse("https://anchor.example.test/checkpoint").unwrap())
            .validate()
            .is_ok()
    );
}

#[test]
fn genesis_body_is_stable_and_has_explicit_kind() {
    let first = genesis_body("deployment-1", &[0; 32]).unwrap();
    let second = genesis_body("deployment-1", &[0; 32]).unwrap();
    assert_eq!(first, second);
    let value: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(value["checkpoint_kind"], "genesis");
    assert_eq!(value["sequence"], 0);
}

#[test]
fn preflight_accepts_shared_health_and_rejects_stale_or_unanchored_state() {
    let now = Utc::now();
    let config = required_config();
    let current = health_snapshot();
    assert!(validate_health(&config, &current, now).is_ok());

    let mut stale = current.clone();
    stale.observed_at = Some(now - ChronoDuration::seconds(121));
    assert!(validate_health(&config, &stale, now).is_err());

    let mut wrong_deployment = current.clone();
    wrong_deployment.deployment_id = Some("other".to_owned());
    assert!(validate_health(&config, &wrong_deployment, now).is_err());

    let mut pending = current.clone();
    pending.pending_exists = true;
    assert!(validate_health(&config, &pending, now).is_err());

    pending.oldest_pending_occurred_at = Some(now - ChronoDuration::seconds(300));
    assert!(validate_health(&config, &pending, now).is_ok());
    pending.oldest_pending_occurred_at = Some(now - ChronoDuration::seconds(301));
    assert!(validate_health(&config, &pending, now).is_err());

    let mut recovered = current.clone();
    recovered.last_exported_occurred_at = Some(now - ChronoDuration::hours(1));
    recovered.last_exported_at = Some(now - ChronoDuration::minutes(10));
    assert!(
        validate_health(&config, &recovered, now).is_ok(),
        "historical delivery lag must not prevent recovery after the backlog is drained"
    );

    let mut missing_checkpoint = current.clone();
    missing_checkpoint.last_exported_sequence = None;
    assert!(validate_health(&config, &missing_checkpoint, now).is_err());

    let mut orphan = current.clone();
    orphan.pending_orphan_exists = true;
    assert!(validate_health(&config, &orphan, now).is_err());

    let mut blocked = current.clone();
    blocked.batch = Some(SecurityAuditBatchLease {
        first_sequence: 8,
        last_sequence: 9,
        event_count: 2,
        generation: 4,
        attempts: 3,
        available_at: None,
        locked_until: None,
        last_error: Some("chain_digest_mismatch".to_owned()),
        blocked_reason: Some("chain_digest_mismatch".to_owned()),
    });
    assert!(validate_health(&config, &blocked, now).is_err());

    let mut behind = current;
    behind.last_exported_sequence = Some(6);
    assert!(validate_health(&config, &behind, now).is_err());
    behind.pending_exists = true;
    behind.oldest_pending_occurred_at = Some(now);
    assert!(validate_health(&config, &behind, now).is_ok());
    behind.last_exported_sequence = Some(8);
    assert!(validate_health(&config, &behind, now).is_err());
}

#[test]
fn preflight_mode_controls_the_shared_database_gate() {
    let current = health_snapshot();
    let required = AuditAnchorPreflight::new(required_config()).unwrap();
    assert!(required.ensure_fresh(&current).is_ok());
    let mut disabled = required_config();
    disabled.mode = AuditAnchorMode::Disabled;
    let mut unavailable = current;
    unavailable.deployment_id = None;
    assert!(
        AuditAnchorPreflight::new(disabled)
            .unwrap()
            .ensure_fresh(&unavailable)
            .is_ok()
    );
}

#[test]
fn health_time_helpers_reject_future_timestamps_and_bound_durations() {
    let now = Utc::now();
    assert_eq!(
        age_seconds(now, now - ChronoDuration::seconds(4)).unwrap(),
        4
    );
    assert!(age_seconds(now, now + ChronoDuration::seconds(1)).is_err());
    assert_eq!(duration_seconds(Duration::from_secs(17)), 17);
    assert_eq!(duration_seconds(Duration::from_secs(u64::MAX)), i64::MAX);
}

#[test]
fn anchor_push_error_codes_cover_transport_serialization_http_and_receipt_classes() {
    assert_eq!(AnchorPushError::Transport.code(), "transport_error");
    assert_eq!(AnchorPushError::Serialize.code(), "serialization_error");
    assert_eq!(AnchorPushError::Http(429).code(), "http_429");
    assert_eq!(AnchorPushError::Http(400).code(), "http_4xx");
    assert_eq!(AnchorPushError::Http(499).code(), "http_4xx");
    assert_eq!(AnchorPushError::Http(500).code(), "http_5xx");
    assert_eq!(AnchorPushError::Http(599).code(), "http_5xx");
    assert_eq!(AnchorPushError::Http(300).code(), "http_other");
    assert_eq!(AnchorPushError::InvalidReceipt.code(), "invalid_receipt");
}

#[tokio::test]
async fn batch_transport_sends_stable_body_signature_and_protocol_headers() {
    let batch = batch(vec![delivery(7)]);
    let receipt = accepted_batch_receipt(&batch);
    let (endpoint, server) = local_anchor_endpoint_with_body(200, receipt).await;
    let config = valid_worker_config(endpoint);
    let expected_body = batch_body(&config.preflight.deployment_id, &batch).unwrap();
    let result = send_batch(&test_client(), &config, &batch).await;
    assert_eq!(result.unwrap(), PushOutcome::Accepted { duplicate: false });
    let request = server.await.expect("local endpoint completes");
    let header_end = request
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .expect("request has headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body = &request[header_end + 4..];
    let expected_signature = format!("sha256={}", sign_body(&config.auth_secret, &expected_body));
    let expected_idempotency_key = format!(
        "batch:deployment-1:{}:{}:{}",
        batch.first_sequence,
        batch.last_sequence,
        encode_hash(&batch.digest)
    );
    assert!(headers.starts_with("POST /checkpoint HTTP/1.1"));
    assert_eq!(
        header_value(&headers, "content-type"),
        Some("application/json")
    );
    assert_eq!(
        header_value(&headers, "idempotency-key"),
        Some(expected_idempotency_key.as_str())
    );
    assert_eq!(
        header_value(&headers, "x-nazo-audit-schema"),
        Some(CHECKPOINT_SCHEMA_VERSION)
    );
    assert_eq!(
        header_value(&headers, "x-nazo-audit-deployment"),
        Some("deployment-1")
    );
    assert_eq!(
        header_value(&headers, "x-nazo-audit-signature"),
        Some(expected_signature.as_str())
    );
    assert!(header_value(&headers, "x-nazo-audit-sent-at").is_some());
    assert_eq!(body, expected_body.as_slice());
}

#[tokio::test]
async fn batch_transport_classifies_http_statuses_disconnects_and_2xx_without_receipt() {
    let client = test_client();
    for (status, expected_code) in [
        (429, "http_429"),
        (400, "http_4xx"),
        (499, "http_4xx"),
        (500, "http_5xx"),
        (599, "http_5xx"),
        (300, "http_other"),
    ] {
        let (endpoint, server) = local_anchor_endpoint(status).await;
        let result = send_batch(
            &client,
            &valid_worker_config(endpoint),
            &batch(vec![delivery(7)]),
        )
        .await
        .expect_err("non-success response is an error");
        assert_eq!(result.code(), expected_code, "status {status}");
        server.await.expect("local endpoint completes");
    }

    let (endpoint, server) = local_disconnect_endpoint().await;
    let result = send_batch(
        &client,
        &valid_worker_config(endpoint),
        &batch(vec![delivery(7)]),
    )
    .await
    .expect_err("closed endpoint is a transport error");
    assert_eq!(result.code(), "transport_error");
    server.await.expect("disconnect endpoint completes");

    let (endpoint, server) = local_anchor_endpoint_with_body(202, b"{}".to_vec()).await;
    let result = send_batch(
        &client,
        &valid_worker_config(endpoint),
        &batch(vec![delivery(7)]),
    )
    .await
    .expect_err("a bare 2xx without a signed receipt is not an acknowledgement");
    assert_eq!(result.code(), "invalid_receipt");
    server.await.expect("bare 2xx endpoint completes");
}

#[tokio::test]
async fn repeated_genesis_calls_emit_stable_body_signature_and_idempotency_key() {
    let receipt = accepted_genesis_receipt(&[9; 32]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback address is available");
    let receipt_for_server = receipt.clone();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("request arrives");
            let request = read_anchor_request(&mut stream).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        receipt_for_server.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("response is writable");
            stream
                .write_all(&receipt_for_server)
                .await
                .expect("receipt body is writable");
            requests.push(request);
        }
        requests
    });
    let config = valid_worker_config(Url::parse(&format!("http://{address}/checkpoint")).unwrap());
    let client = test_client();
    let first = send_genesis_checkpoint(&client, &config, &[9; 32])
        .await
        .expect("genesis request succeeds");
    let second = send_genesis_checkpoint(&client, &config, &[9; 32])
        .await
        .expect("replayed genesis request succeeds");
    assert_eq!(first, PushOutcome::Accepted { duplicate: false });
    assert_eq!(second, PushOutcome::Accepted { duplicate: false });
    let requests = server.await.expect("genesis endpoint completes twice");
    assert_eq!(requests.len(), 2);
    let expected_body = genesis_body("deployment-1", &[9; 32]).unwrap();
    let expected_signature = format!("sha256={}", sign_body(&config.auth_secret, &expected_body));
    for request in requests {
        let header_end = request
            .windows(4)
            .position(|value| value == b"\r\n\r\n")
            .unwrap();
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let body = &request[header_end + 4..];
        assert_eq!(
            header_value(&headers, "idempotency-key"),
            Some(format!("genesis:deployment-1:{}", encode_hash(&[9; 32])).as_str())
        );
        assert_eq!(
            header_value(&headers, "x-nazo-audit-signature"),
            Some(expected_signature.as_str())
        );
        assert_eq!(body, expected_body.as_slice());
    }

    let (endpoint, server) = local_anchor_endpoint(503).await;
    let error = send_genesis_checkpoint(&test_client(), &valid_worker_config(endpoint), &[9; 32])
        .await
        .expect_err("failed genesis response is classified");
    assert_eq!(error.code(), "http_5xx");
    server.await.expect("failed genesis endpoint completes");
}

#[test]
fn retry_delay_and_batch_lag_are_monotonic_and_bounded() {
    assert_eq!(retry_delay(-1), Duration::from_secs(1));
    assert_eq!(retry_delay(0), Duration::from_secs(1));
    assert_eq!(retry_delay(1), Duration::from_secs(1));
    assert_eq!(retry_delay(2), Duration::from_secs(2));
    assert_eq!(retry_delay(3), Duration::from_secs(4));
    assert_eq!(retry_delay(9), Duration::from_secs(256));
    assert_eq!(retry_delay(10), Duration::from_secs(300));
    assert_eq!(retry_delay(i32::MAX), Duration::from_secs(300));

    let mut recent = delivery(7);
    recent.occurred_at = Utc::now() - ChronoDuration::seconds(3);
    assert!(batch_lag_seconds(&batch(vec![recent.clone()])) >= 2);
    recent.occurred_at = Utc::now() + ChronoDuration::seconds(30);
    assert_eq!(batch_lag_seconds(&batch(vec![recent])), 0);
}

#[tokio::test]
async fn repository_adapter_forwards_invalid_pool_calls_without_panicking() {
    let pool = nazo_postgres::create_pool("not a postgres url", 1).unwrap();
    let repository = AuditLedgerRepository::new(pool);

    assert!(
        <AuditLedgerRepository as AuditAnchorRepository>::anchor_health(&repository)
            .await
            .is_err()
    );
    assert!(
        <AuditLedgerRepository as AuditAnchorRepository>::claim_batch(
            &repository,
            "deployment-1",
            0,
            1,
            1
        )
        .await
        .is_err()
    );
    assert!(
        <AuditLedgerRepository as AuditAnchorRepository>::ack_batch(
            &repository,
            SecurityAuditBatchAck {
                generation: 1,
                deployment_id: "deployment-1".to_owned(),
                first_sequence: 1,
                last_sequence: 1,
                event_count: 1,
                last_hash: vec![0; 32],
                batch_digest: vec![0; 32],
            },
        )
        .await
        .is_err()
    );
    assert!(
        <AuditLedgerRepository as AuditAnchorRepository>::fail_batch(
            &repository,
            1,
            Utc::now(),
            "typed-test-error",
            false,
        )
        .await
        .is_err()
    );
}
