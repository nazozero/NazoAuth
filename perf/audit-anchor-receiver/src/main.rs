//! Reference audit-anchor receiver for benchmark and fault-injection runs.
//!
//! Endpoints:
//!   POST /checkpoint    verify + persist + fsync + signed receipt
//!   GET  /checkpoint    read-only checkpoint inspection (Bearer auth)
//!   GET  /__state       inspection: checkpoint, counters, fault mode (Bearer)
//!   POST /__fault       set fault mode {"mode": "..."} (Bearer)
//!   GET  /__pubkey      Ed25519 receipt verification key, base64url (open)
//!
//! Fault modes: none | http_500 | drop | drop_after_persist | bad_signature
//!              | reject_transient | reject_permanent
//!
//! Configuration (environment):
//!   ANCHOR_RECEIVER_LISTEN            default 0.0.0.0:9443
//!   ANCHOR_RECEIVER_TLS_CERT          PEM certificate chain (required)
//!   ANCHOR_RECEIVER_TLS_KEY           PEM private key (required)
//!   ANCHOR_RECEIVER_DEPLOYMENT        expected deployment_id (required)
//!   ANCHOR_RECEIVER_TOKEN             shared HMAC secret = AUDIT_ANCHOR_TOKEN
//!   ANCHOR_RECEIVER_SIGNING_KEY       Ed25519 seed, base64url or hex (required)
//!   ANCHOR_RECEIVER_DATA_DIR          durable state directory (required)
//!   ANCHOR_RECEIVER_MAX_ENVELOPE      max body bytes, default 1572864
//!   ANCHOR_RECEIVER_FAULT             initial fault mode, default none

mod store;
mod wire;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::json;
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use store::{Checkpoint, Store};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::ServerConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    Http500,
    Drop,
    DropAfterPersist,
    BadSignature,
    RejectTransient,
    RejectPermanent,
}

impl Fault {
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "none" => Self::None,
            "http_500" => Self::Http500,
            "drop" => Self::Drop,
            "drop_after_persist" => Self::DropAfterPersist,
            "bad_signature" => Self::BadSignature,
            "reject_transient" => Self::RejectTransient,
            "reject_permanent" => Self::RejectPermanent,
            other => bail!("unknown fault mode {other:?}"),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Http500 => "http_500",
            Self::Drop => "drop",
            Self::DropAfterPersist => "drop_after_persist",
            Self::BadSignature => "bad_signature",
            Self::RejectTransient => "reject_transient",
            Self::RejectPermanent => "reject_permanent",
        }
    }
}

struct Receiver {
    deployment_id: String,
    token: Vec<u8>,
    signing_key: ed25519_dalek::SigningKey,
    wrong_key: ed25519_dalek::SigningKey,
    store: Mutex<Store>,
    fault: Mutex<Fault>,
    max_envelope: usize,
    requests: AtomicU64,
    accepted: AtomicU64,
    duplicates: AtomicU64,
    rejected: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let listen = env("ANCHOR_RECEIVER_LISTEN").unwrap_or_else(|_| "0.0.0.0:9443".to_owned());
    let cert_path = env("ANCHOR_RECEIVER_TLS_CERT").context("ANCHOR_RECEIVER_TLS_CERT is required")?;
    let key_path = env("ANCHOR_RECEIVER_TLS_KEY").context("ANCHOR_RECEIVER_TLS_KEY is required")?;
    let deployment_id =
        env("ANCHOR_RECEIVER_DEPLOYMENT").context("ANCHOR_RECEIVER_DEPLOYMENT is required")?;
    let token = env("ANCHOR_RECEIVER_TOKEN")
        .context("ANCHOR_RECEIVER_TOKEN is required")?
        .into_bytes();
    let signing_key = wire::parse_signing_key(
        &env("ANCHOR_RECEIVER_SIGNING_KEY").context("ANCHOR_RECEIVER_SIGNING_KEY is required")?,
    )?;
    let data_dir = env("ANCHOR_RECEIVER_DATA_DIR").context("ANCHOR_RECEIVER_DATA_DIR is required")?;
    let max_envelope = env("ANCHOR_RECEIVER_MAX_ENVELOPE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_572_864);
    let fault = Fault::parse(&env("ANCHOR_RECEIVER_FAULT").unwrap_or_else(|_| "none".to_owned()))?;

    let acceptor = tls_acceptor(&cert_path, &key_path)?;
    let receiver = Arc::new(Receiver {
        deployment_id,
        token,
        wrong_key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        signing_key,
        store: Mutex::new(Store::open(data_dir)?),
        fault: Mutex::new(fault),
        max_envelope,
        requests: AtomicU64::new(0),
        accepted: AtomicU64::new(0),
        duplicates: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
    });
    eprintln!(
        "anchor receiver on {listen} deployment={} pubkey={}",
        receiver.deployment_id,
        wire::verifying_key_b64(&receiver.signing_key)
    );
    let listener = TcpListener::bind(&listen).await.context("bind listener")?;
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let receiver = receiver.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let _ = handle(receiver, stream).await;
        });
    }
}

fn env(name: &str) -> Result<String, anyhow::Error> {
    std::env::var(name).map_err(|_| anyhow!("missing {name}"))
}

fn tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(File::open(cert_path)?))
        .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(File::open(key_path)?))?
        .ok_or_else(|| anyhow!("no private key in {key_path}"))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

async fn read_request<S: AsyncReadExt + Unpin>(stream: &mut S, max: usize) -> Result<Request> {
    let mut raw = Vec::new();
    let (header_end, content_length) = loop {
        let mut chunk = [0_u8; 8192];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("connection closed before request completed");
        }
        raw.extend_from_slice(&chunk[..read]);
        if raw.len() > 65536 + max {
            bail!("request too large");
        }
        if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..end]);
            let length = head
                .lines()
                .skip(1)
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if raw.len() >= end + 4 + length {
                break (end, length);
            }
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = head.lines();
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default().to_owned();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();
    let body = raw[header_end + 4..header_end + 4 + content_length].to_vec();
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn authorized(request: &Request, token: &[u8]) -> bool {
    request
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|presented| presented.as_bytes() == token)
}

async fn respond<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    status: u16,
    body: &[u8],
) -> Result<()> {
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn handle<S>(receiver: Arc<Receiver>, mut stream: S) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let request = read_request(&mut stream, receiver.max_envelope).await?;
    receiver.requests.fetch_add(1, Ordering::Relaxed);
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/checkpoint") => handle_checkpoint(receiver, &mut stream, &request).await,
        ("GET", "/checkpoint") => {
            if !authorized(&request, &receiver.token) {
                return respond(&mut stream, 401, b"{}").await;
            }
            let store = receiver.store.lock().await;
            let body = match store.checkpoint() {
                Some(checkpoint) => serde_json::to_vec(checkpoint)?,
                None => b"{}".to_vec(),
            };
            drop(store);
            respond(&mut stream, 200, &body).await
        }
        ("GET", "/__state") => {
            if !authorized(&request, &receiver.token) {
                return respond(&mut stream, 401, b"{}").await;
            }
            let fault = *receiver.fault.lock().await;
            let store = receiver.store.lock().await;
            let body = serde_json::to_vec(&json!({
                "fault": fault.name(),
                "requests": receiver.requests.load(Ordering::Relaxed),
                "accepted": receiver.accepted.load(Ordering::Relaxed),
                "duplicates": receiver.duplicates.load(Ordering::Relaxed),
                "rejected": receiver.rejected.load(Ordering::Relaxed),
                "checkpoint": store.checkpoint(),
            }))?;
            drop(store);
            respond(&mut stream, 200, &body).await
        }
        ("POST", "/__fault") => {
            if !authorized(&request, &receiver.token) {
                return respond(&mut stream, 401, b"{}").await;
            }
            #[derive(serde::Deserialize)]
            struct FaultRequest {
                mode: String,
            }
            let parsed: FaultRequest = match serde_json::from_slice(&request.body) {
                Ok(parsed) => parsed,
                Err(_) => return respond(&mut stream, 400, b"{}").await,
            };
            match Fault::parse(&parsed.mode) {
                Ok(fault) => {
                    *receiver.fault.lock().await = fault;
                    respond(&mut stream, 200, b"{}").await
                }
                Err(_) => respond(&mut stream, 400, b"{}").await,
            }
        }
        ("GET", "/__pubkey") => {
            let body = serde_json::to_vec(&json!({
                "receipt_verify_key": wire::verifying_key_b64(&receiver.signing_key),
            }))?;
            respond(&mut stream, 200, &body).await
        }
        _ => respond(&mut stream, 404, b"{}").await,
    }
}

async fn handle_checkpoint<S: AsyncWriteExt + Unpin>(
    receiver: Arc<Receiver>,
    stream: &mut S,
    request: &Request,
) -> Result<()> {
    let fault = *receiver.fault.lock().await;
    match fault {
        Fault::Http500 => return respond(stream, 500, b"{}").await,
        Fault::Drop => return stream.shutdown().await.map_err(Into::into),
        _ => {}
    }

    // Header authentication and deployment binding happen before parsing.
    let signature_ok = request
        .header("x-nazo-audit-signature")
        .is_some_and(|value| wire::verify_body_signature(&receiver.token, value, &request.body));
    let deployment_ok = request
        .header("x-nazo-audit-deployment")
        .is_some_and(|value| value == receiver.deployment_id);
    let schema_ok = request
        .header("x-nazo-audit-schema")
        .is_some_and(|value| value == wire::CHECKPOINT_SCHEMA_VERSION);
    let idempotency_ok = request
        .header("idempotency-key")
        .is_some_and(|value| !value.is_empty());
    if !(signature_ok && deployment_ok && schema_ok && idempotency_ok) {
        return respond(stream, 401, b"{}").await;
    }

    let kind = serde_json::from_slice::<serde_json::Value>(&request.body)
        .ok()
        .and_then(|value| value["checkpoint_kind"].as_str().map(str::to_owned))
        .unwrap_or_default();
    let receipt = match kind.as_str() {
        "genesis" => handle_genesis(&receiver, &request.body).await,
        "batch" => handle_batch(&receiver, &request.body).await,
        _ => Err(anyhow!("unknown checkpoint kind")),
    };
    let mut receipt = match receipt {
        Ok(receipt) => receipt,
        Err(_) => return respond(stream, 400, b"{}").await,
    };
    if matches!(fault, Fault::DropAfterPersist) {
        return stream.shutdown().await.map_err(Into::into);
    }
    if matches!(fault, Fault::RejectTransient | Fault::RejectPermanent) {
        receipt.status = "rejected".to_owned();
        receipt.reject_reason = Some(if matches!(fault, Fault::RejectPermanent) {
            "injected_permanent".to_owned()
        } else {
            "injected_transient".to_owned()
        });
        receipt.permanent = matches!(fault, Fault::RejectPermanent);
        receiver.rejected.fetch_add(1, Ordering::Relaxed);
    }
    let key = if matches!(fault, Fault::BadSignature) {
        &receiver.wrong_key
    } else {
        &receiver.signing_key
    };
    let body = wire::sign_receipt(receipt, key)?;
    respond(stream, 200, &body).await
}

async fn handle_genesis(receiver: &Arc<Receiver>, body: &[u8]) -> Result<wire::AnchorReceipt> {
    let envelope: wire::GenesisEnvelope = serde_json::from_slice(body)?;
    if envelope.schema_version != wire::CHECKPOINT_SCHEMA_VERSION
        || envelope.checkpoint_kind != "genesis"
        || envelope.event_id != wire::GENESIS_EVENT_ID
        || envelope.deployment_id != receiver.deployment_id
        || envelope.sequence != 0
        || envelope.previous_hash != envelope.event_hash
        || envelope.occurred_at != chrono::DateTime::<chrono::Utc>::UNIX_EPOCH
    {
        bail!("genesis envelope is malformed");
    }
    let digest = wire::batch_digest(
        &envelope.deployment_id,
        0,
        0,
        0,
        &wire::decode_hash(&envelope.event_hash)?,
        &wire::decode_hash(&envelope.event_hash)?,
        &[],
    );
    let digest = wire::encode_hash(&digest);
    let mut store = receiver.store.lock().await;
    match store.checkpoint().cloned() {
        Some(checkpoint)
            if checkpoint.checkpoint_kind == "genesis"
                && checkpoint.last_hash == envelope.event_hash
                && checkpoint.deployment_id == envelope.deployment_id =>
        {
            receiver.duplicates.fetch_add(1, Ordering::Relaxed);
            Ok(wire::receipt_for(
                "genesis",
                "duplicate",
                &envelope.deployment_id,
                0,
                0,
                0,
                &envelope.event_hash,
                &digest,
                None,
                false,
            ))
        }
        Some(checkpoint) => Ok(wire::receipt_for(
            "genesis",
            "rejected",
            &envelope.deployment_id,
            0,
            0,
            0,
            &envelope.event_hash,
            &digest,
            Some(format!("genesis_conflicts_with_{}", checkpoint.checkpoint_kind)),
            true,
        )),
        None => {
            store.record(
                body,
                Checkpoint {
                    deployment_id: envelope.deployment_id.clone(),
                    checkpoint_kind: "genesis".to_owned(),
                    last_sequence: 0,
                    last_hash: envelope.event_hash.clone(),
                    batch_digest: digest.clone(),
                    accepted_batches: 0,
                    accepted_events: 0,
                    updated_at: chrono::Utc::now(),
                },
            )?;
            receiver.accepted.fetch_add(1, Ordering::Relaxed);
            Ok(wire::receipt_for(
                "genesis",
                "accepted",
                &envelope.deployment_id,
                0,
                0,
                0,
                &envelope.event_hash,
                &digest,
                None,
                false,
            ))
        }
    }
}

async fn handle_batch(receiver: &Arc<Receiver>, body: &[u8]) -> Result<wire::AnchorReceipt> {
    let envelope: wire::BatchEnvelope = serde_json::from_slice(body)?;
    if envelope.schema_version != wire::CHECKPOINT_SCHEMA_VERSION
        || envelope.checkpoint_kind != "batch"
        || envelope.deployment_id != receiver.deployment_id
    {
        bail!("batch envelope is malformed");
    }
    let rejected = |reason: &str, permanent: bool| {
        wire::receipt_for(
            "batch",
            "rejected",
            &envelope.deployment_id,
            envelope.first_sequence,
            envelope.last_sequence,
            envelope.event_count,
            &envelope.last_hash,
            &envelope.batch_digest,
            Some(reason.to_owned()),
            permanent,
        )
    };
    if wire::verify_batch_content(&envelope).is_err() {
        return Ok(rejected("content_mismatch", true));
    }
    let mut store = receiver.store.lock().await;
    let Some(checkpoint) = store.checkpoint().cloned() else {
        return Ok(rejected("genesis_missing", true));
    };
    if checkpoint.deployment_id != envelope.deployment_id {
        return Ok(rejected("deployment_mismatch", true));
    }
    if checkpoint.last_sequence == envelope.last_sequence
        && checkpoint.batch_digest == envelope.batch_digest
    {
        receiver.duplicates.fetch_add(1, Ordering::Relaxed);
        return Ok(wire::receipt_for(
            "batch",
            "duplicate",
            &envelope.deployment_id,
            envelope.first_sequence,
            envelope.last_sequence,
            envelope.event_count,
            &envelope.last_hash,
            &envelope.batch_digest,
            None,
            false,
        ));
    }
    if checkpoint.last_sequence + 1 != envelope.first_sequence
        || checkpoint.last_hash != envelope.previous_hash
    {
        return Ok(rejected("chain_gap", true));
    }
    store.record(
        body,
        Checkpoint {
            deployment_id: envelope.deployment_id.clone(),
            checkpoint_kind: "batch".to_owned(),
            last_sequence: envelope.last_sequence,
            last_hash: envelope.last_hash.clone(),
            batch_digest: envelope.batch_digest.clone(),
            accepted_batches: checkpoint.accepted_batches + 1,
            accepted_events: checkpoint.accepted_events + envelope.event_count,
            updated_at: chrono::Utc::now(),
        },
    )?;
    receiver.accepted.fetch_add(1, Ordering::Relaxed);
    Ok(wire::receipt_for(
        "batch",
        "accepted",
        &envelope.deployment_id,
        envelope.first_sequence,
        envelope.last_sequence,
        envelope.event_count,
        &envelope.last_hash,
        &envelope.batch_digest,
        None,
        false,
    ))
}
