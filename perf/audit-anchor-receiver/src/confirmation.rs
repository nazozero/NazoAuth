//! Receiver-owned database confirmation after the durable store has fsynced.
//! TLS verifies the database hostname and configured CA (or public roots).
use crate::wire::{decode_hash, AnchorReceipt};
use anyhow::{bail, Context, Result};
use tokio_postgres::{config::SslMode, Config, NoTls};

pub struct DatabaseConfirmation {
    config: Config,
    tls: tokio_postgres_rustls::MakeRustlsConnect,
}

pub fn configuration(url: &str) -> Result<DatabaseConfirmation> {
    let mut config: Config = url
        .parse()
        .context("invalid receiver database configuration")?;
    // Do not let libpq's Prefer mode silently fall back to plaintext.
    if config.get_ssl_mode() != SslMode::Disable {
        config.ssl_mode(SslMode::Require);
    }
    let tls = if let Ok(path) = std::env::var("ANCHOR_RECEIVER_DATABASE_CA") {
        let mut input = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut input) {
            roots.add(cert?)?;
        }
        if roots.is_empty() {
            bail!("receiver database CA bundle is empty");
        }
        tokio_postgres_rustls::MakeRustlsConnect::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    } else {
        tokio_postgres_rustls::MakeRustlsConnect::with_webpki_roots()
    };
    Ok(DatabaseConfirmation { config, tls })
}

pub async fn confirm(
    database: &DatabaseConfirmation,
    receipt: &AnchorReceipt,
    generation: Option<i64>,
) -> Result<()> {
    let last_hash = decode_hash(&receipt.last_hash)?.to_vec();
    let digest = decode_hash(&receipt.batch_digest)?.to_vec();
    let (mut client, driver) = if database.config.get_ssl_mode() == SslMode::Disable {
        let (client, connection) = database.config.connect(NoTls).await?;
        (client, tokio::spawn(connection))
    } else {
        let (client, connection) = database.config.connect(database.tls.clone()).await?;
        (client, tokio::spawn(connection))
    };
    let result = async {
        let transaction = client.transaction().await?;
        let changed: bool = if receipt.checkpoint_kind == "genesis" {
            transaction.query_one("SELECT public.nazo_record_security_audit_genesis($1,$2)",
                &[&receipt.deployment_id, &last_hash]).await?.get(0)
        } else {
            let generation = generation.filter(|v| *v > 0).context("missing audit batch generation")?;
            let count = i32::try_from(receipt.event_count)?;
            transaction.query_one("SELECT public.nazo_ack_security_audit_batch($1,$2,$3,$4,$5,$6,$7)",
                &[&generation,&receipt.first_sequence,&receipt.last_sequence,&count,&last_hash,&digest,&receipt.deployment_id]).await?.get(0)
        };
        if !changed {
            // ACK may have committed before an earlier response/connection loss.
            let row = transaction.query_one("SELECT anchor_deployment_id = $1 AND anchor_accepted_at IS NOT NULL AND (anchor_sequence > $2 OR (anchor_sequence = $2 AND anchor_hash = $3)) FROM public.nazo_security_audit_shared_anchor_health()", &[&receipt.deployment_id,&receipt.last_sequence,&last_hash]).await?;
            if row.get::<_,Option<bool>>(0) != Some(true) { bail!("audit receiver confirmation is stale or mismatched"); }
        }
        transaction.commit().await?;
        Ok(())
    }.await;
    drop(client);
    let _ = driver.await;
    result
}
