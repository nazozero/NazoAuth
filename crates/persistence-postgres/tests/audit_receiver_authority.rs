//! A stolen exporter login cannot acknowledge or erase undelivered evidence.
use diesel_async::{AsyncConnection, AsyncPgConnection, SimpleAsyncConnection};
use nazo_persistence::{SecurityAuditBatchAck, SecurityAuditBatchClaim};
use nazo_postgres::{
    AuditLedgerRepository, SecurityAuditEvent, create_pool, run_pending_migrations,
};
use uuid::Uuid;

const CUTOVER: &str =
    include_str!("../../../migrations/20261011000100_receiver_owned_audit_ack/up.sql");
const ACK: &str =
    "public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)";
const GENESIS: &str = "public.nazo_record_security_audit_genesis(text,bytea)";
const EXPORT: &str = "public.nazo_security_audit_shared_privilege_preflight(boolean,boolean,boolean),public.nazo_security_audit_chain_head_for_update(),public.nazo_security_audit_batch_members(),public.nazo_claim_security_audit_pending(bigint),public.nazo_open_security_audit_batch(bigint,bigint,integer,bytea,integer),public.nazo_finalize_security_audit_claim(bigint,bytea,uuid[],bytea[],bigint,bigint,integer,bytea,integer),public.nazo_reclaim_security_audit_batch(bytea,integer),public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[]),public.nazo_fail_security_audit_batch(bigint,timestamptz,text,boolean),public.nazo_observe_security_audit_anchor(text),public.nazo_security_audit_shared_anchor_health()";
const HEALTH: &str = "public.nazo_security_audit_shared_anchor_health()";

#[tokio::test]
async fn exporter_ack_is_denied_until_independent_receiver_confirms() {
    let base =
        std::env::var("NAZO_AUDIT_TEST_DATABASE_URL").expect("isolated audit database required");
    let tag = Uuid::now_v7().simple().to_string();
    let database = format!("receiver_{tag}");
    let exporter = format!("exporter_{tag}");
    let receiver = format!("receiver_{tag}");
    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&database);
    run_pending_migrations(url.as_str()).await.unwrap();
    let mut owner = AsyncPgConnection::establish(url.as_str()).await.unwrap();
    owner.batch_execute(&format!("CREATE ROLE {exporter} LOGIN PASSWORD '{tag}' NOSUPERUSER NOINHERIT; CREATE ROLE {receiver} LOGIN PASSWORD '{tag}' NOSUPERUSER NOINHERIT; GRANT USAGE ON SCHEMA public TO {exporter},{receiver}; GRANT EXECUTE ON FUNCTION {EXPORT},{ACK},{GENESIS} TO {exporter}; GRANT EXECUTE ON FUNCTION {ACK},{GENESIS},{HEALTH} TO {receiver};")).await.unwrap();
    let writer = AuditLedgerRepository::new(create_pool(url.as_str().to_owned(), 2).unwrap());
    let role_repo = |role: &str| {
        let mut role_url = url.clone();
        role_url.set_username(role).unwrap();
        role_url.set_password(Some(&tag)).unwrap();
        AuditLedgerRepository::new(create_pool(role_url.as_str().to_owned(), 2).unwrap())
    };
    let exported = role_repo(&exporter);
    // The old documented grant permits deletion without any receiver receipt.
    for phase in 0..2 {
        writer
            .append(SecurityAuditEvent {
                event_id: Uuid::now_v7(),
                event_type: "security_fixture".into(),
                event_category: "test".into(),
                payload: serde_json::json!({"phase":phase}),
                occurred_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let SecurityAuditBatchClaim::Claimed(batch) = exported
            .claim_batch("receiver-proof", 1, 131072, 60)
            .await
            .unwrap()
        else {
            panic!("expected real claim")
        };
        let ack = SecurityAuditBatchAck {
            generation: batch.generation,
            deployment_id: "receiver-proof".into(),
            first_sequence: batch.first_sequence,
            last_sequence: batch.last_sequence,
            event_count: batch.event_count(),
            last_hash: batch.last_hash,
            batch_digest: batch.digest,
        };
        if phase == 0 {
            exported.ack_batch(ack).await.unwrap();
            assert!(!writer.anchor_health().await.unwrap().pending_exists);
        } else {
            owner.batch_execute(CUTOVER).await.unwrap();
            exported.check_exporter_available().await.unwrap();
            assert!(exported.ack_batch(ack.clone()).await.is_err());
            assert!(exported.confirm_batch(ack.clone()).await.is_err());
            assert!(writer.anchor_health().await.unwrap().pending_exists);
            assert!(exported.record_genesis("forged", &[0; 32]).await.is_err());
            // Migration stripped ALL historical grants. Give ACK only to the receiver.
            owner
                .batch_execute(&format!(
                    "GRANT EXECUTE ON FUNCTION {ACK},{GENESIS},{HEALTH} TO {receiver}"
                ))
                .await
                .unwrap();
            owner
                .batch_execute(&format!(
                    "GRANT {receiver} TO {exporter} WITH INHERIT FALSE, SET TRUE"
                ))
                .await
                .unwrap();
            assert!(exported.check_exporter_available().await.is_err());
            owner
                .batch_execute(&format!("REVOKE {receiver} FROM {exporter}"))
                .await
                .unwrap();
            exported.check_exporter_available().await.unwrap();
            let received = role_repo(&receiver);
            received.ack_batch(ack.clone()).await.unwrap();
            exported.confirm_batch(ack).await.unwrap();
            assert!(!writer.anchor_health().await.unwrap().pending_exists);
            drop(received);
        }
    }
    drop(writer);
    drop(exported);
    drop(owner);
    admin
        .batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .await
        .unwrap();
    admin
        .batch_execute(&format!("DROP ROLE {exporter},{receiver}"))
        .await
        .unwrap();
}
