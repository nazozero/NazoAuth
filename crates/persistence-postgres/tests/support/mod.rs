pub mod query_counter;

use diesel::{migration::CREATE_MIGRATIONS_TABLE, sql_query, sql_types::Text};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _, SimpleAsyncConnection as _,
};

const PUBLIC_SECURITY_AUDIT_MIGRATION_VERSIONS: [&str; 21] = [
    "20260805000100",
    "20260905000100",
    "20260909000100",
    "20260919000100",
    "20260919000200",
    "20260920000100",
    "20260923000100",
    "20260924000100",
    "20260925000100",
    "20260927000100",
    "20260927000200",
    "20260929000400",
    "20261001000100",
    "20261001000200",
    "20261001000400",
    // Public refresh-family cutover and trigger run once per database.
    "20261001000500",
    "20261002000300",
    // These owners are fixed to public, independent of fixture search_path.
    "20261003000400",
    "20261003000500",
    "20261006000100",
    "20261006000200",
];
const PUBLIC_SECURITY_AUDIT_MIGRATIONS: [&str; 21] = [
    include_str!("../../../../migrations/20260805000100_security_audit_ledger/up.sql"),
    include_str!("../../../../migrations/20260905000100_shared_audit_anchor_state/up.sql"),
    include_str!("../../../../migrations/20260909000100_exporter_owned_audit_chain/up.sql"),
    include_str!("../../../../migrations/20260919000100_audit_outbox_exported_retention/up.sql"),
    include_str!("../../../../migrations/20260919000200_audit_outbox_ack_delete/up.sql"),
    include_str!("../../../../migrations/20260920000100_audit_anchor_batch_delivery/up.sql"),
    include_str!("../../../../migrations/20260923000100_security_audit_online_archive/up.sql"),
    include_str!("../../../../migrations/20260924000100_audit_delivery_scoped_retention/up.sql"),
    include_str!("../../../../migrations/20260925000100_audit_claim_bounded_scan/up.sql"),
    include_str!("../../../../migrations/20260927000100_audit_pending_event_set/up.sql"),
    include_str!("../../../../migrations/20260927000200_refresh_contract_ensure/up.sql"),
    include_str!("../../../../migrations/20260929000400_audit_claim_direct_reads/up.sql"),
    include_str!("../../../../migrations/20261001000100_authorization_decision_facts/up.sql"),
    include_str!(
        "../../../../migrations/20261001000200_authorization_decision_statement_timeout/up.sql"
    ),
    include_str!(
        "../../../../migrations/20261001000400_refresh_contract_reference_integrity/up.sql"
    ),
    include_str!("../../../../migrations/20261001000500_refresh_replay_retention/up.sql"),
    include_str!("../../../../migrations/20261002000300_audit_reachable_role_privileges/up.sql"),
    include_str!("../../../../migrations/20261003000400_access_request_required_outcomes/up.sql"),
    include_str!("../../../../migrations/20261003000500_audit_observation_freshness/up.sql"),
    include_str!("../../../../migrations/20261006000100_audit_ack_observation_clock/up.sql"),
    include_str!("../../../../migrations/20261006000200_audit_fresh_claim_finalization/up.sql"),
];

pub fn schema_database_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

pub async fn run_isolated_application_migrations(database_url: &str) {
    assert!(
        PUBLIC_SECURITY_AUDIT_MIGRATIONS[0]
            .contains("CREATE TABLE public.security_audit_chain_state")
            && PUBLIC_SECURITY_AUDIT_MIGRATIONS[1]
                .contains("ALTER TABLE public.security_audit_chain_state"),
        "the isolated-schema fixture must be reviewed if the public audit boundary changes"
    );

    assert!(
        PUBLIC_SECURITY_AUDIT_MIGRATIONS[17].contains("ALTER TABLE public.client_access_requests")
            && PUBLIC_SECURITY_AUDIT_MIGRATIONS[18]
                .contains("CREATE OR REPLACE FUNCTION public.nazo_observe_security_audit_anchor")
            && PUBLIC_SECURITY_AUDIT_MIGRATIONS[19]
                .contains("CREATE OR REPLACE FUNCTION public.nazo_ack_security_audit_batch")
            && PUBLIC_SECURITY_AUDIT_MIGRATIONS[20]
                .contains("CREATE FUNCTION public.nazo_finalize_security_audit_claim"),
        "public Required approval, observation, ACK and fresh-claim migrations must run only in the real database ledger"
    );

    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("isolated migration database should connect");
    connection
        .batch_execute(CREATE_MIGRATIONS_TABLE)
        .await
        .expect("isolated migration ledger should create");
    for version in PUBLIC_SECURITY_AUDIT_MIGRATION_VERSIONS {
        sql_query(
            "INSERT INTO __diesel_schema_migrations (version)
             VALUES ($1)
             ON CONFLICT (version) DO NOTHING",
        )
        .bind::<Text, _>(version)
        .execute(&mut connection)
        .await
        .expect("public-only migration should be excluded from the application schema fixture");
    }
    drop(connection);

    nazo_postgres::run_pending_migrations(database_url)
        .await
        .expect("isolated application schema migrations should apply");
}
