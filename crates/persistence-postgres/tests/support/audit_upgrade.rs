use diesel_async::{AsyncConnection as _, AsyncPgConnection, SimpleAsyncConnection as _};

// Real application tables satisfy the facts migration's ACL probes. These
// migrations run only after the historical target's preservation assertions.
const CURRENT_AUDIT_MIGRATIONS: &[&str] = &[
    include_str!("../../../../migrations/20260228000100_rust_baseline/up.sql"),
    include_str!("../../../../migrations/20260929000400_audit_claim_direct_reads/up.sql"),
    include_str!("../../../../migrations/20261001000100_authorization_decision_facts/up.sql"),
    include_str!(
        "../../../../migrations/20261001000200_authorization_decision_statement_timeout/up.sql"
    ),
    include_str!("../../../../migrations/20261002000300_audit_reachable_role_privileges/up.sql"),
    include_str!("../../../../migrations/20261003000500_audit_observation_freshness/up.sql"),
    include_str!("../../../../migrations/20261006000100_audit_ack_observation_clock/up.sql"),
    include_str!("../../../../migrations/20261006000200_audit_fresh_claim_finalization/up.sql"),
];

pub async fn upgrade_to_current_audit_schema(owner: &mut AsyncPgConnection) {
    for migration in CURRENT_AUDIT_MIGRATIONS {
        owner
            .transaction::<_, diesel::result::Error, _>(async |connection| {
                connection
                    .batch_execute("SET LOCAL search_path = public")
                    .await?;
                connection.batch_execute(migration).await
            })
            .await
            .expect("the current audit schema's real migration dependency chain should apply");
    }
}
