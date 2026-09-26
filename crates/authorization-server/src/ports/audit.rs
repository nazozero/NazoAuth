//! Tenant-bound security audit capability.

pub type AuditFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>>;

pub trait SecurityAudit: Send + Sync {
    fn ensure_storage(&self) -> AuditFuture<'_>;

    /// Readiness when the required audit record commits before any business
    /// mutation, or in the same transaction as the mutation. That required
    /// append is the fail-closed writer check, so an implementation may elide
    /// the static capability probe; dynamic freshness gates still apply.
    /// Defaults to `ensure_storage` so existing adapters keep the stricter
    /// behavior until they opt in.
    fn ensure_transactional_ready(&self) -> AuditFuture<'_> {
        self.ensure_storage()
    }

    fn record(&self, event: &str, fields: serde_json::Map<String, serde_json::Value>);
    fn record_required<'a>(
        &'a self,
        event: &'a str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuditFuture<'a>;
}

pub fn audit_fields(
    items: &[(&str, serde_json::Value)],
) -> serde_json::Map<String, serde_json::Value> {
    items
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}
