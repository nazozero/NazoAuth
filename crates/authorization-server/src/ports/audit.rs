//! Tenant-bound security audit capability.

pub type AuditFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>>;

pub trait SecurityAudit: Send + Sync {
    fn ensure_storage(&self) -> AuditFuture<'_>;
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
