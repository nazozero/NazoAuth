//! 结构化安全审计日志。

const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "access_token",
    "refresh_token",
    "authorization_code",
    "client_secret",
    "dpop_proof",
    "client_assertion",
];

pub(crate) fn audit_event(event: &str, mut fields: serde_json::Map<String, serde_json::Value>) {
    for key in SENSITIVE_FIELD_NAMES {
        fields.remove(*key);
    }
    tracing::info!(
        target: "audit",
        event,
        fields = %serde_json::Value::Object(fields),
        "security audit event"
    );
}

pub(crate) fn audit_fields(
    items: &[(&str, serde_json::Value)],
) -> serde_json::Map<String, serde_json::Value> {
    items
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_fields_can_remove_sensitive_material() {
        let mut fields = audit_fields(&[
            ("client_id", json!("client-1")),
            ("access_token", json!("secret-token")),
        ]);
        for key in SENSITIVE_FIELD_NAMES {
            fields.remove(*key);
        }

        assert_eq!(fields.get("client_id"), Some(&json!("client-1")));
        assert!(fields.get("access_token").is_none());
    }
}
