//! 结构化安全审计日志。

pub(crate) const AUDIT_SCHEMA_VERSION: &str = "nazo.audit.v1";

const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "access_token",
    "refresh_token",
    "authorization_code",
    "client_secret",
    "dpop_proof",
    "client_assertion",
];

const AUDIT_EVENT_DEFINITIONS: &[(&str, &str)] = &[
    ("admin_user_updated", "administration"),
    ("authorization_approved", "authorization"),
    ("authorization_denied", "authorization"),
    ("authorization_prompt_none_approved", "authorization"),
    ("client_assertion_replay_detected", "credential_replay"),
    ("client_created", "client_lifecycle"),
    ("client_updated", "client_lifecycle"),
    ("dpop_replay_detected", "credential_replay"),
    ("login_failure", "authentication"),
    ("login_success", "authentication"),
    ("refresh_reuse_detected", "token_replay"),
    ("refresh_rotated", "token_lifecycle"),
    ("token_issued", "token_lifecycle"),
    ("token_revoked", "token_lifecycle"),
];

pub(crate) fn audit_event(event: &str, mut fields: serde_json::Map<String, serde_json::Value>) {
    debug_assert!(audit_event_name_valid(event));
    debug_assert!(audit_event_category(event).is_some());
    for key in SENSITIVE_FIELD_NAMES {
        fields.remove(*key);
    }
    fields.insert(
        "schema_version".to_owned(),
        serde_json::Value::String(AUDIT_SCHEMA_VERSION.to_owned()),
    );
    if let Some(category) = audit_event_category(event) {
        fields.insert(
            "event_category".to_owned(),
            serde_json::Value::String(category.to_owned()),
        );
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

fn audit_event_category(event: &str) -> Option<&'static str> {
    AUDIT_EVENT_DEFINITIONS
        .iter()
        .find_map(|(name, category)| (*name == event).then_some(*category))
}

fn audit_event_name_valid(event: &str) -> bool {
    let mut chars = event.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
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

    #[test]
    fn audit_event_names_are_allowlisted_and_siem_ready() {
        for (name, category) in AUDIT_EVENT_DEFINITIONS {
            assert!(audit_event_name_valid(name));
            assert_eq!(audit_event_category(name), Some(*category));
            assert!(audit_event_name_valid(category));
        }
        assert!(audit_event_category("unknown_event").is_none());
        assert!(!audit_event_name_valid("LoginSuccess"));
        assert!(!audit_event_name_valid("login-success"));
        assert!(!audit_event_name_valid(""));
    }

    #[test]
    fn audit_schema_version_is_stable_for_collectors() {
        assert_eq!(AUDIT_SCHEMA_VERSION, "nazo.audit.v1");
    }
}
