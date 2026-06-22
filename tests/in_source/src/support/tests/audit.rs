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
