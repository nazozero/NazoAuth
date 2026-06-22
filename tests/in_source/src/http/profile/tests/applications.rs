use super::*;

#[test]
fn my_application_json_preserves_authorization_metadata_and_filters_bad_scope_values() {
    let now = Utc::now();
    let value = my_application_json(MyApplicationRow {
        client_id: "client-1".to_owned(),
        client_name: "Example Client".to_owned(),
        last_scopes: json!(["openid", "profile", 42, null, {"scope": "admin"}]),
        last_authorized_at: now,
        authorization_count: 3,
    });

    assert_eq!(value["client_id"], "client-1");
    assert_eq!(value["client_name"], "Example Client");
    assert_eq!(value["last_scopes"], json!(["openid", "profile"]));
    assert_eq!(value["last_authorized_at"], json!(now));
    assert_eq!(value["authorization_count"], 3);
}
