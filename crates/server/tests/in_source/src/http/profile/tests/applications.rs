use chrono::Utc;
use serde_json::json;

#[test]
fn profile_core_handlers_use_focused_dependencies() {
    let sources = [
        include_str!("../../../../../../src/http/profile/account.rs"),
        include_str!("../../../../../../src/http/profile/applications.rs"),
        include_str!("../../../../../../src/http/profile/access_requests.rs"),
        include_str!("../../../../../../src/http/profile/delivery.rs"),
        include_str!("../../../../../../src/http/profile/federation_links.rs"),
        include_str!("../../../../../../src/http/profile/avatar.rs"),
    ]
    .join("\n");

    for legacy_signature in [
        "fn me(state: Data<AppState>",
        "fn update_me(\n    state: Data<AppState>",
        "fn my_applications(state: Data<AppState>",
        "fn my_access_requests(state: Data<AppState>",
        "fn create_access_request(\n    state: Data<AppState>",
        "fn access_delivery(\n    state: Data<AppState>",
        "fn my_federation_links(state: Data<AppState>",
        "fn unlink_my_federation_link(\n    state: Data<AppState>",
        "fn upload_avatar(\n    state: Data<AppState>",
        "fn get_avatar(state: Data<AppState>",
        "fn delete_avatar(state: Data<AppState>",
    ] {
        assert!(
            !sources.contains(legacy_signature),
            "profile handler regressed to giant AppState: {legacy_signature}"
        );
    }
    for infrastructure_dependency in ["nazo_postgres::", "nazo_valkey::"] {
        assert!(
            !sources.contains(infrastructure_dependency),
            "profile transport depends on infrastructure adapter: {infrastructure_dependency}"
        );
    }
    assert!(
        !sources.contains("tokio::fs"),
        "profile transport performs filesystem IO directly"
    );
}

#[test]
fn my_application_json_preserves_authorization_metadata_and_filters_bad_scope_values() {
    let now = Utc::now();
    let value = serde_json::to_value(nazo_identity::AuthorizedApplicationView::from(
        nazo_identity::ports::AuthorizedApplication {
            client_id: "client-1".to_owned(),
            client_name: "Example Client".to_owned(),
            last_scopes: json!(["openid", "profile", 42, null, {"scope": "admin"}]),
            last_authorized_at: now,
            authorization_count: 3,
        },
    ))
    .unwrap();

    assert_eq!(value["client_id"], "client-1");
    assert_eq!(value["client_name"], "Example Client");
    assert_eq!(value["last_scopes"], json!(["openid", "profile"]));
    assert_eq!(value["last_authorized_at"], json!(now));
    assert_eq!(value["authorization_count"], 3);
}
