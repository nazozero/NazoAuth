use super::*;

#[test]
fn access_request_json_preserves_admin_review_fields() {
    let id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let approved_client_id = Uuid::now_v7();
    let created_at = Utc::now();
    let resolved_at = created_at + chrono::Duration::minutes(5);

    let body = access_request_json(nazo_postgres::AccessRequestProjection {
        id,
        user_id,
        user_email: "user@example.com".to_owned(),
        site_name: "Example App".to_owned(),
        site_url: "https://client.example".to_owned(),
        request_description: "Needs profile access".to_owned(),
        status: AccessRequestStatus::Approved.code(),
        admin_note: Some("approved after review".to_owned()),
        approved_client_id: Some(approved_client_id),
        created_at,
        resolved_at: Some(resolved_at),
    });

    assert_eq!(body["id"], json!(id));
    assert_eq!(body["user_id"], json!(user_id));
    assert_eq!(body["user_email"], "user@example.com");
    assert_eq!(body["site_name"], "Example App");
    assert_eq!(body["site_url"], "https://client.example");
    assert_eq!(body["request_description"], "Needs profile access");
    assert_eq!(body["status"], AccessRequestStatus::Approved.code());
    assert_eq!(body["admin_note"], "approved after review");
    assert_eq!(body["approved_client_id"], json!(approved_client_id));
    assert_eq!(body["created_at"], json!(created_at));
    assert_eq!(body["resolved_at"], json!(resolved_at));
}
