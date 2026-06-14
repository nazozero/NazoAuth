use super::*;

fn access_request_row(status: AccessRequestStatus) -> UserAccessRequestRow {
    let now = Utc::now();
    UserAccessRequestRow {
        id: Uuid::now_v7(),
        site_name: "Client App".to_owned(),
        site_url: "https://client.example".to_owned(),
        request_description: "Need OpenID access".to_owned(),
        status: status.code(),
        admin_note: Some("review note".to_owned()),
        approved_client_id: Some(Uuid::now_v7()),
        created_at: now,
        resolved_at: Some(now),
    }
}

#[test]
fn user_access_request_json_omits_request_owner_and_client_secret_material() {
    let row = access_request_row(AccessRequestStatus::Approved);
    let value = user_access_request_json(row);

    assert_eq!(value["site_name"], "Client App");
    assert_eq!(value["site_url"], "https://client.example");
    assert_eq!(value["request_description"], "Need OpenID access");
    assert_eq!(value["status"], AccessRequestStatus::Approved.code());
    assert!(value.get("user_id").is_none());
    assert!(value.get("user_email").is_none());
    assert!(value.get("client_secret").is_none());
    assert!(value.get("client_secret_hash").is_none());
}

#[actix_web::test]
async fn my_access_requests_response_counts_only_pending_state() {
    let response = my_access_requests_response(vec![
        access_request_row(AccessRequestStatus::Pending),
        access_request_row(AccessRequestStatus::Approved),
        access_request_row(AccessRequestStatus::Rejected),
    ]);

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("access request body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(3));
    assert_eq!(body["pending_count"], json!(1));
    assert_eq!(
        body["items"]
            .as_array()
            .expect("items should be array")
            .len(),
        3
    );
    assert!(body.get("client_secret").is_none());
}

#[actix_web::test]
async fn create_access_request_response_uses_created_and_public_projection() {
    let response = create_access_request_response(access_request_row(AccessRequestStatus::Pending));

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("create access request body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["status"], AccessRequestStatus::Pending.code());
    assert!(body.get("user_id").is_none());
    assert!(body.get("client_secret").is_none());
}
