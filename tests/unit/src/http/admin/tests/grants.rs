use super::*;

fn grant_row() -> GrantRow {
    GrantRow {
        user_id: Uuid::now_v7(),
        email: "user@example.com".to_owned(),
        client_id: "client-1".to_owned(),
        client_name: "Client One".to_owned(),
        last_authorized_at: Utc::now(),
        authorization_count: 3,
        last_scopes: json!(["openid", "payments", 42, null]),
        last_authorization_details: json!([{"type": "payment_initiation"}]),
    }
}

#[test]
fn grant_json_projects_authorization_record_without_internal_ids() {
    let row = grant_row();
    let value = grant_json(row);

    assert_eq!(value["email"], "user@example.com");
    assert_eq!(value["client_id"], "client-1");
    assert_eq!(value["client_name"], "Client One");
    assert_eq!(value["authorization_count"], 3);
    assert_eq!(value["last_scopes"], json!(["openid", "payments"]));
    assert_eq!(
        value["last_authorization_details"],
        json!([{"type": "payment_initiation"}])
    );
    assert!(value.get("client_pk").is_none());
    assert!(value.get("tenant_id").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn grants_list_response_preserves_pagination_and_scope_projection() {
    let response = grants_list_response(2, 50, 101, vec![grant_row()]);

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("grant list body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(101));
    assert_eq!(body["page"], json!(2));
    assert_eq!(body["page_size"], json!(50));
    let items = body["items"].as_array().expect("items should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["last_scopes"], json!(["openid", "payments"]));
    assert!(items[0].get("oauth_token_id").is_none());
}

#[actix_web::test]
async fn grant_revocation_response_reports_only_aggregate_state_change() {
    let response = grant_revocation_response(2, 1);

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("grant revocation body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["revoked_refresh_tokens"], json!(2));
    assert_eq!(body["removed_grants"], json!(1));
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("access_token").is_none());
}
