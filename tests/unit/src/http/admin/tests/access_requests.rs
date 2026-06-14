use super::*;

fn query_with_status(value: &str) -> HashMap<String, String> {
    HashMap::from([("status".to_owned(), value.to_owned())])
}

fn oauth_error_name(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[test]
fn parse_access_request_status_accepts_only_protocol_state_codes() {
    assert!(
        parse_access_request_status(&HashMap::new())
            .expect("missing status should list all states")
            .is_none()
    );

    for (raw, expected) in [
        ("0", AccessRequestStatus::Pending.code()),
        (" 1 ", AccessRequestStatus::Approved.code()),
        ("2", AccessRequestStatus::Rejected.code()),
    ] {
        let parsed = parse_access_request_status(&query_with_status(raw))
            .expect("valid status should parse")
            .expect("status should be present");
        assert_eq!(parsed.code(), expected);
    }
}

#[test]
fn parse_access_request_status_rejects_malformed_and_unknown_states_fail_closed() {
    for raw in ["-1", "3", "approved", "1.0"] {
        let response = parse_access_request_status(&query_with_status(raw))
            .err()
            .expect("invalid status must not reach database filtering");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            oauth_error_name(&response).as_deref(),
            Some("invalid_request")
        );
    }
}

#[actix_web::test]
async fn access_requests_response_preserves_pagination_and_rows() {
    let request_id = Uuid::now_v7();
    let response = access_requests_response(
        4,
        25,
        77,
        vec![json!({
            "id": request_id,
            "site_name": "Client App",
            "status": AccessRequestStatus::Pending.code()
        })],
    );

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("access request list body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(77));
    assert_eq!(body["page"], json!(4));
    assert_eq!(body["page_size"], json!(25));
    assert_eq!(body["items"][0]["id"], json!(request_id));
    assert!(body.get("client_secret").is_none());
}

#[test]
fn duplicate_access_request_approval_uses_conflict_without_secret_material() {
    let response = access_request_already_approved_response();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn duplicate_access_request_rejection_uses_conflict_without_secret_material() {
    let response = access_request_already_rejected_response();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("invalid_request")
    );
}
