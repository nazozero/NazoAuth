use super::*;
use crate::support::OAuthJsonErrorFields;

#[actix_web::test]
async fn delivery_payload_response_adds_read_once_notice_without_dropping_credentials() {
    let response = delivery_payload_response(
        r#"{"client_id":"client-1","client_secret":"secret-1","client_name":"Example"}"#,
    );

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["client_id"], "client-1");
    assert_eq!(body["client_secret"], "secret-1");
    assert_eq!(body["client_name"], "Example");
    assert_eq!(
        body["read_once_notice"],
        "此凭据链接已完成一次性读取并销毁，请立即保存敏感信息。"
    );
}

#[test]
fn delivery_payload_response_fails_closed_for_corrupted_stored_payload() {
    let response = delivery_payload_response("{not-json");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}
