use super::*;
use actix_web::test::TestRequest;

#[actix_web::test]
async fn success_response_preserves_user_enumeration_resistance() {
    let response = send_code_success_response(false, Some("123456"));
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;

    assert_eq!(body.get("success"), Some(&json!(true)));
    assert_eq!(
        body.get("message").and_then(Value::as_str),
        Some("如果邮箱尚未注册，验证码将会发送。")
    );
    assert!(
        body.get("verification_code").is_none(),
        "normal success responses must not reveal whether an account exists or expose a code"
    );
}

#[actix_web::test]
async fn dev_success_response_exposes_code_only_when_explicitly_enabled_and_available() {
    let without_code = response_json(send_code_success_response(true, None)).await;
    assert!(
        without_code.get("verification_code").is_none(),
        "cooldown and existing-user paths must not invent a verification code"
    );

    let with_code = response_json(send_code_success_response(true, Some("654321"))).await;
    if cfg!(debug_assertions) {
        assert_eq!(with_code.get("verification_code"), Some(&json!("654321")));
    } else {
        assert!(
            with_code.get("verification_code").is_none(),
            "release builds must not leak verification codes even if dev response is configured"
        );
    }
}

#[test]
fn peer_cooldown_key_hashes_peer_identity_and_fails_closed_without_peer() {
    let request = TestRequest::default()
        .peer_addr("203.0.113.10:49152".parse().unwrap())
        .to_http_request();
    let key = email_code_peer_cooldown_key(&request);

    assert!(key.starts_with("oauth:email_verify:peer_send:"));
    assert!(
        !key.contains("203.0.113.10"),
        "rate-limit keys must not store raw peer identifiers"
    );
    assert_eq!(
        key,
        format!(
            "oauth:email_verify:peer_send:{}",
            blake3_hex("203.0.113.10")
        )
    );

    let missing_peer = TestRequest::default().to_http_request();
    assert_eq!(
        email_code_peer_cooldown_key(&missing_peer),
        format!("oauth:email_verify:peer_send:{}", blake3_hex("unknown")),
        "missing peer context must remain rate-limited under a stable fail-closed bucket"
    );
}

async fn response_json(response: HttpResponse) -> Value {
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&body).expect("response body should be json")
}
