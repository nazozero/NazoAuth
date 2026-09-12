use actix_web::body::to_bytes;
use nazo_oauth_server::contracts::oauth_error::OAuthEndpointError;
use serde_json::Value;

use crate::{oauth_endpoint_error_response, oauth_error_description};
use actix_web::{HttpResponse, http::StatusCode};

async fn assert_error(response: HttpResponse, status: StatusCode, code: &str, description: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap())
        .expect("JSON error body");
    assert_eq!(body["error"], code);
    assert_eq!(
        body["error_description"],
        oauth_error_description(description).as_ref()
    );
}

#[actix_web::test]
async fn verification_errors_preserve_existing_oauth_contract() {
    for description in [
        "request object 无效.",
        "request object header 无效.",
        "request object claims 无效.",
        "request object 签名算法无效.",
        "request object 缺少 kid.",
        "request object 签名密钥无效.",
        "request object 验签失败.",
    ] {
        assert_error(
            oauth_endpoint_error_response(OAuthEndpointError::json(
                http::StatusCode::BAD_REQUEST,
                "invalid_request_object",
                description,
            )),
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            description,
        )
        .await;
    }
}

#[actix_web::test]
async fn policy_and_replay_errors_preserve_status_code_and_body() {
    for (status, code, description) in [
        (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request object 与外层 client_id 冲突.",
        ),
        (
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object jti 已使用.",
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "request object 防重放状态不可用.",
        ),
    ] {
        assert_error(
            oauth_endpoint_error_response(OAuthEndpointError::json(
                http::StatusCode::from_u16(status.as_u16()).unwrap(),
                code,
                description,
            )),
            status,
            code,
            description,
        )
        .await;
    }
}
