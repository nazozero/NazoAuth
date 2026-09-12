use super::*;
use nazo_auth::{AuthorizationPortError, AuthorizationRequestError};
fn assert_error(error: OAuthEndpointError, status: StatusCode, code: &str, description: &str) {
    let OAuthEndpointError::Json(fields) = error else {
        panic!("JSON error expected")
    };
    assert_eq!(fields.status, status);
    assert_eq!(fields.error, code);
    assert_eq!(fields.description, description);
}
#[test]
fn verification_errors_preserve_existing_oauth_contract() {
    for (error, description) in [
        (
            RequestObjectVerificationError::InvalidCompact,
            "request object 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidHeader,
            "request object header 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidClaims,
            "request object claims 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidAlgorithm,
            "request object 签名算法无效.",
        ),
        (
            RequestObjectVerificationError::MissingKeyId,
            "request object 缺少 kid.",
        ),
        (
            RequestObjectVerificationError::InvalidKey,
            "request object 签名密钥无效.",
        ),
        (
            RequestObjectVerificationError::InvalidSignature,
            "request object 验签失败.",
        ),
    ] {
        assert_error(
            request_object_verification_error(error),
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            description,
        );
    }
}

#[test]
fn policy_and_replay_errors_preserve_status_code_and_body() {
    for (error, status, code, description) in [
        (
            AuthorizationRequestError::OuterClientIdConflict,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request object 与外层 client_id 冲突.",
        ),
        (
            AuthorizationRequestError::InvalidRequestObjectReplay,
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object jti 已使用.",
        ),
        (
            AuthorizationRequestError::Dependency(AuthorizationPortError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "request object 防重放状态不可用.",
        ),
    ] {
        assert_error(
            request_object_policy_error(error),
            status,
            code,
            description,
        );
    }
}
