use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use nazo_auth::TokenInspection;

use crate::{
    TokenOnlyForm, authorization_error_response, empty_response_no_store, json_response_no_store,
    oauth_token_error, parse_token_management_form, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};

pub const TOKEN_INTROSPECTION_JWT_MEDIA_TYPE: &str = "application/token-introspection+jwt";

pub type TokenManagementFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TokenManagementError>> + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenManagementRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenManagementError {
    InvalidClient { basic_challenge: bool },
    AuthenticationStoreUnavailable,
    ClientLookupUnavailable,
    InspectionUnavailable,
    RevocationUnavailable,
    ResponseProtectionFailed,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TokenIntrospectionRepresentation {
    Inspection(TokenInspection),
    Jwt(String),
}

pub trait TokenManagementRequestGuard: Send + Sync {
    fn enforce<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>>;
}

pub trait TokenManagementOperations: Send + Sync {
    fn introspect<'a>(
        &'a self,
        request: &'a HttpRequest,
        form: TokenOnlyForm,
        signed_response_requested: bool,
    ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation>;

    fn revoke<'a>(
        &'a self,
        request: &'a HttpRequest,
        form: TokenOnlyForm,
    ) -> TokenManagementFuture<'a, ()>;
}

#[derive(Clone)]
pub struct TokenManagementEndpoint {
    guard: Arc<dyn TokenManagementRequestGuard>,
    operations: Arc<dyn TokenManagementOperations>,
}

impl TokenManagementEndpoint {
    pub fn new(
        guard: Arc<dyn TokenManagementRequestGuard>,
        operations: Arc<dyn TokenManagementOperations>,
    ) -> Self {
        Self { guard, operations }
    }
}

pub async fn introspect(
    endpoint: Data<TokenManagementEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&endpoint, &request).await {
        return response;
    }
    let form = match parse_token_management_form(&request, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };
    let has_basic = has_basic_authorization_scheme(&request);
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    let signed_response_requested = signed_introspection_requested(&request);
    match endpoint
        .operations
        .introspect(&request, form, signed_response_requested)
        .await
    {
        Ok(TokenIntrospectionRepresentation::Inspection(inspection)) => {
            json_response_no_store(inspection.into_document())
        }
        Ok(TokenIntrospectionRepresentation::Jwt(token)) => HttpResponse::Ok()
            .insert_header((
                header::CONTENT_TYPE,
                header::HeaderValue::from_static(TOKEN_INTROSPECTION_JWT_MEDIA_TYPE),
            ))
            .insert_header((
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            ))
            .insert_header((header::PRAGMA, header::HeaderValue::from_static("no-cache")))
            .body(token),
        Err(error) => token_management_error_response(error),
    }
}

pub async fn revoke(
    endpoint: Data<TokenManagementEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&endpoint, &request).await {
        return response;
    }
    let form = match parse_token_management_form(&request, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };
    let has_basic = has_basic_authorization_scheme(&request);
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    match endpoint.operations.revoke(&request, form).await {
        Ok(()) => empty_response_no_store(StatusCode::OK),
        Err(error) => token_management_error_response(error),
    }
}

fn has_basic_authorization_scheme(request: &HttpRequest) -> bool {
    let Some(raw) = request
        .headers()
        .get(header::AUTHORIZATION)
        .map(header::HeaderValue::as_bytes)
    else {
        return false;
    };
    let start = raw
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(raw.len());
    raw[start..end].eq_ignore_ascii_case(b"Basic")
}

fn signed_introspection_requested(request: &HttpRequest) -> bool {
    request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';').next().is_some_and(|media_type| {
                    media_type.trim() == TOKEN_INTROSPECTION_JWT_MEDIA_TYPE
                })
            })
        })
}

async fn enforce_rate_limit(
    endpoint: &TokenManagementEndpoint,
    request: &HttpRequest,
) -> Result<(), HttpResponse> {
    match endpoint.guard.enforce(request).await {
        Ok(()) => Ok(()),
        Err(TokenManagementRateLimitError::Unavailable) => Err(token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        )),
        Err(TokenManagementRateLimitError::Limited {
            retry_after_seconds,
        }) => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "请求过于频繁，请稍后重试.",
            );
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            Err(response)
        }
    }
}

fn token_management_error_response(error: TokenManagementError) -> HttpResponse {
    match error {
        TokenManagementError::InvalidClient { basic_challenge } => oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            basic_challenge,
        ),
        TokenManagementError::AuthenticationStoreUnavailable => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
            false,
        ),
        TokenManagementError::ClientLookupUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端查询失败.",
        ),
        TokenManagementError::InspectionUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token 状态查询失败.",
        ),
        TokenManagementError::RevocationUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token 撤销失败.",
        ),
        TokenManagementError::ResponseProtectionFailed => token_management_oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "token introspection JWT response build failed.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{App, http::header, test, web};

    use super::*;

    #[derive(Clone, Copy)]
    struct FakeGuard(Result<(), TokenManagementRateLimitError>);

    impl TokenManagementRequestGuard for FakeGuard {
        fn enforce<'a>(
            &'a self,
            _request: &'a HttpRequest,
        ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>>
        {
            let result = self.0;
            Box::pin(async move { result })
        }
    }

    #[derive(Clone)]
    struct FakeOperations {
        introspection: Result<TokenIntrospectionRepresentation, TokenManagementError>,
        revocation: Result<(), TokenManagementError>,
    }

    impl TokenManagementOperations for FakeOperations {
        fn introspect<'a>(
            &'a self,
            _request: &'a HttpRequest,
            _form: TokenOnlyForm,
            _signed_response_requested: bool,
        ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation> {
            let result = self.introspection.clone();
            Box::pin(async move { result })
        }

        fn revoke<'a>(
            &'a self,
            _request: &'a HttpRequest,
            _form: TokenOnlyForm,
        ) -> TokenManagementFuture<'a, ()> {
            let result = self.revocation;
            Box::pin(async move { result })
        }
    }

    fn endpoint(
        guard: Result<(), TokenManagementRateLimitError>,
        introspection: Result<TokenIntrospectionRepresentation, TokenManagementError>,
        revocation: Result<(), TokenManagementError>,
    ) -> TokenManagementEndpoint {
        TokenManagementEndpoint::new(
            Arc::new(FakeGuard(guard)),
            Arc::new(FakeOperations {
                introspection,
                revocation,
            }),
        )
    }

    fn form_request(method: &'static str, path: &'static str) -> test::TestRequest {
        let request = match method {
            "POST" => test::TestRequest::post(),
            _ => unreachable!("only POST is used"),
        };
        request
            .uri(path)
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("token=opaque&client_id=client")
    }

    #[actix_web::test]
    async fn rate_limit_runs_before_form_parsing_and_keeps_retry_contract() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Err(TokenManagementRateLimitError::Limited {
                        retry_after_seconds: 30,
                    }),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/introspect")
                .set_payload("not-a-form")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "30");
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "temporarily_unavailable");
    }

    #[actix_web::test]
    async fn inactive_introspection_is_exact_rfc7662_no_store_json() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response =
            test::call_service(&service, form_request("POST", "/introspect").to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body, serde_json::json!({"active": false}));
    }

    #[actix_web::test]
    async fn signed_introspection_keeps_media_type_and_cache_headers() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Jwt(
                        "signed.jwt".to_owned(),
                    )),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response = test::call_service(
            &service,
            form_request("POST", "/introspect")
                .insert_header((header::ACCEPT, TOKEN_INTROSPECTION_JWT_MEDIA_TYPE))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            TOKEN_INTROSPECTION_JWT_MEDIA_TYPE
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(test::read_body(response).await, "signed.jwt");
    }

    #[actix_web::test]
    async fn basic_invalid_client_keeps_challenge_and_oauth_error() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Err(TokenManagementError::InvalidClient {
                        basic_challenge: true,
                    }),
                    Ok(()),
                )))
                .route("/introspect", web::post().to(introspect)),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/introspect")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .set_payload("token=opaque")
                .insert_header((header::AUTHORIZATION, "Basic Y2xpZW50OnNlY3JldA=="))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Basic realm=\"nazo-oauth\""
        );
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "invalid_client");
    }

    #[actix_web::test]
    async fn revocation_success_is_empty_and_non_cacheable() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(
                    Ok(()),
                    Ok(TokenIntrospectionRepresentation::Inspection(
                        TokenInspection::Inactive,
                    )),
                    Ok(()),
                )))
                .route("/revoke", web::post().to(revoke)),
        )
        .await;
        let response =
            test::call_service(&service, form_request("POST", "/revoke").to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert!(test::read_body(response).await.is_empty());
    }
}
