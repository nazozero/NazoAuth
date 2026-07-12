use futures_util::future::{Ready, ready};
use http::header;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use super::{
    ResourceServerRequestError, ResourceServerVerifier, VerifiedAccessToken,
    VerifiedSenderConstraintProof, authorize_resource_request,
};

pub fn authorize_actix_request(
    verifier: &ResourceServerVerifier,
    request: &actix_web::HttpRequest,
) -> Result<VerifiedAccessToken, ResourceServerRequestError> {
    use actix_web::HttpMessage;

    let headers: Result<Vec<_>, _> = request
        .headers()
        .get_all(actix_web::http::header::AUTHORIZATION)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ResourceServerRequestError::InvalidRequest)
        })
        .collect();
    let headers = headers?;
    let proof = request
        .extensions()
        .get::<VerifiedSenderConstraintProof>()
        .cloned()
        .unwrap_or_default();
    let query = if request.query_string().is_empty() {
        None
    } else {
        Some(request.query_string())
    };
    let verified = authorize_resource_request(verifier, &headers, query, &proof)?;
    request.extensions_mut().insert(verified.clone());
    Ok(verified)
}

#[derive(Clone, Debug)]
pub struct ActixVerifiedAccessToken(pub VerifiedAccessToken);

impl actix_web::FromRequest for ActixVerifiedAccessToken {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let Some(verifier) = req.app_data::<actix_web::web::Data<ResourceServerVerifier>>() else {
            return ready(Err(actix_web::error::InternalError::from_response(
                "resource server verifier is not configured",
                actix_bearer_error_response(ResourceServerRequestError::InvalidRequest),
            )
            .into()));
        };
        ready(
            authorize_actix_request(verifier, req)
                .map(ActixVerifiedAccessToken)
                .map_err(|error| {
                    actix_web::error::InternalError::from_response(
                        format!("{error:?}"),
                        actix_bearer_error_response(error),
                    )
                    .into()
                }),
        )
    }
}

pub fn actix_bearer_error_response(error: ResourceServerRequestError) -> actix_web::HttpResponse {
    let status = http_status_for_request_error(&error);
    let (code, description) = bearer_error_fields(&error);
    let challenge = bearer_challenge_value(code, description);
    actix_web::HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::UNAUTHORIZED),
    )
    .insert_header((actix_web::http::header::WWW_AUTHENTICATE, challenge))
    .json(serde_json::json!({
        "error": code,
        "error_description": description
    }))
}

#[derive(Clone, Debug)]
pub struct TowerResourceServerLayer {
    verifier: ResourceServerVerifier,
}

impl TowerResourceServerLayer {
    pub fn new(verifier: ResourceServerVerifier) -> Self {
        Self { verifier }
    }
}

impl<S> Layer<S> for TowerResourceServerLayer {
    type Service = TowerResourceServerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TowerResourceServerService {
            inner,
            verifier: self.verifier.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TowerResourceServerService<S> {
    inner: S,
    verifier: ResourceServerVerifier,
}

#[derive(Debug)]
pub enum TowerResourceServerError<E> {
    Unauthorized(ResourceServerRequestError),
    Inner(E),
}

impl<S, B> Service<http::Request<B>> for TowerResourceServerService<S>
where
    S: Service<http::Request<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = TowerResourceServerError<S::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(TowerResourceServerError::Inner)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        if let Err(error) = super::authorize_http_request(&self.verifier, &mut request) {
            return Box::pin(async move { Err(TowerResourceServerError::Unauthorized(error)) });
        }
        let future = self.inner.call(request);
        Box::pin(async move { future.await.map_err(TowerResourceServerError::Inner) })
    }
}

pub fn authorize_tonic_request<T>(
    verifier: &ResourceServerVerifier,
    request: &mut tonic::Request<T>,
) -> Result<VerifiedAccessToken, tonic::Status> {
    let headers = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .into_iter()
        .collect::<Vec<_>>();
    let proof = request
        .extensions()
        .get::<VerifiedSenderConstraintProof>()
        .cloned()
        .unwrap_or_default();
    match authorize_resource_request(verifier, &headers, None, &proof) {
        Ok(verified) => {
            request.extensions_mut().insert(verified.clone());
            Ok(verified)
        }
        Err(error) => Err(tonic_status_for_request_error(error)),
    }
}

pub fn http_bearer_error_response(error: &ResourceServerRequestError) -> http::Response<String> {
    let status = http_status_for_request_error(error);
    let (code, description) = bearer_error_fields(error);
    http::Response::builder()
        .status(status)
        .header(
            header::WWW_AUTHENTICATE,
            bearer_challenge_value(code, description),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(format!(
            r#"{{"error":"{code}","error_description":"{description}"}}"#
        ))
        .expect("static bearer error response must be valid")
}

fn http_status_for_request_error(error: &ResourceServerRequestError) -> http::StatusCode {
    match error {
        ResourceServerRequestError::InvalidRequest => http::StatusCode::BAD_REQUEST,
        _ => http::StatusCode::UNAUTHORIZED,
    }
}

fn bearer_error_fields(error: &ResourceServerRequestError) -> (&'static str, &'static str) {
    match error {
        ResourceServerRequestError::InvalidRequest => (
            "invalid_request",
            "The request used an invalid access token transport.",
        ),
        ResourceServerRequestError::MissingToken => {
            ("invalid_token", "Missing bearer access token.")
        }
        ResourceServerRequestError::MissingSenderConstraint => (
            "invalid_token",
            "Sender-constrained access token requires verified proof.",
        ),
        ResourceServerRequestError::DpopBindingMismatch => {
            ("invalid_token", "DPoP proof does not match access token.")
        }
        ResourceServerRequestError::MtlsBindingMismatch => (
            "invalid_token",
            "Client certificate does not match access token.",
        ),
        ResourceServerRequestError::InvalidToken(_) => {
            ("invalid_token", "Access token is invalid.")
        }
        ResourceServerRequestError::InvalidDpopProof(_) => {
            ("invalid_token", "DPoP proof is invalid.")
        }
    }
}

fn bearer_challenge_value(error: &str, description: &str) -> String {
    format!(r#"Bearer error="{error}", error_description="{description}""#)
}

fn tonic_status_for_request_error(error: ResourceServerRequestError) -> tonic::Status {
    match error {
        ResourceServerRequestError::InvalidRequest => {
            tonic::Status::invalid_argument("invalid_request")
        }
        _ => tonic::Status::unauthenticated("invalid_token"),
    }
}
