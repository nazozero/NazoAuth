use crate::http::{Request, Response};
use bytes::Bytes;
use http::header;
use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use nazo_openid4vp::AuthorizationResponse;
use nazo_openid4vp::application::{
    CreatePresentationRequest, PresentationHttpError, PresentationOperations,
    PresentationResponseBody, PresentationResponseInput,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
pub struct PresentationEndpoint {
    operations: Arc<dyn PresentationOperations>,
    management_token: Arc<[u8]>,
}

impl PresentationEndpoint {
    pub fn new(
        operations: Arc<dyn PresentationOperations>,
        management_token: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            operations,
            management_token: management_token.into().into(),
        }
    }

    fn management_authorized(&self, request: &Request) -> bool {
        if self.management_token.is_empty() {
            return false;
        }
        let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Some((scheme, provided)) = value.to_str().ok().and_then(|value| value.split_once(' '))
        else {
            return false;
        };
        scheme.eq_ignore_ascii_case("Bearer")
            && !provided.is_empty()
            && !provided.chars().any(char::is_whitespace)
            && constant_time_eq(provided.as_bytes(), &self.management_token)
    }
}

pub async fn create_presentation(
    endpoint: &PresentationEndpoint,
    request: &Request,
    body: CreatePresentationRequest,
) -> Response {
    if !endpoint.management_authorized(request) {
        return management_unauthorized();
    }
    match endpoint.operations.create(body).await {
        Ok(value) => json_no_store_no_referrer(value),
        Err(error) => presentation_error(error),
    }
}

pub async fn presentation_request(
    endpoint: &PresentationEndpoint,
    transaction_id: Uuid,
    form: Option<WalletNonceForm>,
) -> Response {
    let wallet_nonce = form.as_ref().and_then(|form| form.wallet_nonce.as_deref());
    match endpoint
        .operations
        .request(transaction_id, wallet_nonce)
        .await
    {
        Ok(PresentationResponseBody::RequestObject(jwt)) => crate::http::finish(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/oauth-authz-req+jwt")
                .header(header::CACHE_CONTROL, "no-store"),
            jwt,
        ),
        Ok(PresentationResponseBody::Json(value)) => json_no_store(value),
        Err(error) => presentation_error(error),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct WalletNonceForm {
    pub wallet_nonce: Option<String>,
}

pub async fn presentation_response(
    endpoint: &PresentationEndpoint,
    transaction_id: Uuid,
    request: &Request,
    body: &Bytes,
) -> Response {
    let response = match parse_presentation_response(request, body) {
        Ok(response) => response,
        Err(error) => return presentation_error(error),
    };
    match endpoint.operations.respond(transaction_id, response).await {
        Ok(Some(redirect_uri)) => crate::http::json(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header(header::CACHE_CONTROL, "no-store"),
            serde_json::json!({"redirect_uri": redirect_uri}),
        ),
        Ok(None) => crate::http::json(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header(header::CACHE_CONTROL, "no-store"),
            serde_json::json!({}),
        ),
        Err(error) => presentation_error(error),
    }
}

pub async fn presentation_complete(
    endpoint: &PresentationEndpoint,
    transaction_id: Uuid,
) -> Response {
    match endpoint.operations.result(transaction_id).await {
        Ok(_) => crate::http::finish(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header(header::CACHE_CONTROL, "no-store")
                .header(header::REFERRER_POLICY, "no-referrer")
                .header(
                    "Content-Security-Policy",
                    "default-src 'none'; frame-ancestors 'none'",
                ),
            "<!doctype html><html><head><meta charset=utf-8><title>Presentation verified</title></head><body><main data-testid=\"vp-verification-result\" data-status=\"verified\"><h1>Presentation verified</h1><p>The credential presentation was verified successfully.</p></main></body></html>",
        ),
        Err(error) => presentation_error(error),
    }
}

fn parse_presentation_response(
    request: &Request,
    body: &[u8],
) -> Result<PresentationResponseInput, PresentationHttpError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(invalid_response(
            "Presentation responses must use application/x-www-form-urlencoded.",
        ));
    }
    let mut values: BTreeMap<Cow<'_, str>, Cow<'_, str>> = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(body) {
        if !matches!(
            name.as_ref(),
            "response" | "vp_token" | "state" | "error" | "error_description"
        ) {
            continue;
        }
        if values.insert(name, value).is_some() {
            return Err(invalid_response(
                "Presentation response parameters must not repeat.",
            ));
        }
    }
    if let Some(response) = values.remove("response") {
        if !values.is_empty() {
            return Err(invalid_response(
                "direct_post.jwt cannot be mixed with plaintext parameters.",
            ));
        }
        return Ok(PresentationResponseInput::DirectPostJwt(
            response.into_owned(),
        ));
    }
    let vp_token = values
        .remove("vp_token")
        .map(|value| {
            serde_json::from_str(value.as_ref())
                .map_err(|_| invalid_response("vp_token must contain valid JSON."))
        })
        .transpose()?;
    let response = AuthorizationResponse {
        vp_token,
        state: values.remove("state").map(Cow::into_owned),
        error: values.remove("error").map(Cow::into_owned),
        error_description: values.remove("error_description").map(Cow::into_owned),
    };
    Ok(PresentationResponseInput::DirectPost(response))
}

fn invalid_response(description: &'static str) -> PresentationHttpError {
    PresentationHttpError {
        status: 400,
        error: "invalid_request",
        description,
    }
}

pub async fn presentation_result(
    endpoint: &PresentationEndpoint,
    request: &Request,
    transaction_id: Uuid,
) -> Response {
    if !endpoint.management_authorized(request) {
        return management_unauthorized();
    }
    match endpoint.operations.result(transaction_id).await {
        Ok(result) => json_no_store(result),
        Err(error) => presentation_error(error),
    }
}

fn management_unauthorized() -> Response {
    crate::http::json(
        http::Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Bearer")
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::REFERRER_POLICY, "no-referrer"),
        serde_json::json!({
            "error": "invalid_token",
            "error_description": "Verifier management authentication is required."
        }),
    )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn json_no_store(value: impl Serialize) -> Response {
    crate::http::json(
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header(header::CACHE_CONTROL, "no-store"),
        value,
    )
}

fn json_no_store_no_referrer(value: impl Serialize) -> Response {
    crate::http::json(
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::REFERRER_POLICY, "no-referrer"),
        value,
    )
}

fn presentation_error(error: PresentationHttpError) -> Response {
    let status =
        http::StatusCode::from_u16(error.status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    crate::http::json(
        http::Response::builder()
            .status(status)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::REFERRER_POLICY, "no-referrer"),
        serde_json::json!({
            "error": error.error,
            "error_description": error.description,
        }),
    )
}
