//! Deserialization at the HTTP boundary. Framework adapters pass unparsed bytes.
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use http::{StatusCode, header};
use std::error::Error;

use crate::integration::{BodyMode, Endpoint, RouteMethod};
use serde::de::DeserializeOwned;

use super::{Request, Response, finish};

pub fn text_error(status: StatusCode, message: impl Into<bytes::Bytes>) -> Response {
    finish(
        http::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8"),
        message,
    )
}

pub fn parse_json<T: DeserializeOwned>(request: &Request) -> Result<T, Response> {
    parse_json_limit(request, 2 * 1024 * 1024)
}

pub fn parse_json_limit<T: DeserializeOwned>(
    request: &Request,
    limit: usize,
) -> Result<T, Response> {
    validate_json_head(request, limit)?;
    if request.body().len() > limit {
        return Err(text_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("JSON payload has exceeded limit ({limit} bytes)"),
        ));
    }
    serde_json::from_slice(request.body()).map_err(|error| {
        text_error(
            StatusCode::BAD_REQUEST,
            format!("Json deserialize error: {error}"),
        )
    })
}

pub fn validate_json_head(request: &Request, limit: usize) -> Result<(), Response> {
    let media = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<mime::Mime>().ok());
    if !media.is_some_and(|v| v.subtype() == mime::JSON || v.suffix() == Some(mime::JSON)) {
        return Err(text_error(StatusCode::BAD_REQUEST, "Content type error"));
    }
    if let Some(length) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        && length > limit
    {
        return Err(text_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("JSON payload ({length} bytes) is larger than allowed (limit: {limit} bytes)"),
        ));
    }
    Ok(())
}

pub fn parse_form<T: DeserializeOwned>(request: &Request) -> Result<T, Response> {
    let encoding = validate_form_head(request)?;
    const LIMIT: usize = 32 * 1024;
    if request.body().len() > LIMIT {
        return Err(text_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("URL encoded payload is larger than allowed (limit: {LIMIT} bytes)"),
        ));
    }
    let parsed = if encoding == encoding_rs::UTF_8 {
        serde_urlencoded::from_bytes(request.body())
    } else {
        let decoded = encoding
            .decode_without_bom_handling_and_without_replacement(request.body())
            .ok_or_else(|| text_error(StatusCode::BAD_REQUEST, "Encoding error"))?;
        serde_urlencoded::from_str(&decoded)
    };
    parsed.map_err(|error| text_error(StatusCode::BAD_REQUEST, format!("Parse error: {error}")))
}

fn validate_form_head(request: &Request) -> Result<&'static encoding_rs::Encoding, Response> {
    let media = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<mime::Mime>().ok());
    let Some(media) = media.filter(|v| {
        v.essence_str()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) else {
        return Err(text_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content type error",
        ));
    };
    let encoding = match media.get_param(mime::CHARSET) {
        None => encoding_rs::UTF_8,
        Some(charset) => encoding_rs::Encoding::for_label(charset.as_str().as_bytes())
            .ok_or_else(|| text_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content type error"))?,
    };
    const LIMIT: usize = 32 * 1024;
    if let Some(length) = request.headers().get(header::CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or_else(|| text_error(StatusCode::LENGTH_REQUIRED, "Payload size is now known"))?;
        if length > LIMIT {
            return Err(text_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "URL-encoded payload is larger ({length} bytes) than allowed (limit: {LIMIT} bytes)"
                ),
            ));
        }
    }
    Ok(encoding)
}

pub fn parse_query<T: DeserializeOwned>(request: &Request) -> Result<T, Response> {
    serde_urlencoded::from_str(request.uri().query().unwrap_or("")).map_err(|error| {
        text_error(
            StatusCode::BAD_REQUEST,
            format!("Query deserialize error: {error}"),
        )
    })
}

pub fn parse_path<T: std::str::FromStr>(value: &str) -> Result<T, Response> {
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| super::empty_response(StatusCode::NOT_FOUND))?
        .parse()
        .map_err(|_| super::empty_response(StatusCode::NOT_FOUND))
}

/// Validate extractor headers before polling the transport. The optional wallet
/// nonce form ignores extraction failure, exactly as its optional input requires.
pub fn validate_route_body_head(request: &Request, method: &RouteMethod) -> Result<bool, Response> {
    match method.body {
        BodyMode::None => Ok(false),
        BodyMode::Json { limit } => validate_json_head(request, limit)
            .map(|()| true)
            .map_err(|response| json_extraction_error(method.endpoint, response)),
        BodyMode::Form => match validate_form_head(request) {
            Ok(_) => Ok(true),
            Err(_) if method.endpoint == Endpoint::PresentationRequest => Ok(false),
            Err(response) => Err(response),
        },
        BodyMode::Bytes => {
            if let Some(length) = request.headers().get(header::CONTENT_LENGTH) {
                let length = length
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or_else(|| {
                        text_error(StatusCode::BAD_REQUEST, "Payload length is unknown")
                    })?;
                if length > 256 * 1024 {
                    return Err(body_overflow_response(method));
                }
            }
            Ok(true)
        }
        // These handlers validate their own headers after admission and before
        // awaiting the collector. Multipart remains incremental in its handler.
        BodyMode::Raw { .. } | BodyMode::Multipart => Ok(true),
    }
}

/// Keep a single chunk in its original allocation. Allocate a contiguous buffer
/// only when a second nonempty chunk makes aggregation necessary.
pub async fn collect_route_body<S, E>(method: &RouteMethod, stream: S) -> Result<Bytes, Response>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: Error + Send + Sync + 'static,
{
    if method.body == BodyMode::None {
        return Ok(Bytes::new());
    }
    let limit = method
        .body
        .limit()
        .expect("multipart is consumed incrementally");
    futures_util::pin_mut!(stream);
    let mut first = Bytes::new();
    let mut collected: Option<BytesMut> = None;
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) if method.endpoint == Endpoint::PresentationRequest => return Ok(Bytes::new()),
            Err(error) => {
                let oversized = (&error as &(dyn Error + 'static))
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::FileTooLarge);
                return Err(if oversized {
                    body_overflow_response(method)
                } else {
                    body_read_error(method, &error)
                });
            }
        };
        let length = collected.as_ref().map_or(first.len(), BytesMut::len);
        if chunk.len() > limit - length {
            return if method.endpoint == Endpoint::PresentationRequest {
                Ok(Bytes::new())
            } else {
                Err(body_overflow_response(method))
            };
        }
        if chunk.is_empty() {
            continue;
        }
        if let Some(collected) = collected.as_mut() {
            collected.extend_from_slice(&chunk);
        } else if first.is_empty() {
            first = chunk;
        } else {
            let mut buffer = match std::mem::take(&mut first).try_into_mut() {
                Ok(buffer) => buffer,
                Err(first) => {
                    let mut buffer = BytesMut::with_capacity(first.len() + chunk.len());
                    buffer.extend_from_slice(&first);
                    buffer
                }
            };
            buffer.extend_from_slice(&chunk);
            collected = Some(buffer);
        }
    }
    Ok(collected.map_or(first, BytesMut::freeze))
}

fn json_extraction_error(endpoint: Endpoint, ordinary: Response) -> Response {
    match endpoint {
        Endpoint::MfaVerify
        | Endpoint::MfaTotpConfirm
        | Endpoint::MfaStepUp
        | Endpoint::MfaBackupCodesRegenerate
        | Endpoint::MfaDisable => super::extract::invalid_mfa_json_response(),
        Endpoint::PasskeyLoginBegin
        | Endpoint::PasskeyLoginFinish
        | Endpoint::PasskeyRegistrationBegin
        | Endpoint::PasskeyRegistrationFinish => super::passkey::invalid_passkey_json_response(),
        _ => ordinary,
    }
}

fn body_overflow_response(method: &RouteMethod) -> Response {
    match method.body {
        BodyMode::Json { limit } => json_extraction_error(
            method.endpoint,
            text_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("JSON payload has exceeded limit ({limit} bytes)"),
            ),
        ),
        BodyMode::Form => text_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "URL encoded payload is larger than allowed (limit: 32768 bytes)",
        ),
        BodyMode::Raw { .. } if method.endpoint == Endpoint::BackchannelAuthentication => {
            super::oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "CIBA body is too large.",
            )
        }
        BodyMode::Raw { .. } => super::oauth_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "logout request body is too large.",
        ),
        _ => text_error(StatusCode::PAYLOAD_TOO_LARGE, "Payload reached size limit"),
    }
}

fn body_read_error(method: &RouteMethod, error: &dyn Error) -> Response {
    match method.body {
        BodyMode::Json { .. } => json_extraction_error(
            method.endpoint,
            text_error(
                StatusCode::BAD_REQUEST,
                format!("Error that occur during reading payload: {error}"),
            ),
        ),
        BodyMode::Form => text_error(
            StatusCode::BAD_REQUEST,
            format!("Error that occur during reading payload: {error}"),
        ),
        BodyMode::Raw { .. } if method.endpoint == Endpoint::BackchannelAuthentication => {
            super::oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA body is invalid.",
            )
        }
        BodyMode::Raw { .. } => super::oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout request body is invalid.",
        ),
        _ => text_error(StatusCode::BAD_REQUEST, error.to_string()),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/http/request.rs"]
mod tests;
