#![forbid(unsafe_code)]
//! Actix registration, connection facts and HTTP value conversion for NazoAuth.
//! All routing, protocol interpretation and endpoint policy belong to the facade.

use std::io;

use actix_web::{
    Error, HttpRequest, HttpResponse,
    body::MessageBody,
    dev::{Decompress, ServiceRequest, ServiceResponse},
    error::PayloadError,
    middleware::Next,
    web,
};
use bytes::Bytes;
use futures_util::{TryStreamExt as _, future::Either};
use nazoauth::{ConnectionFacts, NazoAuth, integration::Route};

/// Register the canonical product surface. Install the already-built tenant as
/// `web::Data<NazoAuth>` in application data, including tenant-selected data.
pub fn configure(config: &mut web::ServiceConfig) {
    config.default_service(web::to(serve));
}

/// Forward transport facts without assembling services or buffering the payload.
pub async fn serve(
    application: web::Data<NazoAuth>,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let route = nazoauth::integration::route_for_path(request.uri().path());
    let forwarded = forward_request_for_route(&request, (), route);
    let body_mode = route
        .map(|route| route.body(forwarded.method()))
        .unwrap_or(nazoauth::integration::BodyMode::None);
    let body = forward_payload(&request, payload.into_inner(), body_mode);
    forward_response(application.handle_stream(forwarded.map(|()| body)).await)
}

fn forward_payload(
    request: &HttpRequest,
    payload: actix_web::dev::Payload,
    body_mode: nazoauth::integration::BodyMode,
) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> {
    if body_mode.decode_content() {
        Either::Left(
            Decompress::from_headers(payload, request.headers())
                .limit(body_mode.limit().expect("decoded bodies have a limit")),
        )
    } else {
        Either::Right(payload)
    }
    .map_err(payload_error)
}

fn payload_error(error: PayloadError) -> io::Error {
    if matches!(error, PayloadError::Overflow) {
        io::Error::new(io::ErrorKind::FileTooLarge, error)
    } else {
        io::Error::other(error)
    }
}

fn request_header(value: &actix_web::http::header::HeaderValue) -> http::HeaderValue {
    let mut converted =
        http::HeaderValue::from_bytes(value.as_bytes()).expect("validated Actix header value");
    converted.set_sensitive(value.is_sensitive());
    converted
}

fn response_header(value: &http::HeaderValue) -> actix_web::http::header::HeaderValue {
    let mut converted = actix_web::http::header::HeaderValue::from_bytes(value.as_bytes())
        .expect("validated HTTP header value");
    converted.set_sensitive(value.is_sensitive());
    converted
}

/// Convert HTTP 0.2 metadata once; the supplied body keeps its original storage.
/// Raw targets and header bytes are preserved without protocol interpretation.
pub fn forward_request<B>(request: &HttpRequest, body: B) -> http::Request<B> {
    forward_request_for_route(request, body, None)
}

fn forward_request_for_route<B>(
    request: &HttpRequest,
    body: B,
    route: Option<&Route>,
) -> http::Request<B> {
    use actix_web::http::Version;
    let mut forwarded = http::Request::new(body);
    *forwarded.method_mut() = http::Method::from_bytes(request.method().as_str().as_bytes())
        .expect("validated Actix method");
    *forwarded.uri_mut() = request
        .uri()
        .to_string()
        .parse()
        .expect("validated Actix URI");
    *forwarded.version_mut() = match request.version() {
        Version::HTTP_09 => http::Version::HTTP_09,
        Version::HTTP_10 => http::Version::HTTP_10,
        Version::HTTP_11 => http::Version::HTTP_11,
        Version::HTTP_2 => http::Version::HTTP_2,
        Version::HTTP_3 => http::Version::HTTP_3,
        _ => unreachable!("http 0.2 exposes only these HTTP versions"),
    };
    if let Some(names) = route.and_then(Route::request_headers) {
        for name in names {
            for value in request.headers().get_all(name.as_str()) {
                forwarded
                    .headers_mut()
                    .append(name.clone(), request_header(value));
            }
        }
    } else {
        forwarded
            .headers_mut()
            .reserve(request.headers().len_keys());
        for (name, value) in request.headers() {
            forwarded.headers_mut().append(
                http::HeaderName::from_bytes(name.as_str().as_bytes())
                    .expect("validated Actix header name"),
                request_header(value),
            );
        }
    }
    if route.is_none_or(Route::needs_connection_facts) {
        let mut facts = request
            .conn_data::<ConnectionFacts>()
            .cloned()
            .unwrap_or_default();
        facts.peer_addr = request.peer_addr();
        forwarded.extensions_mut().insert(facts);
    }
    forwarded
}

/// Convert response metadata once and move the existing body bytes into Actix.
pub fn forward_response(response: http::Response<Bytes>) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let mut forwarded = HttpResponse::new(
        actix_web::http::StatusCode::from_u16(parts.status.as_u16())
            .expect("validated HTTP status"),
    );
    let mut name = None;
    for (next_name, value) in parts.headers {
        if let Some(next_name) = next_name {
            name = Some(
                actix_web::http::header::HeaderName::from_bytes(next_name.as_str().as_bytes())
                    .expect("validated HTTP header name"),
            );
        }
        forwarded.headers_mut().append(
            name.as_ref()
                .expect("header iterator starts with a name")
                .clone(),
            response_header(&value),
        );
    }
    forwarded.set_body(body).map_into_boxed_body()
}

/// Apply the same neutral security policy to host-owned responses and rejections.
pub async fn security_headers<B: MessageBody>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    let defaults = nazoauth::integration::security_headers(request.path());
    let mut response = next.call(request).await?;
    for (name, value) in defaults {
        if !response.headers().contains_key(name.as_str()) {
            response.headers_mut().insert(
                actix_web::http::header::HeaderName::from_bytes(name.as_str().as_bytes())
                    .expect("validated security header name"),
                response_header(value),
            );
        }
    }
    Ok(response)
}

#[cfg(test)]
#[path = "../tests/unit/transport.rs"]
mod tests;
