#![forbid(unsafe_code)]
//! Actix registration, connection facts and HTTP value conversion for NazoAuth.
//! All routing, protocol interpretation and endpoint policy belong to the facade.

use std::{borrow::Cow, io};

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
    for route in nazoauth::integration::routes() {
        config.service(
            web::resource(actix_path(route.path).as_ref())
                .app_data(route)
                .to(serve),
        );
    }
    config.default_service(web::to(serve));
}

fn actix_path(path: &'static str) -> Cow<'static, str> {
    let Some(start) = path.find("{*") else {
        return Cow::Borrowed(path);
    };
    let end = path[start..]
        .find('}')
        .expect("canonical catch-all has a closing brace")
        + start;
    Cow::Owned(format!(
        "{}{{{}:.*}}{}",
        &path[..start],
        &path[start + 2..end],
        &path[end + 1..]
    ))
}

/// Forward one framework request without assembling services or buffering its
/// payload. Decoding consumes the canonical route's transport metadata.
pub async fn serve(
    application: web::Data<NazoAuth>,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let request_head = forward_request(&request, ());
    let body_mode = request
        .app_data::<&'static Route>()
        .map(|route| route.body(request_head.method()))
        .unwrap_or(nazoauth::integration::BodyMode::None);
    let body = forward_payload(&request, payload.into_inner(), body_mode);
    // Move the standard head and the original Bytes stream into the facade.
    let (parts, ()) = request_head.into_parts();
    forward_response(
        application
            .handle_stream(http::Request::from_parts(parts, body))
            .await,
    )
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

/// Translate HTTP metadata, sharing header-value and body storage across the
/// framework's HTTP version boundary. Trust decisions stay in the facade.
pub fn forward_request<B>(request: &HttpRequest, body: B) -> http::Request<B> {
    let mut forwarded = http::Request::new(body);
    *forwarded.method_mut() = http::Method::from_bytes(request.method().as_str().as_bytes())
        .expect("valid framework method");
    *forwarded.uri_mut() = request
        .uri()
        .to_string()
        .try_into()
        .expect("valid framework URI");
    *forwarded.version_mut() = match request.version() {
        actix_web::http::Version::HTTP_09 => http::Version::HTTP_09,
        actix_web::http::Version::HTTP_10 => http::Version::HTTP_10,
        actix_web::http::Version::HTTP_11 => http::Version::HTTP_11,
        actix_web::http::Version::HTTP_2 => http::Version::HTTP_2,
        actix_web::http::Version::HTTP_3 => http::Version::HTTP_3,
        _ => unreachable!("unsupported framework HTTP version"),
    };
    for (name, value) in request.headers() {
        let mut converted = http::HeaderValue::from_maybe_shared(Bytes::from_owner(value.clone()))
            .expect("valid framework header value");
        converted.set_sensitive(value.is_sensitive());
        forwarded.headers_mut().append(
            http::HeaderName::from_bytes(name.as_str().as_bytes())
                .expect("valid framework header name"),
            converted,
        );
    }
    let mut facts = request
        .conn_data::<ConnectionFacts>()
        .cloned()
        .unwrap_or_default();
    facts.peer_addr = request.peer_addr();
    forwarded.extensions_mut().insert(facts);
    forwarded
}

/// Move response body storage into Actix while preserving every repeated header.
pub fn forward_response(response: http::Response<Bytes>) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let mut builder = HttpResponse::build(
        actix_web::http::StatusCode::from_u16(parts.status.as_u16()).expect("valid HTTP status"),
    );
    for (name, value) in &parts.headers {
        builder.append_header((actix_header_name(name), actix_header_value(value)));
    }
    builder.body(body)
}

fn actix_header_name(name: &http::HeaderName) -> actix_web::http::header::HeaderName {
    actix_web::http::header::HeaderName::from_bytes(name.as_str().as_bytes())
        .expect("valid HTTP header name")
}

fn actix_header_value(value: &http::HeaderValue) -> actix_web::http::header::HeaderValue {
    let mut converted =
        actix_web::http::header::HeaderValue::from_maybe_shared(Bytes::from_owner(value.clone()))
            .expect("valid HTTP header value");
    converted.set_sensitive(value.is_sensitive());
    converted
}

/// Apply the same neutral security policy to host-owned responses and rejections.
pub async fn security_headers<B: MessageBody>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    let defaults = nazoauth::integration::security_headers(request.path());
    let mut response = next.call(request).await?;
    for (name, value) in defaults {
        let name = actix_header_name(name);
        if !response.headers().contains_key(&name) {
            response
                .headers_mut()
                .insert(name, actix_header_value(value));
        }
    }
    Ok(response)
}

#[cfg(test)]
#[path = "../tests/unit/transport.rs"]
mod tests;
