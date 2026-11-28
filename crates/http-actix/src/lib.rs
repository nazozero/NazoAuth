#![forbid(unsafe_code)]
//! Actix registration, connection facts and HTTP value conversion for NazoAuth.
//! All routing, protocol interpretation and endpoint policy belong to the facade.
//! [`mount`] serves one fixed graph; [`DynamicMount`] selects graphs from the
//! shared live directory and also serves the native executable.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use actix_web::{
    Error, HttpRequest, HttpResponse,
    body::MessageBody,
    dev::{Decompress, Payload, ServiceRequest, ServiceResponse},
    error::PayloadError,
    http::header::{CONTENT_ENCODING, ContentEncoding},
    middleware::Next,
    web,
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt as _, TryStreamExt as _};
use nazoauth::{ConnectionFacts, NazoAuth, integration::Route};

mod dynamic;
pub use dynamic::{DynamicMount, DynamicMountService};

/// Register the canonical product surface. Install the already-built tenant as
/// `web::Data<NazoAuth>` in application data, including tenant-selected data.
pub fn configure(config: &mut web::ServiceConfig) {
    config.default_service(web::to(serve));
}

/// Mount a prepared tenant and its standards-derived discovery paths once.
///
/// `reserved_paths` declares the application's occupied paths and scopes. Actix
/// does not expose existing registrations through `ServiceConfig`; the host
/// supplies those namespaces so conflicts fail before route installation.
/// The mounted `/ui` subtree remains available to host-owned UI resources.
/// Fixed mounts do not consult a tenant directory. Use [`DynamicMount`] when
/// tenant selection and graph replacement must follow a live registry.
pub fn mount(
    application: Arc<NazoAuth>,
    reserved_paths: &[&str],
) -> anyhow::Result<impl FnOnce(&mut web::ServiceConfig) + use<>> {
    application.mount().check_conflicts(reserved_paths)?;
    let existing_root_paths: Vec<actix_web::dev::Url> = if application.mount().path() == "/" {
        reserved_paths
            .iter()
            .map(|path| {
                path.trim_end_matches('/')
                    .parse()
                    .map(actix_web::dev::Url::new)
            })
            .collect::<Result<_, _>>()?
    } else {
        Vec::new()
    };
    Ok(move |config: &mut web::ServiceConfig| {
        let application = web::Data::from(application);
        let discovery = application.clone();
        // Resource identifiers may contain escapes or Actix pattern characters.
        // Compare the raw path instead of compiling each identifier as a pattern.
        config.service(
            web::scope("/.well-known")
                .guard(actix_web::guard::fn_guard(move |context| {
                    discovery
                        .mount()
                        .discovery_paths()
                        .any(|path| path == context.head().uri.path())
                }))
                .app_data(application.clone())
                .configure(configure),
        );
        let scope = if application.mount().path() == "/" {
            ""
        } else {
            application.mount().path()
        };
        let mounted = application.clone();
        config.service(
            web::scope(scope)
                .guard(actix_web::guard::fn_guard(move |context| {
                    let path = context.head().uri.path();
                    if !mounted.mount().owns_path(path) {
                        return false;
                    }
                    // Host routing decodes ordinary escapes before matching.
                    // Keep the authentication prefix raw, but preserve host/UI
                    // aliases using Actix's own path representation.
                    let decoded = path
                        .contains('%')
                        .then(|| actix_web::dev::Url::new(context.head().uri.clone()));
                    let host_path = decoded.as_ref().map_or(path, actix_web::dev::Url::path);
                    decoded
                        .as_ref()
                        .is_none_or(|url| mounted.mount().owns_path(url.path()))
                        && !existing_root_paths.iter().any(|prefix| {
                            host_path
                                .strip_prefix(prefix.path())
                                .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
                        })
                }))
                .app_data(application)
                .configure(configure),
        );
    })
}

/// Forward transport facts without assembling services or buffering the payload.
pub async fn serve(
    application: web::Data<NazoAuth>,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    // Actix's wire parser rejects missing/duplicate Host fields, but leaves
    // their URI-host grammar to the service. Keep this check outside the shared
    // handler: dynamic selection has already admitted the same header.
    let invalid = if request.version() >= actix_web::http::Version::HTTP_2 {
        dynamic::request_authority(&request).is_err()
    } else {
        request
            .headers()
            .get(actix_web::http::header::HOST)
            .is_some_and(|host| {
                !host
                    .to_str()
                    .is_ok_and(nazoauth::integration::valid_host_header)
            })
    };
    if invalid {
        return rejection(http::StatusCode::BAD_REQUEST, request.uri().path());
    }
    serve_request(&application, &request, payload.into_inner()).await
}

fn rejection(status: http::StatusCode, path: &str) -> HttpResponse {
    let mut response = http::Response::new(Bytes::new());
    *response.status_mut() = status;
    for (name, value) in nazoauth::integration::security_headers(path) {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    forward_response(response)
}

async fn serve_request(
    application: &NazoAuth,
    request: &HttpRequest,
    payload: Payload,
) -> HttpResponse {
    let route = application.route_for_path(request.uri().path());
    let forwarded = forward_request_for_route(request, (), route);
    let body_mode = route
        .map(|route| route.body(forwarded.method()))
        .unwrap_or(nazoauth::integration::BodyMode::None);
    let body = forward_payload(request, payload, body_mode);
    forward_response(application.handle_stream(forwarded.map(|()| body)).await)
}

fn forward_payload(
    request: &HttpRequest,
    payload: Payload,
    body_mode: nazoauth::integration::BodyMode,
) -> impl Stream<Item = Result<Bytes, io::Error>> {
    let encoding = if body_mode.decode_content() {
        request
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or(ContentEncoding::Identity)
    } else {
        ContentEncoding::Identity
    };
    if encoding == ContentEncoding::Identity {
        ForwardPayload::Plain(payload)
    } else {
        // Admission can reject without reading the payload. Keep decoder state
        // and buffers unallocated until the endpoint actually consumes it.
        ForwardPayload::Encoded {
            payload,
            encoding,
            limit: body_mode.limit().expect("decoded bodies have a limit"),
        }
    }
    .map_err(payload_error)
}

// Reuse the unread payload's storage for the decoder instead of retaining both
// states in every handler future.
enum ForwardPayload {
    Plain(Payload),
    Encoded {
        payload: Payload,
        encoding: ContentEncoding,
        limit: usize,
    },
    Decoding(Decompress<Payload>),
}

impl Stream for ForwardPayload {
    type Item = Result<Bytes, PayloadError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let state = self.get_mut();
        loop {
            match state {
                Self::Plain(payload) => return payload.poll_next_unpin(context),
                Self::Encoded {
                    payload,
                    encoding,
                    limit,
                } => {
                    *state =
                        Self::Decoding(Decompress::new(payload.take(), *encoding).limit(*limit));
                }
                Self::Decoding(payload) => return payload.poll_next_unpin(context),
            }
        }
    }
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
    let mut response = next.call(request).await?;
    let request = response.request();
    let path = request
        .app_data::<web::Data<NazoAuth>>()
        .and_then(|application| application.route_for_path(request.uri().path()))
        .map_or(request.path(), |route| route.path);
    let defaults = nazoauth::integration::security_headers(path);
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
