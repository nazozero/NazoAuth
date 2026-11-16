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
    // Keep manifest order while excluding unrelated path groups from each scan.
    let mut groups: Vec<(&'static str, Vec<&'static Route>)> = Vec::new();
    for route in nazoauth::integration::routes() {
        let end = route.path[1..]
            .find('/')
            .map_or(route.path.len(), |index| index + 1);
        let prefix = &route.path[..end];
        if let Some((_, routes)) = groups.iter_mut().find(|(key, _)| *key == prefix) {
            routes.push(route);
        } else {
            groups.push((prefix, vec![route]));
        }
    }
    for (prefix, routes) in groups {
        if routes.len() == 1 {
            let route = routes[0];
            config.service(
                web::resource(actix_path(route.path).as_ref())
                    .app_data(route)
                    .to(serve),
            );
        } else {
            let mut scope = web::scope(prefix).default_service(web::to(serve));
            for route in routes {
                scope = scope.service(
                    web::resource(actix_path(&route.path[prefix.len()..]).as_ref())
                        .app_data(route)
                        .to(serve),
                );
            }
            config.service(scope);
        }
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
    let route = request.app_data::<&'static Route>();
    let body_mode = route
        .map(|route| route.body(request.method()))
        .unwrap_or(nazoauth::integration::BodyMode::None);
    let needs_connection_facts = route.is_none_or(|route| route.needs_connection_facts());
    let body = forward_payload(&request, payload.into_inner(), body_mode);
    forward_response(
        application
            .handle_stream(forward_request_with_connection_facts(
                &request,
                body,
                needs_connection_facts,
            ))
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

/// Share standard HTTP metadata and body storage. Trust decisions stay in the
/// facade.
pub fn forward_request<B>(request: &HttpRequest, body: B) -> http::Request<B> {
    forward_request_with_connection_facts(request, body, true)
}

fn forward_request_with_connection_facts<B>(
    request: &HttpRequest,
    body: B,
    needs_connection_facts: bool,
) -> http::Request<B> {
    let mut forwarded = http::Request::new(body);
    *forwarded.method_mut() = request.method().clone();
    *forwarded.uri_mut() = request.uri().clone();
    *forwarded.version_mut() = request.version();
    forwarded
        .headers_mut()
        .reserve(request.headers().len_keys());
    for (name, value) in request.headers() {
        forwarded.headers_mut().append(name.clone(), value.clone());
    }
    if needs_connection_facts {
        let mut facts = request
            .conn_data::<ConnectionFacts>()
            .cloned()
            .unwrap_or_default();
        facts.peer_addr = request.peer_addr();
        forwarded.extensions_mut().insert(facts);
    }
    forwarded
}

/// Move response body storage into Actix while preserving every repeated header.
pub fn forward_response(response: http::Response<Bytes>) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let mut forwarded = HttpResponse::new(parts.status);
    let mut name = None;
    for (next_name, value) in parts.headers {
        if let Some(next_name) = next_name {
            name = Some(next_name);
        }
        forwarded.headers_mut().append(
            name.as_ref()
                .expect("header iterator starts with a name")
                .clone(),
            value,
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
        if !response.headers().contains_key(name) {
            response.headers_mut().insert(name.clone(), value.clone());
        }
    }
    Ok(response)
}

#[cfg(test)]
#[path = "../tests/unit/transport.rs"]
mod tests;
