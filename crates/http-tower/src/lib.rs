//! One-call mounting for hosts using Tower services and standard HTTP bodies.
//!
//! [`mount`] wraps the complete existing host service. It selects NazoAuth's
//! prepared namespace before host routing, preserving the original request URI
//! and the existing service's routes, middleware and fallback. The optional
//! `axum` feature supplies `axum::mount` and reads Axum's trusted connection
//! extension when no [`nazoauth::integration::ConnectionFacts`] were supplied.

#![forbid(unsafe_code)]

use std::{
    error::Error,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::future::{BoxFuture, Either};
use http::{Request, Response};
use http_body::Body;
use nazoauth::{NazoAuth, integration::BodyMode};
use tower_service::Service;

#[cfg(feature = "axum")]
pub mod axum;
mod transport;

/// An existing host service with a prepared NazoAuth namespace.
#[derive(Clone)]
pub struct Mounted<S> {
    existing: S,
    application: Arc<NazoAuth>,
    existing_root_paths: Arc<[String]>,
}

/// Mount every configured endpoint, including discovery outside the prefix.
///
/// Declare the existing host's literal path namespaces in `occupied_paths` so
/// conflicts fail before serving traffic. At `/`, these namespaces retain their
/// existing handlers and fallback; NazoAuth owns the remaining non-UI surface.
/// At a non-root prefix, all unowned paths reach the existing service unchanged.
///
/// The host supplies trusted connection facts through request extensions and
/// retains ownership of TLS, listeners, I/O capabilities and background tasks.
/// Complete host routing and middleware before mounting. Middleware that must
/// apply to both services belongs outside the returned service.
pub fn mount<S>(
    existing: S,
    application: Arc<NazoAuth>,
    occupied_paths: &[&str],
) -> anyhow::Result<Mounted<S>> {
    application.mount().check_conflicts(occupied_paths)?;
    let existing_root_paths = if application.mount().path() == "/" {
        occupied_paths
            .iter()
            .map(|path| path.trim_end_matches('/').to_owned())
            .collect()
    } else {
        Arc::from([])
    };
    Ok(Mounted {
        existing,
        application,
        existing_root_paths,
    })
}

impl<S, B, R> Service<Request<B>> for Mounted<S>
where
    S: Service<Request<B>, Response = Response<R>>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
    R: From<Bytes>,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = Either<S::Future, BoxFuture<'static, Result<Self::Response, Self::Error>>>;

    // Both branches share the host's backpressure. Call the same instance whose
    // readiness was checked; cloning it here would lose reserved capacity.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.existing.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let path = request.uri().path();
        let is_existing = self.existing_root_paths.iter().any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
        });
        if is_existing || !self.application.mount().owns_path(path) {
            return Either::Left(self.existing.call(request));
        }
        let route = self.application.route_for_path(path);
        let body_mode = route.map_or(BodyMode::None, |route| route.body(request.method()));
        #[cfg(feature = "axum")]
        let request = {
            let mut request = request;
            if route.is_none_or(nazoauth::integration::Route::needs_connection_facts) {
                axum::connection_facts(&mut request);
            }
            request
        };
        let application = self.application.clone();
        Either::Right(Box::pin(async move {
            Ok(application
                .handle_stream(transport::forward_request(request, body_mode))
                .await
                .map(R::from))
        }))
    }
}
