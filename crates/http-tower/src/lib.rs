//! One-call mounting for hosts using Tower services and standard HTTP bodies.
//!
//! [`mount`] wraps a complete request service. [`mount_make_service`] wraps the
//! host's native connection factory, retaining its startup preparation and
//! projecting trusted connection facts once per connection. Both select the
//! prepared namespace before host routing and preserve the original URI.

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
use nazoauth::{ConnectionFacts, NazoAuth, integration::BodyMode};
use tower_service::Service;

mod make_service;
mod transport;

pub use make_service::{MakeServiceFuture, MountedMakeService, mount_make_service};

/// An existing host service with a prepared NazoAuth namespace.
#[derive(Clone)]
pub struct Mounted<S> {
    existing: S,
    context: Arc<MountContext>,
}

#[derive(Clone)]
struct Registration {
    application: Arc<NazoAuth>,
    existing_root_paths: Arc<[String]>,
}

struct MountContext {
    registration: Registration,
    connection_facts: Option<ConnectionFacts>,
}

impl Registration {
    fn new(application: Arc<NazoAuth>, occupied_paths: &[&str]) -> anyhow::Result<Self> {
        application.mount().check_conflicts(occupied_paths)?;
        let existing_root_paths = if application.mount().path() == "/" {
            occupied_paths
                .iter()
                .map(|path| path.trim_end_matches('/').to_owned())
                .collect()
        } else {
            Arc::from([])
        };
        Ok(Self {
            application,
            existing_root_paths,
        })
    }
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
/// Complete host preparation, routing and middleware before mounting. Middleware
/// that must apply to both services belongs outside the returned service.
pub fn mount<S>(
    existing: S,
    application: Arc<NazoAuth>,
    occupied_paths: &[&str],
) -> anyhow::Result<Mounted<S>> {
    Ok(Mounted {
        existing,
        context: Arc::new(MountContext {
            registration: Registration::new(application, occupied_paths)?,
            connection_facts: None,
        }),
    })
}

impl<S, B, R> Service<Request<B>> for Mounted<S>
where
    S: Service<Request<B>, Response = Response<R>>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
    R: From<Bytes>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Either<S::Future, BoxFuture<'static, Result<Self::Response, Self::Error>>>;

    // Both branches pass the host's readiness gate. For host requests, call the
    // same instance whose readiness was checked, preserving reserved capacity.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.existing.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let registration = &self.context.registration;
        let path = request.uri().path();
        let is_existing = registration.existing_root_paths.iter().any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
        });
        if is_existing || !registration.application.mount().owns_path(path) {
            return Either::Left(self.existing.call(request));
        }
        let route = registration.application.route_for_path(path);
        let body_mode = route.map_or(BodyMode::None, |route| route.body(request.method()));
        if route.is_some_and(nazoauth::integration::Route::needs_connection_facts) {
            connection_facts(&mut request, self.context.connection_facts.as_ref());
        }
        let context = self.context.clone();
        // Keep the larger authentication future off every host request's frame.
        // Retain the mount context without touching the shared application's
        // reference count on the request path.
        Either::Right(Box::pin(async move {
            Ok(context
                .registration
                .application
                .handle_stream(transport::forward_request(request, body_mode))
                .await
                .map(R::from))
        }))
    }
}

fn connection_facts<B>(request: &mut Request<B>, facts: Option<&ConnectionFacts>) {
    if let Some(facts) = facts
        && request.extensions().get::<ConnectionFacts>().is_none()
    {
        request.extensions_mut().insert(facts.clone());
    }
}

#[cfg(test)]
#[path = "../tests/unit/connection_facts.rs"]
mod tests;
