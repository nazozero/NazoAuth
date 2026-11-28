//! Live tenant selection over the same standard HTTP transport contract.

use std::{
    error::Error,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures_util::future::{BoxFuture, Either};
use http::{Request, Response, StatusCode};
use http_body::Body;
use nazoauth::{
    ConnectionFacts,
    integration::{BodyMode, request_authority},
    runtime::TenantRuntimeRegistry,
};
use pin_project_lite::pin_project;
use tower_service::Service;

#[derive(Clone)]
struct Registration {
    registry: TenantRuntimeRegistry,
    occupied_paths: Arc<[String]>,
}

impl Registration {
    fn new(registry: TenantRuntimeRegistry, occupied_paths: &[&str]) -> anyhow::Result<Self> {
        registry.require_mount_paths(occupied_paths)?;
        Ok(Self {
            registry,
            occupied_paths: occupied_paths
                .iter()
                .map(|path| path.trim_end_matches('/').to_owned())
                .collect(),
        })
    }
}

struct MountContext {
    registration: Registration,
    connection_facts: Option<ConnectionFacts>,
}

/// A host service mounted against an atomically replaceable tenant directory.
#[derive(Clone)]
pub struct DynamicMounted<S> {
    existing: S,
    context: Arc<MountContext>,
}

/// Mount a live directory. Reserved host namespaces bypass tenant selection;
/// other requests select by actual authority and authenticated TLS server name.
/// Unowned paths of a known tenant continue to the host with its `Arc<NazoAuth>`
/// in request extensions, retaining the selected generation for UI and other
/// host handlers. Invalid HTTP/1 Host fields return 400; unknown tenants fail
/// closed. Future snapshots honor the same reservations.
pub fn mount_dynamic<S>(
    existing: S,
    registry: TenantRuntimeRegistry,
    occupied_paths: &[&str],
) -> anyhow::Result<DynamicMounted<S>> {
    Ok(DynamicMounted {
        existing,
        context: Arc::new(MountContext {
            registration: Registration::new(registry, occupied_paths)?,
            connection_facts: None,
        }),
    })
}

impl<S, B, R> Service<Request<B>> for DynamicMounted<S>
where
    S: Service<Request<B>, Response = Response<R>>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
    R: From<Bytes>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Either<S::Future, BoxFuture<'static, Result<Self::Response, Self::Error>>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.existing.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let registration = &self.context.registration;
        let path = request.uri().path();
        if registration.occupied_paths.iter().any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
        }) {
            return Either::Left(self.existing.call(request));
        }
        let server_name = request
            .extensions()
            .get::<ConnectionFacts>()
            .or(self.context.connection_facts.as_ref())
            .and_then(|facts| facts.server_name.as_deref());
        let selected = super::transport::validate_host(&request)
            .and_then(|()| {
                request_authority(&request).ok_or(if request.version() >= http::Version::HTTP_2 {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::NOT_FOUND
                })
            })
            .and_then(|authority| registration.registry.resolve(authority, server_name));
        let runtime = match selected {
            Ok(runtime) => runtime,
            Err(status) => {
                let response = super::transport::rejection(status, path);
                return Either::Right(Box::pin(async move { Ok(response.map(R::from)) }));
            }
        };
        if !runtime.application().mount().owns_path(path) {
            request
                .extensions_mut()
                .insert(runtime.application().clone());
            return Either::Left(self.existing.call(request));
        }
        let route = runtime.application().route_for_path(path);
        let body_mode = route.map_or(BodyMode::None, |route| route.body(request.method()));
        if route.is_some_and(nazoauth::integration::Route::needs_connection_facts) {
            super::connection_facts(&mut request, self.context.connection_facts.as_ref());
        }
        // Retaining the selected generation keeps this request coherent across a
        // directory swap without touching the application's own Arc counter.
        Either::Right(Box::pin(async move {
            Ok(runtime
                .application()
                .handle_stream(super::transport::forward_request(request, body_mode))
                .await
                .map(R::from))
        }))
    }
}

/// A host connection factory whose services select the current tenant directory.
#[derive(Clone)]
pub struct DynamicMountedMakeService<M, F> {
    existing: M,
    registration: Registration,
    connection_facts: F,
}

/// Mount a live directory around a connection factory. Trusted per-request
/// connection facts retain precedence over the once-per-connection projection.
pub fn mount_make_service_dynamic<M, F>(
    existing: M,
    registry: TenantRuntimeRegistry,
    occupied_paths: &[&str],
    connection_facts: F,
) -> anyhow::Result<DynamicMountedMakeService<M, F>> {
    Ok(DynamicMountedMakeService {
        existing,
        registration: Registration::new(registry, occupied_paths)?,
        connection_facts,
    })
}

impl<M, F, T> Service<T> for DynamicMountedMakeService<M, F>
where
    M: Service<T>,
    F: FnMut(&T) -> ConnectionFacts,
{
    type Response = DynamicMounted<M::Response>;
    type Error = M::Error;
    type Future = DynamicMakeServiceFuture<M::Future>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.existing.poll_ready(context)
    }

    fn call(&mut self, target: T) -> Self::Future {
        let connection_facts = (self.connection_facts)(&target);
        DynamicMakeServiceFuture {
            future: self.existing.call(target),
            context: Some(MountContext {
                registration: self.registration.clone(),
                connection_facts: Some(connection_facts),
            }),
        }
    }
}

pin_project! {
    /// The original host connection future followed by dynamic mounting.
    pub struct DynamicMakeServiceFuture<F> {
        #[pin]
        future: F,
        context: Option<MountContext>,
    }
}

impl<F, S, E> Future for DynamicMakeServiceFuture<F>
where
    F: Future<Output = Result<S, E>>,
{
    type Output = Result<DynamicMounted<S>, E>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let existing = ready!(this.future.poll(context))?;
        let context = this
            .context
            .take()
            .expect("make-service future polled after completion");
        Poll::Ready(Ok(DynamicMounted {
            existing,
            context: Arc::new(context),
        }))
    }
}

#[cfg(test)]
#[path = "../tests/unit/dynamic.rs"]
mod tests;
