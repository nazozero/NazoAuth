use super::super::tenant_runtime::{ProcessRuntime, TenantHostIndex, TenantRuntimeRegistry};
use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{Extensions, ServiceRequest, ServiceResponse};
use actix_web::error::ErrorRequestTimeout;
use actix_web::http::StatusCode;
use actix_web::middleware::{Next, from_fn};
use actix_web::{App, Error, HttpServer, web};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::Instrument;

/// Bounds the complete request future, including typed extractors and handlers
/// that drain `web::Payload` themselves. Actix's client request timeout only
/// covers request-head parsing, so this application-level guard is required to
/// close a connection whose body trickles after the head has been accepted.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Keep the head timeout explicit even though Actix has a default. This
/// protects the boundary if the framework default changes during an upgrade.
const HTTP_CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// `max_connections` is per worker in Actix. Four thousand is below the
/// framework default (25,000) while retaining headroom for normal API use.
const HTTP_MAX_CONNECTIONS_PER_WORKER: usize = 4_096;

#[derive(Default)]
struct WorkerTenantDataCache {
    index: Option<Arc<TenantHostIndex>>,
    by_host: HashMap<String, (Rc<Extensions>, nazo_identity::TenantId)>,
}

impl WorkerTenantDataCache {
    fn resolve(
        &mut self,
        index: Arc<TenantHostIndex>,
        host: &str,
    ) -> Option<(Rc<Extensions>, nazo_identity::TenantId)> {
        let changed = match &self.index {
            Some(current) => !Arc::ptr_eq(current, &index),
            None => true,
        };
        if changed {
            self.index = Some(Arc::clone(&index));
            self.by_host.clear();
        }

        if let Some(data) = self.by_host.get(host) {
            return Some(data.clone());
        }
        let assembly = index.by_host.get(host)?.assembly();
        let data = (
            assembly.app_data_container(),
            assembly.startup.settings.tenant.context.tenant_id,
        );
        self.by_host.insert(host.to_owned(), data.clone());
        Some(data)
    }
}

fn direct_tls_host_matches(server_name: Option<&str>, host: &str) -> bool {
    server_name.is_none_or(|server_name| server_name == host)
}

fn tenant_rejection(request: ServiceRequest, status: StatusCode) -> ServiceResponse {
    let mut response = http::Response::new(bytes::Bytes::new());
    *response.status_mut() =
        http::StatusCode::from_u16(status.as_u16()).expect("validated Actix status");
    for (name, value) in nazoauth::integration::security_headers(request.path()) {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    request.into_response(nazo_http_actix::forward_response(response))
}

async fn bind_tenant_app_data<B>(
    registry: TenantRuntimeRegistry,
    cache: Rc<RefCell<WorkerTenantDataCache>>,
    mut request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    B: MessageBody + 'static,
{
    let Some(host) = crate::bootstrap::host::canonical_request_host(request.head()) else {
        return Ok(tenant_rejection(request, StatusCode::NOT_FOUND).map_into_right_body());
    };
    if !direct_tls_host_matches(
        request
            .request()
            .conn_data::<nazoauth::ConnectionFacts>()
            .and_then(|facts| facts.server_name.as_deref()),
        &host,
    ) {
        return Ok(tenant_rejection(request, StatusCode::MISDIRECTED_REQUEST).map_into_right_body());
    }
    let container = cache.borrow_mut().resolve(registry.load(), &host);
    let Some((container, tenant_id)) = container else {
        return Ok(tenant_rejection(request, StatusCode::NOT_FOUND).map_into_right_body());
    };

    request.add_data_container(container);
    Ok(crate::adapters::audit::REQUEST_TENANT
        .scope(tenant_id, async { next.call(request).await })
        .await?
        .map_into_left_body())
}

async fn request_timeout<B>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    request_timeout_with_duration(request, next, HTTP_REQUEST_TIMEOUT).await
}

async fn request_timeout_with_duration<B>(
    request: ServiceRequest,
    next: Next<B>,
    duration: Duration,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    timeout(duration, next.call(request))
        .await
        .map_err(|_| ErrorRequestTimeout("request exceeded the configured time limit"))?
}

async fn observe_request<B>(req: ServiceRequest, next: Next<B>) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    let method = req.method().clone();
    let started = std::time::Instant::now();
    let span = tracing::info_span!(
        "http.request",
        "otel.kind" = "server",
        "http.request.method" = %method,
        "http.route" = tracing::field::Empty
    );
    let future = next.call(req);
    async move {
        let result = future.await;
        let (route, status) = match &result {
            Ok(response) => {
                let request = response.request();
                let route = request.match_pattern().map(Cow::Owned).or_else(|| {
                    nazoauth::integration::route_for_path(request.uri().path())
                        .map(|route| Cow::Borrowed(route.path))
                });
                (route, response.status())
            }
            Err(error) => (None, error.as_response_error().status_code()),
        };
        let route = route.as_deref().unwrap_or("unmatched");
        tracing::Span::current().record("http.route", route);
        tracing::info!(
            monotonic_counter.http_server_requests = 1_u64,
            histogram.http_server_request_duration_ms = started.elapsed().as_secs_f64() * 1_000.0,
            "http.request.method" = %method,
            "http.response.status_code" = i64::from(status.as_u16()),
            "http.route" = route,
            "HTTP request completed"
        );
        result
    }
    .instrument(span)
    .await
}

/// Owns the Actix worker factory, middleware, route registration, and
/// listener setup.  All application data is assembled before entering this
/// function so worker creation cannot repeat persistence/provider initialization.
pub(super) async fn run(
    process: Arc<ProcessRuntime>,
    registry: TenantRuntimeRegistry,
) -> anyhow::Result<()> {
    let config = &process.config;
    let bind = config.get("BIND").unwrap_or("0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;
    let direct_tls = process.direct_tls.clone();
    let client_verifier = process.client_verifier.clone();
    let ui_static_dir = crate::bootstrap::ui_release::resolve(config).await?;
    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");
    tracing::info!(
        "inbound HTTP/1.1 only; HTTP/2 is disabled in this build; TLS and mTLS remain supported"
    );

    let server = HttpServer::new(move || {
        let cache = Rc::new(RefCell::new(WorkerTenantDataCache::default()));
        let tenant_registry = registry.clone();
        let mut tenant_scope = web::scope("");
        if let Some(path) = ui_static_dir.clone() {
            tenant_scope = tenant_scope.service(crate::bootstrap::ui_static_files(path));
        }
        tenant_scope = tenant_scope.configure(nazo_http_actix::configure);
        let tenant_scope = tenant_scope.wrap(from_fn(move |request, next| {
            bind_tenant_app_data(tenant_registry.clone(), Rc::clone(&cache), request, next)
        }));

        App::new()
            .wrap(from_fn(request_timeout))
            .wrap(from_fn(observe_request))
            .service(tenant_scope)
    })
    // Inbound HTTP/2 is not enabled in the native dependency graph.
    .client_request_timeout(HTTP_CLIENT_REQUEST_TIMEOUT)
    .max_connections(HTTP_MAX_CONNECTIONS_PER_WORKER)
    .on_connect(move |io, extensions| {
        crate::adapters::transport_facts::capture_direct_tls_client_certificate(
            io,
            extensions,
            client_verifier.as_deref(),
        );
    });
    let (server, tls_reloader) = if let Some(listeners) = direct_tls {
        tracing::info!("nazo-oauth-server direct HTTPS listener on {addr}");
        tracing::info!(
            "nazo-oauth-server direct mTLS listener on {}",
            listeners.mtls_bind
        );
        let snapshots = listeners.snapshots.clone();
        let reload_interval = listeners.reload_interval;
        let server = server
            .bind_rustls_0_23(addr, listeners.public)?
            .bind_rustls_0_23(listeners.mtls_bind, listeners.mtls)?;
        let reloader = crate::bootstrap::spawn_direct_tls_reloader(snapshots, reload_interval);
        (server, Some(reloader))
    } else {
        (server.bind(addr)?, None)
    };
    let result = server.run().await;
    if let Some(reloader) = tls_reloader {
        reloader.abort();
        let _ = reloader.await;
    }
    result?;
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/unit/bootstrap/startup/services/factory.rs"]
mod tests;
