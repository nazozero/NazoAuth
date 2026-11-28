use super::super::tenant_runtime::ProcessRuntime;
use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::error::ErrorRequestTimeout;
use actix_web::middleware::{Next, from_fn};
use actix_web::{App, Error, HttpServer, web};
use nazoauth::runtime::TenantRuntimeRegistry;
use std::borrow::Cow;
use std::net::SocketAddr;
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

/// The listener owns TLS reloads even when its serving future is cancelled.
struct TlsReloader(tokio::task::JoinHandle<()>);

impl Drop for TlsReloader {
    fn drop(&mut self) {
        self.0.abort();
    }
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
                    request
                        .app_data::<web::Data<nazoauth::NazoAuth>>()
                        .and_then(|application| application.route_for_path(request.uri().path()))
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
pub(in crate::bootstrap::startup) async fn run(
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

    let mount = nazo_http_actix::DynamicMount::new(registry, &[])?;
    let server = HttpServer::new(move || {
        let mut host = web::scope("");
        if let Some(path) = ui_static_dir.clone() {
            host = host.service(crate::bootstrap::ui_static_files(path));
        }
        App::new()
            .service(host)
            .wrap(mount.clone())
            .wrap(from_fn(request_timeout))
            .wrap(from_fn(observe_request))
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
        (server, Some(TlsReloader(reloader)))
    } else {
        (server.bind(addr)?, None)
    };
    let result = server.run().await;
    if let Some(mut reloader) = tls_reloader {
        reloader.0.abort();
        let _ = (&mut reloader.0).await;
    }
    result?;
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/unit/bootstrap/startup/services/factory.rs"]
mod tests;
