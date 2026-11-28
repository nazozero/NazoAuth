#![forbid(unsafe_code)]
//! An existing Axum application with one NazoAuth mount call.

use std::{net::SocketAddr, sync::Arc};

use axum::{Router, extract::ConnectInfo, http::StatusCode, routing::get, serve::IncomingStream};
use nazoauth::{ConnectionFacts, NazoAuth, runtime::TenantRuntimeRegistry};
use tokio::net::TcpListener;

/// The host's existing routes, UI, method handling and fallback.
pub fn application(mount_path: &str) -> Router {
    let ui = format!("{}/ui", mount_path.trim_end_matches('/'));
    Router::new()
        .route("/api/health", get(|| async { "existing-api" }))
        .route(
            "/api/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
        )
        .route("/users/me", get(|| async { "existing-user" }))
        .route(&ui, get(|| async { "host-owned-ui" }))
        .fallback(|| async { (StatusCode::NOT_FOUND, "host-fallback") })
        .method_not_allowed_fallback(|| async {
            (StatusCode::METHOD_NOT_ALLOWED, "host-method-not-allowed")
        })
}

/// Continue serving on the application's listener with its actual socket facts.
pub async fn serve(listener: TcpListener, auth: Arc<NazoAuth>) -> anyhow::Result<()> {
    let app = application(auth.mount().path());
    let app = nazo_http_tower::mount_make_service(
        app.into_make_service_with_connect_info::<SocketAddr>(),
        auth,
        &["/api", "/users"],
        |connection: &IncomingStream<'_, TcpListener>| ConnectionFacts {
            peer_addr: Some(*connection.remote_addr()),
            ..ConnectionFacts::default()
        },
    )?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Serve the shared live tenant directory on the host's existing listener.
///
/// Keep the shared runtime owner alive until this listener has drained. The
/// registry publishes rebuilt tenant graphs without replacing the Axum router.
pub async fn serve_dynamic(
    listener: TcpListener,
    existing: Router,
    tenants: TenantRuntimeRegistry,
) -> anyhow::Result<()> {
    let app = nazo_http_tower::mount_make_service_dynamic(
        existing.into_make_service_with_connect_info::<SocketAddr>(),
        tenants,
        &["/api", "/users"],
        |connection: &IncomingStream<'_, TcpListener>| ConnectionFacts {
            peer_addr: Some(*connection.remote_addr()),
            ..ConnectionFacts::default()
        },
    )?;
    axum::serve(listener, app).await?;
    Ok(())
}
