#![forbid(unsafe_code)]
//! An existing Axum application with one NazoAuth mount call.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router, ServiceExt, body::Body, http::StatusCode, routing::RouterIntoService, routing::get,
};
use nazo_http_tower::Mounted;
use nazoauth::NazoAuth;

/// Supply the prepared tenant; the host retains its routes, UI and fallback.
pub fn application(auth: Arc<NazoAuth>) -> anyhow::Result<Mounted<RouterIntoService<Body>>> {
    let ui = format!("{}/ui", auth.mount().path().trim_end_matches('/'));
    let app = Router::new()
        .route("/api/health", get(|| async { "existing-api" }))
        .route("/users/me", get(|| async { "existing-user" }))
        .route(&ui, get(|| async { "host-owned-ui" }))
        .fallback(|| async { (StatusCode::NOT_FOUND, "host-fallback") })
        .method_not_allowed_fallback(|| async {
            (StatusCode::METHOD_NOT_ALLOWED, "host-method-not-allowed")
        });

    nazo_http_tower::axum::mount(app, auth, &["/api/", "/users", &ui])
}

/// Continue serving on the application's listener with its actual socket facts.
pub async fn serve(listener: tokio::net::TcpListener, auth: Arc<NazoAuth>) -> anyhow::Result<()> {
    let app = application(auth)?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
