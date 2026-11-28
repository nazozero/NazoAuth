//! One-call mounting for an existing Axum application.

use std::{net::SocketAddr, sync::Arc};

use ::axum::{Router, body::Body, extract::ConnectInfo, routing::RouterIntoService};
use http::Request;
use nazoauth::{ConnectionFacts, NazoAuth};

use crate::Mounted;

/// Mount a prepared tenant around the complete application, preserving its
/// routes, method handling and fallback. Configure the application's state and
/// routes before mounting. `reserved_paths` declares occupied host namespaces
/// so conflicts fail during mounting; Axum does not expose its route table.
///
/// The result is a Tower service. Use Axum's normal `ServiceExt` when serving it:
///
/// ```no_run
/// use std::{net::SocketAddr, sync::Arc};
/// use axum::{Router, ServiceExt};
/// use nazoauth::NazoAuth;
///
/// # fn application(app: Router, auth: Arc<NazoAuth>) -> anyhow::Result<()> {
/// let app = nazo_http_tower::axum::mount(app, auth, &["/api"])?;
/// let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
/// # let _ = make_service;
/// # Ok(())
/// # }
/// ```
///
/// `ConnectInfo<SocketAddr>` supplies the socket peer when no `ConnectionFacts`
/// extension is present. An authenticated ingress can supply that extension
/// before this service; its values are retained. Forwarding headers never
/// establish connection facts here.
pub fn mount(
    existing: Router,
    application: Arc<NazoAuth>,
    reserved_paths: &[&str],
) -> anyhow::Result<Mounted<RouterIntoService<Body>>> {
    // Match Axum's make-service preparation: turn handlers into routes once.
    crate::mount(
        existing.with_state(()).into_service::<Body>(),
        application,
        reserved_paths,
    )
}

pub(crate) fn connection_facts<B>(request: &mut Request<B>) {
    if request.extensions().get::<ConnectionFacts>().is_some() {
        return;
    }
    if let Some(ConnectInfo(peer_addr)) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
    {
        request.extensions_mut().insert(ConnectionFacts {
            peer_addr: Some(peer_addr),
            ..ConnectionFacts::default()
        });
    }
}

#[cfg(test)]
#[path = "../tests/unit/axum.rs"]
mod tests;
