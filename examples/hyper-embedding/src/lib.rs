#![forbid(unsafe_code)]
//! A native Hyper host using the shared Tower adapter.

use std::{error::Error, sync::Arc};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::{body::Body, service::Service};
use hyper_util::service::TowerToHyperService;
use nazoauth::{NazoAuth, NazoAuthBuilder, capabilities::Capabilities, config::Configuration};

/// Prepare one tenant with the embedding application's actual I/O capabilities.
pub async fn build(
    configuration: Configuration,
    capabilities: Capabilities,
    instance_id: impl Into<String>,
    prefix: &str,
) -> anyhow::Result<Arc<NazoAuth>> {
    Ok(Arc::new(
        NazoAuthBuilder::new(configuration, capabilities, instance_id)
            .mount_path(prefix)
            .build()
            .await?,
    ))
}

/// Install the shared mounted service at Hyper's Tower service boundary.
///
/// The host supplies a Tower service for its existing routes and connection
/// facts in request extensions. Hyper's adapter handles readiness on each call.
pub fn mount<S, B>(
    application: Arc<NazoAuth>,
    existing: S,
    occupied_paths: &[&str],
) -> anyhow::Result<
    impl Service<Request<B>, Response = Response<Full<Bytes>>, Error = S::Error, Future: Send>
    + Clone
    + use<S, B>,
>
where
    S: tower::Service<Request<B>, Response = Response<Full<Bytes>>> + Clone + Send,
    S::Future: Send,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    Ok(TowerToHyperService::new(nazo_http_tower::mount(
        existing,
        application,
        occupied_paths,
    )?))
}
