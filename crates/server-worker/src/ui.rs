//! Same-origin NazoAuthWeb assets. Protocol routes never use an SPA fallback.
use bytes::Bytes;
use http::{Response, StatusCode, header};
use http_body_util::{BodyExt as _, Full};
use worker::{Env, HttpRequest};

use crate::WorkerConfiguration;

pub(crate) async fn serve(
    request: &HttpRequest,
    env: &Env,
    configuration: &WorkerConfiguration,
) -> Option<worker::Result<Response<Full<Bytes>>>> {
    if configuration.machine_only
        || !matches!(*request.method(), http::Method::GET | http::Method::HEAD)
    {
        return None;
    }
    let path = request.uri().path();
    if matches!(path, "/device" | "/ui/device")
        && !configuration
            .modules
            .contains(&nazo_runtime_modules::ModuleId::DeviceAuthorization)
    {
        return Some(Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Full::new(Bytes::new()))
            .expect("static response")));
    }
    let destination = match path {
        "/" | "/ui" => Some("/ui/"),
        "/auth" | "/auth/passkey" => Some("/ui/auth"),
        "/consent" => Some("/ui/consent"),
        "/device" => Some("/ui/device"),
        _ => None,
    };
    if let Some(destination) = destination {
        let mut location = destination.to_owned();
        if let Some(query) = request.uri().query() {
            location.push('?');
            location.push_str(query);
        }
        let result = Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(header::LOCATION, location)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Full::new(Bytes::new()))
            .map_err(|_| worker::Error::RustError("UI redirect failed".into()));
        return Some(result);
    }
    if !path.starts_with("/ui/") {
        return None;
    }
    Some(
        async {
            let assets = env.assets("ASSETS")?;
            let is_file = path
                .rsplit('/')
                .next()
                .is_some_and(|last| last.contains('.'))
                || path.starts_with("/ui/assets/")
                || path.starts_with("/ui/icons/");
            let target = if is_file { path } else { "/ui/index.html" };
            let url = format!("{}{target}", configuration.issuer.trim_end_matches('/'));
            let response = assets.fetch(url, None).await?;
            let (mut parts, body) = response.into_parts();
            // Large hashed assets are served directly by Cloudflare. Only the shell
            // or small manifest reaches this bounded path; missing files stay 404.
            let bytes = http_body_util::Limited::new(body, 512 * 1024)
                .collect()
                .await
                .map_err(|_| worker::Error::RustError("UI asset exceeds its limit".into()))?
                .to_bytes();
            if !is_file {
                parts.headers.insert(
                    header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-cache"),
                );
            }
            let body = if request.method() == http::Method::HEAD {
                Bytes::new()
            } else {
                bytes
            };
            Ok(Response::from_parts(parts, Full::new(body)))
        }
        .await,
    )
}
