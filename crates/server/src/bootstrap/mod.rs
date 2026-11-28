//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod authentication_services;
mod object_store;
pub(crate) mod observability;
mod registration_services;
mod startup;
mod transport;
mod ui_release;
pub(crate) use authentication_services::LoginPasswordVerifier;
pub use object_store::{
    ServerAvatarObjectStoreBindings, ServerAvatarObjectStoreProvider, ServerAvatarStorageCapability,
};
pub(crate) use registration_services::RegistrationSecretHasher;
pub use startup::run;

use std::{path::PathBuf, sync::Arc};

use crate::adapters::security::{
    configure_password_hash_limits, default_password_hash_max_concurrency,
    default_password_hash_queue_timeout_ms, initialize_dummy_password_hash,
};
use crate::config::ConfigSource;
use crate::settings::Settings;
use actix_files::{Files, NamedFile};
use actix_web::{
    HttpResponse,
    dev::{HttpServiceFactory, ServiceRequest, ServiceResponse, fn_service},
    middleware::from_fn,
    web,
};
use nazo_http_actix::security_headers;
use transport::{direct_tls_listeners, spawn_direct_tls_reloader};

/// Application persistence and deployment authority supplied by the native launcher.
pub struct ServerPersistence {
    pub application: nazo_oauth_server::ports::persistence::ServerPersistenceBindings,
    pub tenant_directory: Arc<dyn nazo_persistence::TenantDirectoryStore>,
    pub controller_registry: Arc<dyn nazo_persistence::ControllerRegistryPort>,
    pub recovery_root: Arc<dyn nazo_persistence::RecoveryRootPort>,
}

pub(crate) fn ui_static_files(root: PathBuf) -> impl HttpServiceFactory {
    let index = root.join("index.html");
    let files = Files::new("", root)
        .index_file("index.html")
        .disable_content_disposition()
        .default_handler(fn_service(move |request: ServiceRequest| {
            let index = index.clone();
            async move {
                let missing_asset = request
                    .path()
                    .rsplit('/')
                    .next()
                    .is_some_and(|segment| segment.contains('.'));
                let (request, _) = request.into_parts();
                if missing_asset {
                    return Ok(ServiceResponse::new(
                        request,
                        HttpResponse::NotFound().finish(),
                    ));
                }
                let file = match NamedFile::open(index) {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(ServiceResponse::new(
                            request,
                            HttpResponse::NotFound().finish(),
                        ));
                    }
                    Err(error) => return Err(error.into()),
                };
                let response = file.into_response(&request);
                Ok(ServiceResponse::new(request, response))
            }
        }));
    web::scope("")
        .guard(actix_web::guard::fn_guard(|context| {
            let prefix = context
                .app_data::<web::Data<nazoauth::NazoAuth>>()
                .map_or("", |application| {
                    application.mount().path().trim_end_matches('/')
                });
            let raw_path = context.head().uri.path();
            // Keep the selected tenant's mount literal; Actix handles ordinary
            // UI escapes after that boundary just as it does for static assets.
            if !raw_path.starts_with(prefix) {
                return false;
            }
            let decoded = actix_web::dev::Url::new(context.head().uri.clone());
            decoded.path().strip_prefix(prefix).is_some_and(|tail| {
                tail.strip_prefix("/ui")
                    .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
            })
        }))
        .wrap(from_fn(ui_file_path))
        .wrap(from_fn(security_headers))
        .default_service(files)
}

async fn ui_file_path<B: actix_web::body::MessageBody>(
    mut request: ServiceRequest,
    next: actix_web::middleware::Next<B>,
) -> Result<ServiceResponse<B>, actix_web::Error> {
    let prefix_len = request
        .app_data::<web::Data<nazoauth::NazoAuth>>()
        .map_or(0, |application| {
            application.mount().path().trim_end_matches('/').len()
        });
    let consumed = u16::try_from(prefix_len + "/ui".len())
        .map_err(|_| actix_web::error::ErrorBadRequest("UI mount path is too long"))?;
    // Only the host's static-file route cursor changes. The external request
    // target remains untouched, and Files retains its path traversal checks.
    request.match_info_mut().reset();
    request.match_info_mut().skip(consumed);
    next.call(request).await
}

#[cfg(test)]
#[path = "../../tests/unit/bootstrap.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/support/bootstrap.rs"]
pub(crate) mod test_support;
