//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod authentication_services;
mod host;
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

fn ui_static_files(root: PathBuf) -> impl HttpServiceFactory {
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
    web::scope("/ui")
        .wrap(from_fn(security_headers))
        .service(files)
}

#[cfg(test)]
#[path = "../../tests/unit/bootstrap.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/support/bootstrap.rs"]
pub(crate) mod test_support;
