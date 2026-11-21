use std::sync::Arc;

use crate::http::{
    Response as HttpResponse, empty_response, finish, json_response, json_response_status,
};
use http::StatusCode;
use nazo_persistence::DatabaseHealthPort;
use serde::Serialize;
use serde_json::json;

#[derive(Clone)]
pub struct ReadinessDependencies {
    database: Arc<dyn DatabaseHealthPort>,
    transient_state: Arc<dyn nazo_oauth_server::ports::transient_state::TransientStateHealthPort>,
    keyset: nazo_key_management::KeyManager,
}

impl ReadinessDependencies {
    pub fn new(
        database: Arc<dyn DatabaseHealthPort>,
        transient_state: Arc<
            dyn nazo_oauth_server::ports::transient_state::TransientStateHealthPort,
        >,
        keyset: nazo_key_management::KeyManager,
    ) -> Self {
        Self {
            database,
            transient_state,
            keyset,
        }
    }
}

#[derive(Serialize)]
struct DependencyCheck {
    status: &'static str,
}

#[derive(Serialize)]
struct ReadinessResponse {
    status: &'static str,
    checks: ReadinessChecks,
}

#[derive(Serialize)]
struct ReadinessChecks {
    database: DependencyCheck,
    transient_state: DependencyCheck,
    signing_keys: DependencyCheck,
}

pub async fn live() -> HttpResponse {
    json_response(json!({"status": "live"}))
}

pub async fn startup() -> HttpResponse {
    // The listener is bound only after migrations, dependency connections,
    // runtime-module initialization, and signing-key loading have completed.
    json_response(json!({"status": "started"}))
}

pub async fn ready(dependencies: &ReadinessDependencies) -> HttpResponse {
    let (database, transient_state) = futures_util::join!(
        dependencies.database.check(),
        dependencies.transient_state.check()
    );
    let database_up = database.is_ok();
    let transient_state_up = transient_state.is_ok();
    let signing_keys_up = dependencies.keyset.is_healthy();
    if let Err(error) = database {
        tracing::warn!(%error, "readiness database probe failed");
    }
    if let Err(error) = transient_state {
        tracing::warn!(%error, "readiness transient-state probe failed");
    }
    if !signing_keys_up {
        tracing::warn!("readiness signing-key lifecycle is unhealthy");
    }
    readiness_response(database_up, transient_state_up, signing_keys_up)
}

pub fn readiness_response(
    database_up: bool,
    transient_state_up: bool,
    signing_keys_up: bool,
) -> HttpResponse {
    let ready = database_up && transient_state_up && signing_keys_up;
    json_response_status(
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        ReadinessResponse {
            status: if ready { "ready" } else { "not_ready" },
            checks: ReadinessChecks {
                database: DependencyCheck {
                    status: if database_up { "up" } else { "down" },
                },
                transient_state: DependencyCheck {
                    status: if transient_state_up { "up" } else { "down" },
                },
                signing_keys: DependencyCheck {
                    status: if signing_keys_up { "up" } else { "down" },
                },
            },
        },
    )
}

pub async fn mdoc_crl(
    source: Option<&dyn crate::capabilities::MdocCrlProvider>,
    issuer_id: &str,
) -> HttpResponse {
    let Some(source) = source else {
        return crate::http::empty_response_no_store(StatusCode::NOT_FOUND);
    };
    let mut response = match source.signed_crl(issuer_id).await {
        Ok(Some(crl)) => finish(
            ::http::Response::builder()
                .header(::http::header::CONTENT_TYPE, "application/pkix-crl"),
            crl,
        ),
        Ok(None) => empty_response(StatusCode::NOT_FOUND),
        Err(error) => {
            tracing::warn!(%error, "mdoc CRL is unavailable");
            empty_response(StatusCode::SERVICE_UNAVAILABLE)
        }
    };
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
#[path = "../tests/unit/well_known_crl.rs"]
mod crl_tests;
