#[path = "framework_boundary_transport/authorization_contract.rs"]
mod authorization_contract;
#[path = "framework_boundary_transport/ciba_device.rs"]
mod ciba_device;
#[path = "framework_boundary_transport/dynamic_registration.rs"]
mod dynamic_registration;
#[path = "framework_boundary_transport/fapi_resource.rs"]
mod fapi_resource;
#[path = "framework_boundary_transport/mtls_real_boundary.rs"]
mod mtls_real_boundary;
#[path = "framework_boundary_transport/rate_limit_dpop.rs"]
mod rate_limit_dpop;
#[path = "framework_boundary_transport/userinfo_mtls.rs"]
mod userinfo_mtls;
#[path = "framework_boundary_transport/well_known_views.rs"]
mod well_known_views;

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, body::to_bytes};

async fn live_transport_state() -> crate::test_support::TestInfrastructure {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("transport golden tests require the configured test PostgreSQL database");
    let valkey_url = std::env::var("VALKEY_URL")
        .expect("transport golden tests require the configured test Valkey instance");
    let database = nazo_postgres::create_pool(database_url, 2).expect("test database pool");
    let valkey = nazo_valkey::test_support::connect(&valkey_url, std::time::Duration::from_secs(1))
        .await
        .expect("test Valkey connection");
    let mut settings =
        crate::settings::Settings::from_config(&crate::config::ConfigSource::default())
            .expect("test settings");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://mtls.example".to_owned();
    settings.protocol.default_audience = "resource://default".to_owned();
    crate::test_support::initialize_audit_dependencies(&database);
    crate::test_support::TestInfrastructure {
        diesel_db: database,
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

async fn ready_body_bytes(response: HttpResponse) -> Vec<u8> {
    to_bytes(response.into_body())
        .await
        .expect("response body must serialize to bytes")
        .to_vec()
}

struct NoFapiMtls;

impl nazo_http_actix::mtls::MtlsThumbprintExtractor for NoFapiMtls {
    fn resolve(&self, _request: &HttpRequest) -> Option<String> {
        panic!("certificate extraction must not run without access token")
    }
}
