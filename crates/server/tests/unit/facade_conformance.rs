use std::sync::Arc;

use actix_web::{App, HttpResponse, body::MessageBody, test as awtest, web};
use bytes::Bytes;
use nazoauth::{ConnectionFacts, integration::conformance};

#[path = "facade_axum.rs"]
mod axum_embedding;
#[path = "facade_configuration.rs"]
mod configuration;
#[path = "facade_cors.rs"]
mod cors;
#[path = "facade_credentials.rs"]
mod credentials;
#[path = "facade_hyper.rs"]
mod hyper_embedding;
#[path = "facade_ingress.rs"]
mod ingress;
#[path = "facade_mount.rs"]
mod mount;
#[path = "facade_oauth.rs"]
mod oauth;
#[path = "facade_passkey.rs"]
mod passkey;

pub(crate) fn deployment(
    control_tenant: nazo_identity::TenantId,
    database: &nazo_postgres::DbPool,
) -> Arc<nazoauth::capabilities::DeploymentCapabilities> {
    use nazo_operator_protocol::{
        CONTROL_DISCOVERY_PRODUCT, CONTROL_DISCOVERY_SCHEMA, DeploymentStatement, PROTOCOL_VERSION,
        instance_key_id,
    };
    struct ControlTenant(nazo_identity::TenantId);
    impl nazoauth::capabilities::TenantAvailability for ControlTenant {
        fn contains_tenant(&self, tenant: nazo_identity::TenantId) -> bool {
            self.0 == tenant
        }
    }
    let key = nazo_crypto::ed25519::SigningKey::from_bytes(&[7; 32]);
    let identity = nazoauth::capabilities::DeploymentIdentity::new(
        key.clone(),
        DeploymentStatement {
            schema: CONTROL_DISCOVERY_SCHEMA,
            product: CONTROL_DISCOVERY_PRODUCT.to_owned(),
            deployment_id: "test-deployment".to_owned(),
            runtime_instance_id: "test-instance".to_owned(),
            issuer: "https://issuer.example".to_owned(),
            release: "test".to_owned(),
            control_protocol_versions: vec![CONTROL_DISCOVERY_SCHEMA],
            operator_protocol_versions: vec![PROTOCOL_VERSION],
            instance_key_id: instance_key_id(&key.verifying_key()),
            issued_at: 1_700_000_000,
        },
    )
    .unwrap();
    Arc::new(nazoauth::capabilities::DeploymentCapabilities {
        identity,
        control_tenant,
        tenants: Arc::new(ControlTenant(control_tenant)),
        controller_registry: Arc::new(nazo_postgres::ControllerRegistryRepository::new(
            database.clone(),
        )),
        recovery_root: Arc::new(nazo_postgres::RecoveryRootRepository::new(database.clone())),
    })
}

pub(crate) async fn infrastructure(
    register_optional_routes: bool,
) -> crate::test_support::TestInfrastructure {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("facade conformance requires the configured test PostgreSQL database");
    let valkey_url = std::env::var("VALKEY_URL")
        .expect("facade conformance requires the configured test Valkey instance");
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("facade conformance database migrations");
    let database = nazo_postgres::create_pool(database_url, 2).expect("test database pool");
    let valkey = nazo_valkey::test_support::connect(&valkey_url, std::time::Duration::from_secs(1))
        .await
        .expect("test Valkey connection");
    let mut settings = crate::settings::Settings::from_config(
        &crate::config::ConfigSource::from_pairs_for_test([]),
    )
    .unwrap();
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://mtls.example".to_owned();
    settings.protocol.protected_resource_identifier =
        "https://issuer.example/fapi/resource".to_owned();
    settings.session.cookie_secure = true;
    settings.modules.register_openid4vci_routes = register_optional_routes;
    settings.modules.register_openid4vp_routes = register_optional_routes;
    settings.modules.enable_openid4vci_issuer = false;
    settings.modules.enable_openid4vp_verifier = false;
    crate::test_support::initialize_audit_dependencies(&database);
    crate::test_support::TestInfrastructure {
        diesel_db: database,
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager_with_auxiliary(
            jsonwebtoken::Algorithm::RS256,
        ),
    }
}

pub(crate) fn framework_request(request: &http::Request<Bytes>) -> awtest::TestRequest {
    let mut builder = awtest::TestRequest::with_uri(&request.uri().to_string())
        .method(actix_web::http::Method::from_bytes(request.method().as_str().as_bytes()).unwrap())
        .set_payload(request.body().clone());
    for (name, value) in request.headers() {
        builder = builder.append_header((name.as_str(), value.as_bytes()));
    }
    if let Some(peer) = request
        .extensions()
        .get::<ConnectionFacts>()
        .and_then(|facts| facts.peer_addr)
    {
        builder = builder.peer_addr(peer);
    }
    builder
}

pub(crate) async fn standard_response(response: HttpResponse) -> http::Response<Bytes> {
    let mut standard = http::Response::builder().status(response.status().as_u16());
    for (name, value) in response.headers() {
        standard = standard.header(name.as_str(), value.as_bytes());
    }
    let body = match response.into_body().try_into_bytes() {
        Ok(bytes) => bytes,
        Err(stream) => actix_web::body::to_bytes(stream).await.unwrap(),
    };
    standard.body(body).unwrap()
}

#[actix_web::test]
async fn public_facade_and_actix_keep_routes_and_protocol_contracts_equivalent() {
    for register_optional_routes in [false, true] {
        let mut state = infrastructure(register_optional_routes).await;
        Arc::make_mut(&mut state.settings)
            .endpoint
            .cors_allowed_origins = vec!["https://browser.example".to_owned()];
        let facade = crate::test_support::facade::application(&state)
            .await
            .unwrap();
        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::from(facade.clone()))
                .configure(nazo_http_actix::configure),
        )
        .await;
        conformance::assert_adapter(&facade, |request| {
            let app = &app;
            async move {
                standard_response(
                    awtest::call_service(app, framework_request(&request).to_request())
                        .await
                        .into_parts()
                        .1,
                )
                .await
            }
        })
        .await;
        for (method, target) in [
            (http::Method::GET, "/.well-known/openid-credential-issuer"),
            (http::Method::POST, "/openid4vci/nonce"),
            (
                http::Method::GET,
                "/admin/openid4vci/credential-datasets/subject/configuration",
            ),
            (http::Method::POST, "/openid4vp/presentations"),
        ] {
            let response = awtest::call_service(
                &app,
                awtest::TestRequest::with_uri(target)
                    .method(
                        actix_web::http::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
                    )
                    .to_request(),
            )
            .await;
            assert_eq!(
                response.status(),
                actix_web::http::StatusCode::NOT_FOUND,
                "optional tenant capability became visible with process registration={register_optional_routes}: {target}"
            );
        }
    }
}
