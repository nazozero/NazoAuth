use super::*;
use actix_web::body::EitherBody;
use actix_web::dev::Extensions;
use actix_web::{App, HttpResponse, test, web};
use arc_swap::ArcSwap;
use futures_util::{StreamExt as _, stream};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

#[test]
async fn direct_tls_sni_and_http_host_must_select_the_same_tenant() {
    assert!(direct_tls_host_matches(None, "tenant-a.example"));
    assert!(direct_tls_host_matches(
        Some("tenant-a.example"),
        "tenant-a.example"
    ));
    assert!(!direct_tls_host_matches(
        Some("tenant-a.example"),
        "tenant-b.example"
    ));
}

#[actix_web::test]
async fn tenant_rejections_keep_security_headers_and_the_session_iframe_exception() {
    for path in ["/token", "/check_session"] {
        for status in [StatusCode::NOT_FOUND, StatusCode::MISDIRECTED_REQUEST] {
            let response =
                tenant_rejection(test::TestRequest::get().uri(path).to_srv_request(), status);
            assert_eq!(response.status(), status);
            for (name, value) in nazoauth::integration::security_headers(path) {
                assert_eq!(
                    response
                        .headers()
                        .get(name.as_str())
                        .map(|value| value.as_bytes()),
                    Some(value.as_bytes())
                );
            }
            assert_eq!(
                response
                    .headers()
                    .get("x-frame-options")
                    .map(|value| value.as_bytes()),
                (path != "/check_session").then_some(b"DENY".as_slice()),
            );
            assert_eq!(
                response
                    .headers()
                    .get("content-security-policy")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .contains("frame-ancestors 'none'"),
                path != "/check_session",
            );
            assert!(test::read_body(response).await.is_empty());
        }
    }
}

#[actix_web::test]
async fn request_metrics_keep_host_patterns_and_canonical_product_routes() {
    let log = std::env::temp_dir().join(format!("http-metrics-{}.log", uuid::Uuid::now_v7()));
    let writer = std::fs::File::create_new(&log).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.try_clone().unwrap())
        .finish();
    let subscriber = tracing::subscriber::set_default(subscriber);
    let app = test::init_service(
        App::new().wrap(from_fn(observe_request)).service(
            web::scope("")
                .service(web::scope("/ui").route(
                    "/{asset:.*}",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                ))
                .route(
                    "/admin/clients/{native_client}",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                )
                .default_service(web::to(|| async { HttpResponse::NotFound().finish() })),
        ),
    )
    .await;
    let cases = [
        ("/jwks.json", "/jwks.json", StatusCode::NOT_FOUND),
        (
            "/register/private-client-id?state=private-query",
            "/register/{client_id}",
            StatusCode::NOT_FOUND,
        ),
        (
            "/.well-known/oauth-protected-resource/private/resource",
            "/.well-known/oauth-protected-resource/{*tail}",
            StatusCode::NOT_FOUND,
        ),
        ("/%6Awks.json", "/jwks.json", StatusCode::NOT_FOUND),
        (
            "/admin/clients/private-native-id",
            "/admin/clients/{native_client}",
            StatusCode::OK,
        ),
        ("/ui/assets/private.js", "/ui/{asset:.*}", StatusCode::OK),
        (
            "/private-unknown-path?state=private-query",
            "unmatched",
            StatusCode::NOT_FOUND,
        ),
    ];
    for (path, _, status) in cases {
        let response =
            test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
        assert_eq!(response.status(), status);
    }
    drop(subscriber);
    let output = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_file(log).unwrap();
    let events = output
        .lines()
        .filter(|line| line.contains("HTTP request completed"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), cases.len());
    for (event, (_, route, status)) in events.iter().zip(cases) {
        assert!(
            event.contains(&format!("http.route=\"{route}\"")),
            "{event}"
        );
        assert!(
            event.contains(&format!("http.response.status_code={}", status.as_u16())),
            "{event}"
        );
        assert!(
            !event.contains("private-"),
            "raw request target entered metrics"
        );
    }
}

async fn test_request_timeout<B>(
    request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    request_timeout_with_duration(request, next, Duration::from_millis(10)).await
}

fn delayed_payload() -> actix_web::dev::Payload {
    let stream = stream::once(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok::<web::Bytes, actix_web::error::PayloadError>(web::Bytes::from_static(
            br#"{"value":"ok"}"#,
        ))
    });
    let stream: Pin<
        Box<dyn futures_util::Stream<Item = Result<web::Bytes, actix_web::error::PayloadError>>>,
    > = Box::pin(stream);
    actix_web::dev::Payload::from(stream)
}

#[actix_web::test]
async fn request_timeout_covers_typed_json_extractor() {
    let log = std::env::temp_dir().join(format!("http-metrics-{}.log", uuid::Uuid::now_v7()));
    let writer = std::fs::File::create_new(&log).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.try_clone().unwrap())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let app = test::init_service(
        App::new()
            .wrap(from_fn(test_request_timeout))
            .wrap(from_fn(observe_request))
            .route(
                "/json",
                web::post()
                    .to(|_: web::Json<serde_json::Value>| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/json")
        .insert_header(("content-type", "application/json"))
        .to_request();
    let (request, _) = request.replace_payload(delayed_payload());
    let error = test::try_call_service(&app, request)
        .await
        .expect_err("slow JSON body must time out");

    assert_eq!(
        error.as_response_error().status_code(),
        actix_web::http::StatusCode::REQUEST_TIMEOUT
    );
    drop(_subscriber);
    let output = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_file(log).unwrap();
    let mut events = output
        .lines()
        .filter(|line| line.contains("HTTP request completed"));
    let event = events.next().expect("timeout completion metric");
    assert!(event.contains("monotonic_counter.http_server_requests=1"));
    assert!(event.contains("histogram.http_server_request_duration_ms="));
    assert!(event.contains("http.response.status_code=408"));
    assert!(event.contains("http.route=\"unmatched\""));
    assert!(events.next().is_none());
}

#[actix_web::test]
async fn request_timeout_covers_raw_payload_extractor() {
    let app = test::init_service(App::new().wrap(from_fn(test_request_timeout)).route(
        "/raw",
        web::post().to(|mut payload: web::Payload| async move {
            while payload.next().await.is_some() {}
            HttpResponse::Ok().finish()
        }),
    ))
    .await;

    let request = test::TestRequest::post().uri("/raw").to_request();
    let (request, _) = request.replace_payload(delayed_payload());
    let error = test::try_call_service(&app, request)
        .await
        .expect_err("slow raw payload must time out");

    assert_eq!(
        error.as_response_error().status_code(),
        actix_web::http::StatusCode::REQUEST_TIMEOUT
    );
}

async fn tenant_issuer(issuer: web::Data<&'static str>) -> HttpResponse {
    HttpResponse::Ok().body(*issuer.get_ref())
}

#[derive(Clone)]
struct TestTenantData {
    issuer: web::Data<&'static str>,
    context: web::Data<nazo_identity::TenantContext>,
    application: Option<web::Data<nazoauth::NazoAuth>>,
}

impl TestTenantData {
    fn system(issuer: &'static str) -> Self {
        Self {
            issuer: web::Data::new(issuer),
            context: web::Data::new(nazo_identity::TenantContext::default_system()),
            application: None,
        }
    }

    fn tenant(issuer: &'static str, tenant_id: u128) -> Self {
        let mut context = nazo_identity::TenantContext::default_system();
        context.tenant_id = nazo_identity::TenantId::new(uuid::Uuid::from_u128(tenant_id))
            .expect("non-zero test tenant id");
        Self {
            issuer: web::Data::new(issuer),
            context: web::Data::new(context),
            application: None,
        }
    }
}

type TestTenantIndex = HashMap<String, TestTenantData>;

#[derive(Default)]
struct TestWorkerCache {
    index: Option<Arc<TestTenantIndex>>,
    by_host: HashMap<String, Rc<Extensions>>,
}

async fn bind_test_tenant<B>(
    registry: Arc<ArcSwap<TestTenantIndex>>,
    cache: Rc<RefCell<TestWorkerCache>>,
    builds: Rc<Cell<usize>>,
    mut request: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    B: MessageBody + 'static,
{
    let Some(host) = crate::bootstrap::host::canonical_request_host(request.head()) else {
        return Ok(request
            .into_response(HttpResponse::NotFound().finish())
            .map_into_right_body());
    };
    let index = registry.load_full();
    let container = {
        let mut cache = cache.borrow_mut();
        let changed = match &cache.index {
            Some(current) => !Arc::ptr_eq(current, &index),
            None => true,
        };
        if changed {
            cache.index = Some(Arc::clone(&index));
            cache.by_host.clear();
        }
        if let Some(container) = cache.by_host.get(&host) {
            Some(Rc::clone(container))
        } else {
            index.get(&host).map(|tenant| {
                builds.set(builds.get() + 1);
                let mut extensions = Extensions::new();
                let _ = extensions.insert(tenant.issuer.clone());
                let _ = extensions.insert(tenant.context.clone());
                if let Some(application) = &tenant.application {
                    let _ = extensions.insert(application.clone());
                }
                let container = Rc::new(extensions);
                cache.by_host.insert(host.clone(), Rc::clone(&container));
                container
            })
        }
    };
    let Some(container) = container else {
        return Ok(request
            .into_response(HttpResponse::NotFound().finish())
            .map_into_right_body());
    };
    request.add_data_container(container);
    Ok(next.call(request).await?.map_into_left_body())
}

#[actix_web::test]
async fn request_data_container_tracks_runtime_host_index_updates() {
    let registry = Arc::new(ArcSwap::from_pointee(HashMap::from([(
        "tenant-a.example".to_owned(),
        TestTenantData::tenant("https://tenant-a.example/v1", 2),
    )])));
    let cache = Rc::new(RefCell::new(TestWorkerCache::default()));
    let builds = Rc::new(Cell::new(0));
    let app = test::init_service(
        App::new().service(
            web::scope("")
                .app_data(web::Data::new("static-value-must-be-overridden"))
                .wrap(from_fn({
                    let registry = Arc::clone(&registry);
                    let cache = Rc::clone(&cache);
                    let builds = Rc::clone(&builds);
                    move |request, next| {
                        bind_test_tenant(
                            Arc::clone(&registry),
                            Rc::clone(&cache),
                            Rc::clone(&builds),
                            request,
                            next,
                        )
                    }
                }))
                .route("/issuer", web::get().to(tenant_issuer)),
        ),
    )
    .await;

    macro_rules! assert_issuer {
        ($host:expr, $expected:expr) => {{
            let request = test::TestRequest::get()
                .uri("/issuer")
                .insert_header(("host", $host))
                .to_request();
            let response = test::call_service(&app, request).await;
            assert_eq!(response.status(), actix_web::http::StatusCode::OK);
            assert_eq!(test::read_body(response).await, $expected);
        }};
    }

    assert_issuer!("Tenant-A.Example.:443", "https://tenant-a.example/v1");
    assert_issuer!("tenant-a.example", "https://tenant-a.example/v1");
    assert_eq!(
        builds.get(),
        1,
        "same index must reuse the worker container"
    );

    let mut with_b = (*registry.load_full()).clone();
    with_b.insert(
        "tenant-b.example".to_owned(),
        TestTenantData::tenant("https://tenant-b.example", 3),
    );
    registry.store(Arc::new(with_b));
    assert_issuer!("tenant-b.example", "https://tenant-b.example");

    let mut replaced = (*registry.load_full()).clone();
    replaced.insert(
        "tenant-a.example".to_owned(),
        TestTenantData::tenant("https://tenant-a.example/v2", 2),
    );
    registry.store(Arc::new(replaced));
    assert_issuer!("tenant-a.example", "https://tenant-a.example/v2");

    let mut without_b = (*registry.load_full()).clone();
    without_b.remove("tenant-b.example");
    registry.store(Arc::new(without_b));
    let disabled = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/issuer")
            .insert_header(("host", "tenant-b.example"))
            .to_request(),
    )
    .await;
    assert_eq!(disabled.status(), actix_web::http::StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn deployment_routes_are_gated_but_runtime_modules_are_tenant_scoped() {
    let state = crate::facade_conformance::infrastructure(false).await;
    let deployment = crate::facade_conformance::deployment(
        nazo_identity::TenantContext::default_system().tenant_id,
    );
    let mut tenants = HashMap::from([
        (
            "system.example".to_owned(),
            TestTenantData::system("https://system.example"),
        ),
        (
            "tenant.example".to_owned(),
            TestTenantData::tenant("https://tenant.example", 2),
        ),
    ]);
    for tenant in tenants.values_mut() {
        let mut state = state.clone();
        let settings = Arc::make_mut(&mut state.settings);
        settings.tenant.context = *tenant.context.get_ref();
        settings.endpoint.issuer = tenant.issuer.get_ref().to_string();
        settings.endpoint.cors_allowed_origins = vec!["https://admin.example".to_owned()];
        let application = crate::test_support::facade::builder(&state, Default::default())
            .unwrap()
            .with_deployment(deployment.clone())
            .build()
            .await
            .unwrap();
        tenant.application = Some(web::Data::new(application));
    }
    let registry = Arc::new(ArcSwap::from_pointee(tenants));
    let cache = Rc::new(RefCell::new(TestWorkerCache::default()));
    let builds = Rc::new(Cell::new(0));
    let app = test::init_service(
        App::new().service(
            web::scope("")
                .configure(nazo_http_actix::configure)
                .wrap(from_fn({
                    let registry = Arc::clone(&registry);
                    let cache = Rc::clone(&cache);
                    let builds = Rc::clone(&builds);
                    move |request, next| {
                        bind_test_tenant(
                            Arc::clone(&registry),
                            Rc::clone(&cache),
                            Rc::clone(&builds),
                            request,
                            next,
                        )
                    }
                })),
        ),
    )
    .await;

    let preflight = |host: &'static str, path: &'static str| {
        test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri(path)
            .insert_header((actix_web::http::header::HOST, host))
            .insert_header((actix_web::http::header::ORIGIN, "https://admin.example"))
            .insert_header((
                actix_web::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                "GET",
            ))
            .to_request()
    };

    let tenant_runtime_modules =
        test::call_service(&app, preflight("tenant.example", "/admin/runtime-modules")).await;
    assert_eq!(
        tenant_runtime_modules.status(),
        actix_web::http::StatusCode::OK
    );

    let system_route =
        test::call_service(&app, preflight("system.example", "/admin/runtime-modules")).await;
    assert_eq!(system_route.status(), actix_web::http::StatusCode::OK);

    let tenant_admin_route =
        test::call_service(&app, preflight("tenant.example", "/admin/users")).await;
    assert_eq!(tenant_admin_route.status(), actix_web::http::StatusCode::OK);
    let forbidden = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/.well-known/nazoauth-control")
            .insert_header((actix_web::http::header::HOST, "tenant.example"))
            .to_request(),
    )
    .await;
    assert_eq!(forbidden.status(), actix_web::http::StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn legacy_custom_control_tenant_remains_authorized() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use nazo_operator_protocol::{
        CONTROL_DISCOVERY_SCHEMA, DiscoveryRequest, DiscoveryResponse, decode_instance_public_key,
        instance_key_id, verify_discovery_statement,
    };
    let control_tenant_id =
        nazo_identity::TenantId::new(uuid::Uuid::from_u128(42)).expect("non-zero test tenant id");
    let mut state = crate::facade_conformance::infrastructure(false).await;
    Arc::make_mut(&mut state.settings).tenant.context.tenant_id = control_tenant_id;
    let application = crate::test_support::facade::builder(&state, Default::default())
        .unwrap()
        .with_deployment(crate::facade_conformance::deployment(control_tenant_id))
        .build()
        .await
        .unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(application))
            .configure(nazo_http_actix::configure),
    )
    .await;
    let nonce = URL_SAFE_NO_PAD.encode([11; 32]);
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/.well-known/nazoauth-control")
            .set_json(DiscoveryRequest {
                schema: CONTROL_DISCOVERY_SCHEMA,
                nonce: nonce.clone(),
            })
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    let response: DiscoveryResponse = test::read_body_json(response).await;
    let key = decode_instance_public_key(&response.instance_public_key).unwrap();
    let statement = verify_discovery_statement(
        &response.statement,
        &instance_key_id(&key),
        &key,
        &nonce,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    assert_eq!(statement.nonce, nonce);
}
