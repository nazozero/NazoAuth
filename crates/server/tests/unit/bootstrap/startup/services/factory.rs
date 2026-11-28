use super::*;
use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use futures_util::{StreamExt as _, stream};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn cancelling_listener_ownership_stops_tls_reloads() {
    let (started, running) = tokio::sync::oneshot::channel();
    let (completion, stopped) = tokio::sync::oneshot::channel::<()>();
    let owner = TlsReloader(tokio::spawn(async move {
        let _completion = completion;
        let _ = started.send(());
        std::future::pending::<()>().await;
    }));
    running.await.unwrap();
    drop(owner);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stopped)
            .await
            .expect("TLS reload task must stop with its listener")
            .is_err()
    );
}

#[actix_web::test]
async fn request_metrics_keep_host_patterns_and_canonical_product_routes() {
    let state = crate::facade_conformance::infrastructure(false).await;
    let application = crate::test_support::facade::builder(&state, Default::default())
        .unwrap()
        .build()
        .await
        .unwrap();
    let log = std::env::temp_dir().join(format!("http-metrics-{}.log", uuid::Uuid::now_v7()));
    let writer = std::fs::File::create_new(&log).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.try_clone().unwrap())
        .finish();
    let subscriber = tracing::subscriber::set_default(subscriber);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(application))
            .wrap(from_fn(observe_request))
            .service(
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
            "unmatched",
            StatusCode::NOT_FOUND,
        ),
        (
            "/.well-known/oauth-protected-resource/fapi/resource",
            "/.well-known/oauth-protected-resource",
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
        .with_deployment(crate::facade_conformance::deployment(
            control_tenant_id,
            &state.diesel_db,
        ))
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
        jiff::Timestamp::now().as_second(),
    )
    .unwrap();
    assert_eq!(statement.nonce, nonce);
}
