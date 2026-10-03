use actix_web::{App, http::StatusCode, test, web};

use super::*;

#[actix_web::test]
async fn controller_slot_list_has_one_control_tenant_route_and_no_admin_get_alias() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let context = nazo_identity::TenantContext::default_system();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(context))
            .app_data(web::Data::new(ControlTenantId::new(context.tenant_id)))
            .configure(|cfg| configure(cfg, &settings, false)),
    )
    .await;

    let control = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/controller-registry/slots?deployment_id=deployment-a")
            .to_request(),
    )
    .await;
    assert_ne!(control.status(), StatusCode::NOT_FOUND);
    assert_ne!(control.status(), StatusCode::METHOD_NOT_ALLOWED);

    let old_admin_get = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/admin/controller-registry/slots?deployment_id=deployment-a")
            .to_request(),
    )
    .await;
    assert_eq!(
        old_admin_get.status(),
        StatusCode::NOT_FOUND,
        "the old GET path must not remain as a compatibility alias"
    );
}

#[actix_web::test]
async fn retired_bootstrap_admin_endpoint_stays_unreachable() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let context = nazo_identity::TenantContext::default_system();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(context))
            .app_data(web::Data::new(ControlTenantId::new(context.tenant_id)))
            .configure(|cfg| configure(cfg, &settings, false)),
    )
    .await;

    for method in [test::TestRequest::get, test::TestRequest::post] {
        let response =
            test::call_service(&app, method().uri("/bootstrap-admin").to_request()).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "the retired public bootstrap-admin surface must not come back"
        );
    }
}

struct MemoryPoolMetrics(std::sync::atomic::AtomicU64);

impl nazo_persistence::DatabasePoolMetricsPort for MemoryPoolMetrics {
    fn snapshot(&self) -> nazo_persistence::DatabasePoolMetrics {
        let observation = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        nazo_persistence::DatabasePoolMetrics {
            acquire_count: observation,
            wait_nanos_total: 0,
            wait_nanos_max: 0,
            connections: Some(4),
            idle_connections: Some(4),
            waiting_acquisitions: Some(0),
        }
    }
}

#[actix_web::test]
async fn perf_metrics_reads_one_memory_snapshot_without_an_admin_caller() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let context = nazo_identity::TenantContext::default_system();
    let metrics = std::sync::Arc::new(MemoryPoolMetrics(std::sync::atomic::AtomicU64::new(0)));
    let port: std::sync::Arc<dyn nazo_persistence::DatabasePoolMetricsPort> = metrics.clone();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(context))
            .app_data(web::Data::new(ControlTenantId::new(context.tenant_id)))
            .app_data(web::Data::from(port))
            .configure(|cfg| configure(cfg, &settings, true)),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::get().uri("/__perf/metrics").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["db_pool"]["acquire_count"], 1);
    assert_eq!(body["db_pool"]["connections"], 4);
    assert!(body["audit_queue"]["pending_in_process"].as_u64().is_some());
    assert_eq!(metrics.0.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[actix_web::test]
async fn perf_metrics_disabled_wrong_or_missing_tenant_do_not_read_metrics() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let control = nazo_identity::TenantContext::default_system();
    let wrong = nazo_identity::TenantContext {
        tenant_id: nazo_identity::TenantId::new(uuid::Uuid::now_v7()).unwrap(),
        ..control
    };
    for (enabled, tenant, control_present) in [
        (false, Some(control), true),
        (true, Some(wrong), true),
        (true, None, true),
        (true, Some(control), false),
    ] {
        let metrics = std::sync::Arc::new(MemoryPoolMetrics(std::sync::atomic::AtomicU64::new(0)));
        let port: std::sync::Arc<dyn nazo_persistence::DatabasePoolMetricsPort> = metrics.clone();
        let mut app = App::new().app_data(web::Data::from(port));
        if let Some(tenant) = tenant {
            app = app.app_data(web::Data::new(tenant));
        }
        if control_present {
            app = app.app_data(web::Data::new(ControlTenantId::new(control.tenant_id)));
        }
        let app = test::init_service(app.configure(|cfg| configure(cfg, &settings, enabled))).await;
        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/__perf/metrics").to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(metrics.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

#[actix_web::test]
async fn perf_metrics_parallel_requests_keep_individual_observation_semantics() {
    let settings = Settings::from_config(&crate::config::ConfigSource::default()).unwrap();
    let context = nazo_identity::TenantContext::default_system();
    let metrics = std::sync::Arc::new(MemoryPoolMetrics(std::sync::atomic::AtomicU64::new(0)));
    let port: std::sync::Arc<dyn nazo_persistence::DatabasePoolMetricsPort> = metrics.clone();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(context))
            .app_data(web::Data::new(ControlTenantId::new(context.tenant_id)))
            .app_data(web::Data::from(port))
            .configure(|cfg| configure(cfg, &settings, true)),
    )
    .await;
    let responses = futures_util::future::join_all((0..16).map(|_| {
        test::call_service(
            &app,
            test::TestRequest::get().uri("/__perf/metrics").to_request(),
        )
    }))
    .await;
    let mut observations = std::collections::BTreeSet::new();
    for response in responses {
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(response).await;
        observations.insert(body["db_pool"]["acquire_count"].as_u64().unwrap());
        assert!(body["audit_queue"]["pending_in_process"].as_u64().is_some());
    }
    assert_eq!(observations, (1..=16).collect());
    assert_eq!(metrics.0.load(std::sync::atomic::Ordering::Relaxed), 16);
}
