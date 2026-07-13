use super::*;
use std::sync::Arc;

use actix_web::middleware::from_fn;
use actix_web::{App, test as actix_test};

use crate::config::ConfigSource;
use crate::settings::Settings;

fn disabled_route_state() -> Data<AppState> {
    Data::new(AppState {
        diesel_db: nazo_postgres::create_pool(
            "postgres://runtime_routes_invalid:runtime_routes_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("test pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("test Valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    })
}

#[actix_web::test]
async fn accepted_change_is_explicitly_pending_and_not_cacheable() {
    let response = accepted_response(json!({
        "module_id": "ciba",
        "desired_state": "disabled",
        "revision": 9,
        "actual_state": "enabled",
        "status_url": "/admin/runtime-modules",
    }));
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("accepted response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("accepted response must be JSON");
    assert_eq!(body["actual_state"], "enabled");
    assert_eq!(body["revision"], 9);
    assert_eq!(body["status_url"], "/admin/runtime-modules");
}

#[test]
fn public_module_identifiers_round_trip_exhaustively() {
    for module_id in ModuleId::ALL {
        assert_eq!(parse_module_id(module_id_name(module_id)), Some(module_id));
        assert!(!module_description(module_id).is_empty());
    }
    assert_eq!(parse_module_id("unknown"), None);
}

#[test]
fn event_contract_matches_frontend_wire_names() {
    let event = nazo_runtime_modules::ModuleEventRecord {
        event_id: "01900000-0000-7000-8000-000000000001".to_owned(),
        module_id: ModuleId::Ciba,
        event_type: ModuleEventType::TransitionCompleted,
        revision: ModuleRevision::new(7),
        instance_id: Some("instance-1".to_owned()),
        actor_id: None,
        reason: Some("approved change".to_owned()),
        before: Some(ModuleEventState::Actual(ModuleState::Starting)),
        after: Some(ModuleEventState::Actual(ModuleState::Enabled)),
        outcome_code: None,
        occurred_at: SystemTime::UNIX_EPOCH,
    };
    let value = runtime_event_json(&event);
    assert_eq!(value["module_id"], "ciba");
    assert_eq!(value["event_type"], "transition_completed");
    assert_eq!(value["before_state"], "starting");
    assert_eq!(value["after_state"], "enabled");
    assert_eq!(value["revision"], 7);
    assert!(value.get("created_at").is_some());
}

#[test]
fn reason_and_event_page_bounds_are_explicit() {
    assert_eq!(MAX_REASON_CHARS, 500);
    assert_eq!(
        EventPageQuery {
            page: None,
            page_size: None
        }
        .page,
        None
    );
    let valid = RuntimeModulePatch {
        desired_state: DesiredMode::Enabled,
        expected_revision: 1,
        reason: "  approved for incident response  ".to_owned(),
        cascade: false,
    };
    assert_eq!(
        validated_reason(&valid).unwrap(),
        "approved for incident response"
    );
    assert!(
        validated_reason(&RuntimeModulePatch {
            reason: " ".to_owned(),
            ..valid
        })
        .is_err()
    );
}

#[test]
fn recent_mfa_requires_mfa_amr_and_a_bounded_authentication_time() {
    let now = 10_000;
    assert!(recent_mfa_values(
        &["pwd".to_owned(), "mfa".to_owned()],
        now - 300,
        now
    ));
    assert!(!recent_mfa_values(&["pwd".to_owned()], now, now));
    assert!(!recent_mfa_values(&["mfa".to_owned()], now - 301, now));
    assert!(!recent_mfa_values(&["mfa".to_owned()], now + 31, now));
}

#[test]
fn dynamic_registration_routes_are_static_and_handlers_own_disabled_behavior() {
    let routes = include_str!("../../../../../../src/bootstrap/routes.rs");
    assert!(routes.contains("cfg.route(\"/register\""));
    assert!(!routes.contains("if settings.enable_dynamic_client_registration"));
    let handler = include_str!("../../../../../../src/http/dynamic_client_registration.rs");
    assert!(handler.contains(
        "if !state.accepts_module(nazo_runtime_modules::ModuleId::DynamicClientRegistration)"
    ));
    assert!(handler.contains("return empty_response(StatusCode::NOT_FOUND)"));
}

#[actix_web::test]
async fn disabled_dynamic_registration_static_route_contract_is_stable() {
    let state = disabled_route_state();
    assert!(!state.settings.enable_dynamic_client_registration);
    let settings = state.settings.clone();
    let app = actix_test::init_service(
        App::new()
            .wrap(from_fn(nazo_http_actix::security_headers))
            .app_data(state)
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    for request in [
        actix_test::TestRequest::post()
            .uri("/register")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload("{}")
            .to_request(),
        actix_test::TestRequest::get().uri("/register").to_request(),
        actix_test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/register")
            .to_request(),
    ] {
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
        assert!(actix_test::read_body(response).await.is_empty());
    }
}
