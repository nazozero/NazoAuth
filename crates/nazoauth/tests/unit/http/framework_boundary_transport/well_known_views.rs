use std::sync::Arc;

use actix_web::{http::StatusCode, web::Data};
use futures_util::future::{BoxFuture, FutureExt};
use nazo_key_management::KeyManager;
use nazo_persistence::{DatabaseHealthError, DatabaseHealthPort};
use serde_json::Value;

use super::ready_body_bytes;
use crate::http;
use crate::http::well_known::ReadinessDependencies;

#[derive(Clone)]
struct FakeDatabaseHealth {
    ok: bool,
}

impl DatabaseHealthPort for FakeDatabaseHealth {
    fn check(&self) -> BoxFuture<'_, Result<(), DatabaseHealthError>> {
        let ok = self.ok;
        async move { if ok { Ok(()) } else { Err(DatabaseHealthError) } }.boxed()
    }
}

#[derive(Clone)]
struct FakeTransientStateHealth {
    ok: bool,
}

impl nazo_oauth_server::ports::transient_state::TransientStateHealthPort
    for FakeTransientStateHealth
{
    fn check(&self) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<'_, ()> {
        let ok = self.ok;
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err(nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable)
            }
        })
    }
}

fn healthy_keyset() -> KeyManager {
    KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA)
}

#[actix_web::test]
async fn framework_boundary_transport_readiness_contracts_match_expected_boundary() {
    let ready = http::well_known::ready(Data::new(ReadinessDependencies::new(
        Arc::new(FakeDatabaseHealth { ok: true }),
        Arc::new(FakeTransientStateHealth { ok: true }),
        healthy_keyset(),
    )))
    .await;
    assert_eq!(ready.status(), StatusCode::OK);

    let ready = serde_json::from_slice::<Value>(&ready_body_bytes(ready).await)
        .expect("readiness body should deserialize");
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["checks"]["database"]["status"], "up");
    assert_eq!(ready["checks"]["transient_state"]["status"], "up");
    assert_eq!(ready["checks"]["signing_keys"]["status"], "up");
}

#[actix_web::test]
async fn framework_boundary_transport_readiness_fails_closed_when_dependencies_are_unavailable() {
    let response = http::well_known::ready(Data::new(ReadinessDependencies::new(
        Arc::new(FakeDatabaseHealth { ok: false }),
        Arc::new(FakeTransientStateHealth { ok: true }),
        healthy_keyset(),
    )))
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let payload = serde_json::from_slice::<Value>(&ready_body_bytes(response).await)
        .expect("readiness body should parse");
    assert_eq!(payload["status"], "not_ready");
    assert_eq!(payload["checks"]["database"]["status"], "down");
    assert_eq!(payload["checks"]["transient_state"]["status"], "up");
    assert_eq!(payload["checks"]["signing_keys"]["status"], "up");
}

#[actix_web::test]
async fn framework_boundary_transport_well_known_endpoints_keep_contracts() {
    assert_eq!(
        http::well_known::live().await.into_inner(),
        serde_json::json!({"status": "live"})
    );
    assert_eq!(
        http::well_known::startup().await.into_inner(),
        serde_json::json!({"status": "started"})
    );
    assert_eq!(
        http::well_known::captcha_config().await.into_inner(),
        serde_json::json!({
            "turnstile_enabled": false,
            "turnstile_site_key": Value::Null,
            "registration_enabled": true
        })
    );
}

#[test]
fn framework_boundary_transport_views_helpers_maintain_http_projection_semantics() {
    let mut query = std::collections::HashMap::new();
    query.insert("page".to_owned(), "3".to_owned());
    query.insert("page_size".to_owned(), "50".to_owned());
    assert_eq!(http::views::pagination(&query), (3, 50, 100));

    let mut headers = actix_web::http::header::HeaderMap::new();
    let fetch = actix_web::http::header::HeaderName::from_static("sec-fetch-site");
    assert!(!http::views::is_cross_site_fetch(&headers));
    headers.insert(
        fetch.clone(),
        actix_web::http::header::HeaderValue::from_static("same-origin"),
    );
    assert!(!http::views::is_cross_site_fetch(&headers));
    headers.insert(
        fetch,
        actix_web::http::header::HeaderValue::from_static("cross-site"),
    );
    assert!(http::views::is_cross_site_fetch(&headers));
}
