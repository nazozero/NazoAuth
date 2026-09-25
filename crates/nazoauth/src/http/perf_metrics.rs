use actix_web::{HttpResponse, web::Data};
use nazo_persistence::DatabasePoolMetricsPort;
use serde_json::json;

pub(crate) async fn perf_metrics(database: Data<dyn DatabasePoolMetricsPort>) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "db_pool": database.snapshot(),
        "audit_queue": crate::adapters::audit::audit_queue_metrics()
    }))
}
