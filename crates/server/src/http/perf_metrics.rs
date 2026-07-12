use nazo_postgres::db_pool_metrics;

use super::prelude::*;

pub(crate) async fn perf_metrics() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "db_pool": db_pool_metrics()
    }))
}
