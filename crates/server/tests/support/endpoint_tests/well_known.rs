// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::well_known::*;
#[path = "../../unit/http/well_known.rs"]
pub(crate) mod tests;

use actix_web::{HttpResponse, web::Data};
use serde_json::{Value, json};
use std::sync::Arc;

pub(crate) async fn ready(dependencies: Data<ReadinessDependencies>) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::well_known::ready(dependencies.get_ref()).await,
    )
}

pub(crate) fn readiness_response(
    database_up: bool,
    transient_state_up: bool,
    signing_keys_up: bool,
) -> HttpResponse {
    nazo_http_actix::forward_response(nazoauth::test_support::well_known::readiness_response(
        database_up,
        transient_state_up,
        signing_keys_up,
    ))
}
