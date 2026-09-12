use actix_web::HttpRequest;
use nazo_oauth_server::contracts::request_facts::DpopRequestFacts;

pub(crate) fn dpop_proof_present(request: &HttpRequest) -> bool {
    nazo_http_actix::dpop_proof_present(request.headers())
}

pub(crate) fn dpop_request_facts(request: &HttpRequest) -> DpopRequestFacts<'_> {
    DpopRequestFacts {
        method: http::Method::from_bytes(request.method().as_str().as_bytes())
            .expect("HTTP method is valid"),
        path: request.uri().path(),
        proof: nazo_http_actix::dpop_proof_header(request.headers()),
        proof_present: dpop_proof_present(request),
    }
}
