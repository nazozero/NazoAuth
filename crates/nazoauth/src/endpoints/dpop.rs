use crate::http::Request as HttpRequest;
use nazo_oauth_server::contracts::request_facts::DpopRequestFacts;

pub fn dpop_proof_present(request: &HttpRequest) -> bool {
    crate::http::dpop_proof_present(request.headers())
}

pub fn dpop_request_facts(request: &HttpRequest) -> DpopRequestFacts<'_> {
    DpopRequestFacts {
        method: request.method().clone(),
        path: request.uri().path(),
        authority: crate::http::dpop_request_authority(request),
        proof: crate::http::dpop_proof_header(request.headers()),
        proof_present: dpop_proof_present(request),
    }
}
