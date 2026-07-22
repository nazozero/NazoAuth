use crate::domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};

use crate::settings::Settings;

use actix_web::http::header;

use actix_web::http::header::HeaderValue;

use serde_json::json;

use uuid::Uuid;

pub(crate) fn request_mtls_thumbprint(req: &HttpRequest, settings: &Settings) -> Option<String> {
    request_mtls_client_certificate(req, settings)?.thumbprint
}

pub(crate) fn request_mtls_client_certificate(
    req: &HttpRequest,
    settings: &Settings,
) -> Option<MtlsClientCertificate> {
    if !request_from_trusted_proxy_cidrs(req, &settings.endpoint.trusted_proxy_cidrs) {
        return None;
    }
    request_mtls_client_certificate_from_headers(req.headers())
}

fn merge_sorted_unique(target: &mut Vec<String>, incoming: Vec<String>) {
    target.extend(incoming);
    target.sort();
    target.dedup();
}
