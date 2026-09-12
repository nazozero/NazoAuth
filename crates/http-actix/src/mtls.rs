//! Deployment-specific extraction of the peer certificate thumbprint.
use actix_web::HttpRequest;

pub trait MtlsThumbprintExtractor: Send + Sync {
    fn resolve(&self, request: &HttpRequest) -> Option<String>;
}
