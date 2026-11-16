//! Deployment-specific extraction of the peer certificate thumbprint.
use crate::http::Request;

pub trait MtlsThumbprintExtractor: Send + Sync {
    fn resolve(&self, request: &Request) -> Option<String>;
}
