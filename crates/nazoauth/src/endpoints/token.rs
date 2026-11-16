//! Token transport boundaries.
use crate::http::Request as HttpRequest;
pub mod ciba;
pub mod device;
pub mod device_config;
pub mod dispatch;

use nazo_oauth_server::token::client_auth::ClientAuthRequestFacts;

pub struct ServerTokenManagementRequestFactsExtractor {
    pub client_ip: crate::http::ClientIpConfig,
}

impl ServerTokenManagementRequestFactsExtractor {
    pub fn new(client_ip: crate::http::ClientIpConfig) -> Self {
        Self { client_ip }
    }
}

impl crate::http::TokenManagementRequestFactsExtractor
    for ServerTokenManagementRequestFactsExtractor
{
    fn extract(
        &self,
        request: &HttpRequest,
    ) -> nazo_oauth_server::contracts::token_management::TokenManagementRequestFacts {
        nazo_oauth_server::contracts::token_management::TokenManagementRequestFacts {
            source_ip: crate::http::client_ip_with_config(request, &self.client_ip),
            endpoint_path: request.uri().path().to_owned(),
            client_certificate: None,
        }
    }

    fn extract_client_certificate(
        &self,
        request: &HttpRequest,
    ) -> Option<nazo_oauth_server::contracts::token_client_auth::ClientCertificateFacts> {
        crate::endpoints::mtls::request_mtls_client_certificate(request)
    }
}

pub fn client_auth_request_facts(request: &HttpRequest) -> ClientAuthRequestFacts<'_> {
    crate::endpoints::mtls::with_request_mtls_client_certificate(request, |certificate| {
        ClientAuthRequestFacts::borrowed(request.uri().path(), certificate)
    })
}

pub mod issue;

#[cfg(test)]
#[path = "../../tests/unit/endpoints/token_forms.rs"]
mod forms_tests;
