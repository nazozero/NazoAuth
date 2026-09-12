//! Token transport boundaries.
pub(crate) mod ciba;
pub(crate) mod device;
pub(crate) mod device_config;
pub(crate) mod dispatch;
pub(crate) mod issue;
use actix_web::HttpRequest;
#[cfg(test)]
use nazo_http_actix::parse_token_form;
#[cfg(test)]
use nazo_oauth_server::contracts::token_forms::{TokenForm, TokenFormError};
use nazo_oauth_server::token::client_auth::ClientAuthRequestFacts;
#[cfg(test)]
#[path = "../../tests/unit/http/token/forms.rs"]
mod forms_tests;
pub(crate) struct ServerTokenManagementRequestFactsExtractor {
    client_ip: nazo_http_actix::ClientIpConfig,
}

impl ServerTokenManagementRequestFactsExtractor {
    pub(crate) fn new(client_ip: nazo_http_actix::ClientIpConfig) -> Self {
        Self { client_ip }
    }
}

impl nazo_http_actix::TokenManagementRequestFactsExtractor
    for ServerTokenManagementRequestFactsExtractor
{
    fn extract(
        &self,
        request: &HttpRequest,
    ) -> nazo_oauth_server::contracts::token_management::TokenManagementRequestFacts {
        nazo_oauth_server::contracts::token_management::TokenManagementRequestFacts {
            source_ip: nazo_http_actix::client_ip_with_config(request, &self.client_ip),
            endpoint_path: request.path().to_owned(),
            client_certificate: None,
        }
    }

    fn extract_client_certificate(
        &self,
        request: &HttpRequest,
    ) -> Option<nazo_oauth_server::contracts::token_client_auth::ClientCertificateFacts> {
        crate::http::mtls::request_mtls_client_certificate(
            request,
            self.client_ip.trusted_proxy_cidrs(),
        )
    }
}

pub(crate) fn client_auth_request_facts(
    request: &HttpRequest,
    trusted_proxy_cidrs: &[nazo_http_actix::IpCidr],
) -> ClientAuthRequestFacts {
    ClientAuthRequestFacts::new(
        request.path(),
        crate::http::mtls::request_mtls_client_certificate(request, trusted_proxy_cidrs),
    )
}

#[cfg(test)]
#[path = "../../tests/unit/http/token/lifecycle_boundary.rs"]
mod lifecycle_boundary_tests;

#[cfg(test)]
#[path = "../../tests/unit/http/token/client_auth.rs"]
mod client_auth_tests;

#[cfg(test)]
#[path = "../../tests/unit/http/token/authorization_code.rs"]
mod authorization_code_tests;

#[cfg(test)]
#[path = "../../tests/unit/http/token/client_credentials.rs"]
mod client_credentials_tests;

#[cfg(test)]
#[path = "../../tests/unit/http/token/refresh.rs"]
mod refresh_tests;

#[cfg(test)]
#[path = "../../tests/unit/http/token/jwt_bearer.rs"]
mod jwt_bearer_tests;

#[cfg(test)]
#[path = "../../tests/unit/http/token/token_exchange.rs"]
mod token_exchange_tests;

#[cfg(test)]
#[path = "../../tests/unit/http/token/native_sso.rs"]
mod native_sso_tests;
