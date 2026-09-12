// Dynamic client registration is kept as one transport-facing module for
// callers and route wiring. Bearer parsing, IP resolution, extraction, and
// response presentation stay here; business operations live in the application.

mod auth;
mod handlers;
mod ip;
mod response;
mod types;

pub use handlers::{
    client_configuration_delete, client_configuration_get, client_configuration_put,
    dynamic_client_registration,
};
pub use ip::{
    ClientIpConfig, ClientIpHeaderMode, ClientIpParseError, IpCidr, client_ip_with_config,
    client_ip_with_context, parse_forwarded_for_value, parse_trusted_proxy_cidrs,
    request_from_trusted_proxy_cidrs,
};
pub use nazo_auth::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, DynamicRegistrationFuture,
};
pub use types::DynamicRegistrationEndpoint;

#[cfg(test)]
use auth::{bearer_token, parse_bearer};

#[cfg(test)]
#[path = "../tests/unit/dynamic_client_registration.rs"]
mod tests;
