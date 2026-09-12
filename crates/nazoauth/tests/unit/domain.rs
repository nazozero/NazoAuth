//! Native integration tests for application operations.
#[cfg(test)]
#[path = "domain/authorization_decision.rs"]
mod authorization_decision_tests;
#[cfg(test)]
#[path = "domain/local_registration.rs"]
mod local_registration_tests;
#[cfg(test)]
#[path = "../support/domain/passkey_operations.rs"]
pub(crate) mod passkey;

#[cfg(test)]
#[path = "domain/resource_server.rs"]
mod resource_server_tests;

#[cfg(test)]
#[path = "domain/userinfo.rs"]
pub(crate) mod userinfo;

#[cfg(test)]
#[path = "domain/openid4vc_endpoints_openid4vp.rs"]
mod openid4vc_endpoints_openid4vp_tests;
#[cfg(test)]
#[path = "domain/openid4vci_endpoint_operations.rs"]
mod openid4vci_endpoint_operations_tests;

#[cfg(test)]
#[path = "domain/openid4vc_attestation_repository.rs"]
mod openid4vc_attestation_repository_tests;
