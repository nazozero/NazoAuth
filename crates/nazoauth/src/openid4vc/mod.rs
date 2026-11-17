//! HTTP endpoints for OpenID4VCI issuer and OpenID4VP verifier roles.
//!
//! Domain policy remains in `nazo-openid4vci` and `nazo-openid4vp`.

#![forbid(unsafe_code)]

mod vci;
mod vp;

#[cfg(feature = "conformance")]
pub(crate) use vci::credential_success;

pub use vci::{
    CredentialIssuerEndpoint, create_credential_offer, credential, credential_issuer_metadata,
    credential_nonce, credential_offer, deferred_credential, notification,
};
pub use vp::{
    PresentationEndpoint, create_presentation, presentation_complete, presentation_request,
    presentation_response, presentation_result,
};
