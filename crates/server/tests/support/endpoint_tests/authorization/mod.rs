// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::authorization::*;
#[path = "../../../unit/http/authorization/boundary.rs"]
pub(crate) mod boundary_tests;
pub(crate) mod config;
pub(crate) mod consent;
pub(crate) mod par;
pub(crate) mod request;
#[path = "../../http/authorization.rs"]
pub(crate) mod test_support;

pub(crate) use config::authorization_config;
