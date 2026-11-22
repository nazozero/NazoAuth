// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::auth::federation::oidc::*;
#[path = "../../../../unit/http/auth/federation/oidc.rs"]
pub(crate) mod tests;

use serde_json::Value;
