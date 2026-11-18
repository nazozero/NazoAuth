// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::auth::federation::oidc::*;
#[path = "../../../../unit/http/auth/federation/oidc.rs"]
pub(crate) mod tests;

use nazo_oauth_server::crypto::pkce_s256;
use serde_json::Value;
