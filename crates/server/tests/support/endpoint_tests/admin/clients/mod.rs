// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::admin::clients::*;
#[path = "../../../../unit/http/admin/clients/boundary.rs"]
pub(crate) mod boundary_tests;
pub(crate) mod create;
pub(crate) mod detail;
pub(crate) mod list;
#[path = "../../../http/admin/clients.rs"]
pub(crate) mod test_support;
pub(crate) mod update;

pub(crate) use nazo_key_management::ClientRegistrationCrypto as ServerAdminClientCrypto;
