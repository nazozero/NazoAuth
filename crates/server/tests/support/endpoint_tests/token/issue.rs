// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::token::issue::*;
#[path = "../../http/token/issue.rs"]
pub(crate) mod test_support;
#[path = "../../../unit/http/token/issue.rs"]
pub(crate) mod tests;

use crate::settings::Settings;
