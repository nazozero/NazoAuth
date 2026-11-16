// Native regression module: reexports the actual neutral implementation.
pub(crate) mod flow;
#[path = "../../../../unit/http/authorization/request.rs"]
pub(crate) mod tests;

pub(crate) use flow::{authorize_get, authorize_post};
