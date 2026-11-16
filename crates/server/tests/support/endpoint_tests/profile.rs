// Native regression module: reexports the actual neutral implementation.
pub(crate) mod access_requests;
pub(crate) mod avatar;
pub(crate) mod delivery;
pub(crate) mod federation_links;
#[path = "../../unit/http/profile.rs"]
pub(crate) mod tests;
