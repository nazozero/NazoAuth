mod admin;
mod base;
mod dynamic_registration;
mod logout;
mod mapping;
mod mutation;
mod query;

pub use base::OAuthClientRepository;
pub use mutation::{deactivate_client_on_connection, insert_client_on_connection};
pub use query::active_public_client_ids_on_connection;

use mapping::map_error;
pub(super) use mapping::{OAuthClientRecord, client_security_policy};

#[cfg(test)]
#[path = "../../../tests/unit/repositories/clients.rs"]
mod tests;
