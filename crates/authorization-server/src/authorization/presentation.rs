//! Public client display metadata and authorization redirect query construction.

pub use nazo_auth::ClientPresentation;

use super::AuthorizationRequestContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientPresentationError {
    NotFound,
    Unavailable,
}

pub(crate) async fn client_presentation_with_context(
    context: &AuthorizationRequestContext<'_>,
    client_id: &str,
) -> Result<ClientPresentation, ClientPresentationError> {
    context
        .service
        .active_client_presentation(client_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to load client presentation metadata");
            ClientPresentationError::Unavailable
        })?
        .ok_or(ClientPresentationError::NotFound)
}

pub(crate) fn append_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let Ok(mut url) = url::Url::parse(base) else {
        return base.to_owned();
    };
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in pairs {
            if !v.is_empty() {
                qp.append_pair(k, v);
            }
        }
    }
    url.to_string()
}

#[cfg(test)]
#[path = "../../tests/unit/authorization/presentation.rs"]
mod tests;
