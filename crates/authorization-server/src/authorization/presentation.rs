//! Public client display metadata and authorization redirect query construction.

use nazo_auth::ClientPresentationMetadata;
use serde::Serialize;

use super::AuthorizationRequestContext;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientPresentation {
    pub client_name: String,
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientPresentationError {
    NotFound,
    Unavailable,
}

pub(crate) async fn client_presentation_with_context(
    context: &AuthorizationRequestContext<'_>,
    client_id: &str,
) -> Result<ClientPresentation, ClientPresentationError> {
    let client = context
        .service
        .client_by_id(client_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to load client presentation metadata");
            ClientPresentationError::Unavailable
        })?;
    let client = client.ok_or(ClientPresentationError::NotFound)?;
    active_client_presentation(client.is_active, &client.client_name, &client.presentation)
}

fn active_client_presentation(
    is_active: bool,
    client_name: &str,
    presentation: &ClientPresentationMetadata,
) -> Result<ClientPresentation, ClientPresentationError> {
    if !is_active {
        return Err(ClientPresentationError::NotFound);
    }
    Ok(ClientPresentation {
        client_name: client_name.to_owned(),
        logo_uri: presentation.logo_uri.clone(),
        policy_uri: presentation.policy_uri.clone(),
        tos_uri: presentation.tos_uri.clone(),
    })
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
