use crate::settings::Settings;

use chrono::Utc;

use uuid::Uuid;

pub(crate) fn oidc_subject(
    pairwise_subject_secret: &[u8],
    issuer: &str,
    sector_identifier_host: &str,
    user_id: Uuid,
) -> String {
    debug_assert!(pairwise_subject_secret.len() >= 32);
    nazo_auth::pairwise_subject(
        pairwise_subject_secret,
        issuer,
        sector_identifier_host,
        user_id,
    )
}

pub(crate) fn compute_subject_for_client(
    settings: &Settings,
    user_id: Uuid,
    client_subject_type: &str,
    sector_identifier_host: Option<&str>,
    redirect_uri: &str,
) -> anyhow::Result<String> {
    nazo_auth::oidc_subject_for_client(
        &settings.endpoint.issuer,
        settings.protocol.pairwise_subject_secret.as_deref(),
        user_id,
        client_subject_type,
        sector_identifier_host,
        redirect_uri,
    )
    .map_err(Into::into)
}
