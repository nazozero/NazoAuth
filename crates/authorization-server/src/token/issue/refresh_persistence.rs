use super::*;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::client_policy::client_supports_grant;
pub(super) struct PendingRefreshToken {
    pub(super) raw: String,
    /// Identity of this generation; the parent's spent proof names it as the
    /// direct successor.
    pub(super) member_id: Uuid,
    pub(super) family: Uuid,
    pub(super) rotated_from: Option<Uuid>,
    /// `(original member id, original token digest, retry start)` — the digest
    /// is what a persisted retry must prove against the spent-proof edge.
    pub(super) lost_response_retry: Option<(Uuid, [u8; 32], DateTime<Utc>)>,
    pub(super) issued_at: DateTime<Utc>,
    pub(super) expires_at: DateTime<Utc>,
}

pub(super) fn refresh_authentication_context(
    issue: &TokenIssue,
    issuer: &str,
    audience: &str,
    id_token_sid: Option<&str>,
) -> Option<nazo_auth::RefreshTokenAuthenticationContext> {
    // Every refresh family carries one immutable authentication contract. An
    // absent original auth_time or malformed AMR must never be synthesized.
    let context = nazo_auth::RefreshTokenAuthenticationContext {
        version: nazo_auth::RefreshTokenAuthenticationContext::CURRENT_VERSION,
        issuer: issuer.to_owned(),
        audience: audience.to_owned(),
        auth_time: issue.auth_time?,
        amr: issue.amr.clone(),
        oidc_sid: issue.oidc_sid.clone(),
        id_token_sid: id_token_sid.map(ToOwned::to_owned),
        acr: issue.acr.clone(),
        nonce: issue.nonce.clone(),
        userinfo_claims: issue.userinfo_claims.clone(),
        userinfo_claim_requests: issue.userinfo_claim_requests.clone(),
        id_token_claims: issue.id_token_claims.clone(),
        id_token_claim_requests: issue.id_token_claim_requests.clone(),
    };
    context.is_well_formed().then_some(context)
}

/// Bind the values actually signed to the original source snapshot. Keeping
/// an unchanged contract in the commit is insufficient if the signing input
/// could independently change its subject, claims, or granted privileges.
pub(super) fn refresh_issue_matches_source(
    issue: &TokenIssue,
    client: &ClientRow,
    issuer: &str,
) -> bool {
    let source = match (&issue.refresh_token_policy, &issue.refresh_authority) {
        (RefreshTokenPolicy::NoRefresh, None) => return !issue.include_refresh,
        (RefreshTokenPolicy::IssueNew, None) => return true,
        (RefreshTokenPolicy::PreserveExisting, Some(source)) => source,
        (
            RefreshTokenPolicy::Rotate {
                family_id,
                rotated_from_id,
            },
            Some(source),
        ) if *family_id == source.family_id && *rotated_from_id == source.member_id => source,
        (
            RefreshTokenPolicy::RotateLostResponse {
                family_id,
                successor_id,
                ..
            },
            Some(source),
        ) if *family_id == source.family_id && *successor_id == source.member_id => source,
        _ => return false,
    };
    let context = &source.contract.authentication_context;
    source.tenant_id == client.tenant_id
        && source.client_id == client.id
        && source.user_id == issue.user_id
        && source.contract.subject == issue.subject
        && source.contract.authorization_details == issue.authorization_details
        && context.is_well_formed()
        && context.issuer == issuer
        && context.audience == client.client_id
        && issue.auth_time == Some(context.auth_time)
        && context.amr == issue.amr
        && context.oidc_sid == issue.oidc_sid
        && context.id_token_sid.is_none()
        && context.acr == issue.acr
        && context.nonce.is_none()
        && context.userinfo_claims == issue.userinfo_claims
        && context.userinfo_claim_requests == issue.userinfo_claim_requests
        && context.id_token_claims == issue.id_token_claims
        && context.id_token_claim_requests == issue.id_token_claim_requests
        && nazo_auth::is_subset(&issue.scopes, &source.contract.scopes)
        && !issue.audiences.is_empty()
        && nazo_auth::is_subset(&issue.audiences, &source.current_audiences)
        && issue.refresh_id_token_sid.as_ref() == Some(&source.id_token_sid)
        && issue.actor.is_none()
        && source
            .dpop_jkt
            .as_ref()
            .is_none_or(|binding| issue.dpop_jkt.as_ref() == Some(binding))
        && source
            .mtls_x5t_s256
            .as_ref()
            .is_none_or(|binding| issue.mtls_x5t_s256.as_ref() == Some(binding))
        // Actual AT constraints may be added to an unbound source, but the
        // retained or replacement RT must keep the source's exact bindings.
        && issue.refresh_token_dpop_jkt == source.dpop_jkt
        && issue.refresh_token_mtls_x5t_s256 == source.mtls_x5t_s256
        && issue.refresh_token_client_attestation_jkt == source.client_attestation_jkt
        && issue.refresh_grant_audiences.is_none()
}

pub fn should_issue_refresh_token(
    client: &ClientRow,
    scopes: &[String],
    openid4vci_credential_authorization: bool,
) -> bool {
    client_supports_grant(client, "refresh_token")
        && (scopes.iter().any(|scope| scope == "offline_access")
            || openid4vci_credential_authorization)
}

pub(super) fn prepare_refresh_token(
    client: &ClientRow,
    issue: &TokenIssue,
    refresh: &PendingRefreshToken,
    id_token_sid: Option<String>,
) -> nazo_auth::NewRefreshToken {
    nazo_auth::NewRefreshToken {
        raw_token: refresh.raw.clone(),
        member_id: refresh.member_id,
        tenant_id: client.tenant_id,
        family_id: refresh.family,
        rotated_from_id: refresh.rotated_from,
        lost_response_retry: refresh.lost_response_retry.map(
            |(original_id, original_blake3, retry_started_at)| nazo_auth::LostResponseRetry {
                original_id,
                original_blake3,
                retry_started_at,
            },
        ),
        client_id: client.id,
        user_id: issue.user_id,
        audiences: if issue.refresh_authority.is_some() {
            issue.audiences.clone()
        } else {
            issue
                .refresh_grant_audiences
                .as_ref()
                .unwrap_or(&issue.audiences)
                .clone()
        },
        issued_at: refresh.issued_at,
        expires_at: refresh.expires_at,
        dpop_jkt: issue.refresh_token_dpop_jkt.clone(),
        mtls_x5t_s256: issue.refresh_token_mtls_x5t_s256.clone(),
        client_attestation_jkt: issue.refresh_token_client_attestation_jkt.clone(),
        id_token_sid,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/token/issue/refresh_persistence.rs"]
mod tests;
