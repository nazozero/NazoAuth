//! Token issuance semantics and persisted response recovery.
use crate::{
    contracts::{
        oauth_error::OAuthEndpointError, request_facts::DpopErrorContext,
        token_endpoint::TokenEndpointSuccess,
    },
    crypto::{blake3_hex, random_urlsafe_token},
    domain::{
        client_jwe::{JwePayloadKind, client_jwe_key, encrypt_compact_jwe},
        oauth::{RefreshTokenPolicy, TokenIssue},
        oidc_claims::oidc_id_token_user_claims,
        rows::ClientRow,
    },
};
use http::StatusCode;
use nazo_auth::{
    DpopNoncePolicy, TokenIssuanceRecord, issue_authorization_server_dpop_nonce,
    normalize_authorization_details,
};
use nazo_key_management::{signing_algorithm_from_name, signing_algorithm_name};
use serde_json::{Value, json};
use uuid::Uuid;
// 统一 access_token、refresh_token 和 id_token 的响应形状。

mod authorization_code_state;
#[path = "issue_grant.rs"]
mod issue_grant;
mod refresh_persistence;

use crate::services::ServerTokenService;
use crate::token::native_sso::persist_native_sso_device_secret;

#[derive(Clone)]
pub struct TokenIssuanceConfig {
    pub issuer: Box<str>,
    pub mtls_endpoint_base_url: Box<str>,
    pub dpop_nonce_policy: DpopNoncePolicy,
    pub default_audience: Box<str>,
    pub openid4vci_enabled: bool,
    pub openid4vci_credential_scopes: Box<[String]>,
    pub pairwise_subject_secret: Option<Box<str>>,
    pub client_secret_pepper: Box<str>,
    pub rate_limit_window_seconds: u64,
    pub token_rate_limit_max_requests: u64,
    pub auth_code_ttl_seconds: u64,
    pub access_token_ttl_seconds: i64,
    pub id_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
}

impl TokenIssuanceConfig {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn mtls_endpoint_base_url(&self) -> &str {
        &self.mtls_endpoint_base_url
    }

    pub fn dpop_nonce_policy(&self) -> DpopNoncePolicy {
        self.dpop_nonce_policy
    }

    pub fn default_audience(&self) -> &str {
        &self.default_audience
    }

    pub fn openid4vci_audience(
        &self,
        scopes: &[String],
        authorization_details: &Value,
    ) -> Option<&str> {
        let requested_by_scope = scopes.iter().any(|scope| {
            self.openid4vci_credential_scopes
                .iter()
                .any(|configured| configured == scope)
        });
        let requested_by_authorization_details = authorization_details
            .as_array()
            .into_iter()
            .flatten()
            .any(|detail| detail.get("type").and_then(Value::as_str) == Some("openid_credential"));
        (self.openid4vci_enabled && (requested_by_scope || requested_by_authorization_details))
            .then_some(self.issuer())
    }

    pub fn pairwise_subject_secret(&self) -> Option<&str> {
        self.pairwise_subject_secret.as_deref()
    }

    pub fn auth_code_ttl_seconds(&self) -> u64 {
        self.auth_code_ttl_seconds.max(1)
    }

    pub fn client_secret_pepper(&self) -> &str {
        &self.client_secret_pepper
    }

    pub fn rate_limit_window_seconds(&self) -> u64 {
        self.rate_limit_window_seconds
    }

    pub fn token_rate_limit_max_requests(&self) -> u64 {
        self.token_rate_limit_max_requests
    }
}

pub struct TokenIssuanceContext<'a> {
    pub config: &'a TokenIssuanceConfig,
    pub modules: &'a nazo_runtime_modules::ActiveModuleSnapshot,
    pub authorization: &'a crate::services::ServerAuthorizationService,
    pub security_audit: &'a dyn crate::ports::audit::SecurityAudit,
    pub remote_client_documents:
        &'a dyn crate::contracts::dynamic_client_registration::RemoteJwksResolverPort,
}

impl TokenIssuanceContext<'_> {
    pub fn accepts(&self, module: nazo_runtime_modules::ModuleId) -> bool {
        nazo_auth::module_admissible(
            self.modules,
            module,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    pub fn permits(&self, module: nazo_runtime_modules::ModuleId) -> bool {
        nazo_auth::module_admissible(
            self.modules,
            module,
            nazo_auth::CapabilityAdmission::ExistingTransaction,
        )
    }
}

use authorization_code_state::{
    consumed_authorization_code_ttl_seconds, mark_failed_authorization_code_if_needed,
};
pub use authorization_code_state::{
    mark_failed_authorization_code, revoke_issued_authorization_code_tokens,
};
pub use refresh_persistence::should_issue_refresh_token;
use refresh_persistence::{
    PendingRefreshToken, prepare_refresh_token, refresh_authentication_context,
};

fn client_session_sid_enabled(frontchannel_logout: bool, client: &ClientRow) -> bool {
    (frontchannel_logout
        && client.frontchannel_logout_uri.is_some()
        && client.frontchannel_logout_session_required)
        || (client.backchannel_logout_uri.is_some() && client.backchannel_logout_session_required)
}

fn id_token_session_sid<'a>(
    client: &ClientRow,
    issue: &'a TokenIssue,
    frontchannel_logout: bool,
) -> Option<&'a str> {
    if let Some(contract) = issue.refresh_id_token_sid.as_ref() {
        return contract.as_deref();
    }
    if let Some(native_sso) = issue.native_sso.as_ref() {
        return Some(native_sso.sid.as_str());
    }
    if client_session_sid_enabled(frontchannel_logout, client) {
        return issue.oidc_sid.as_deref();
    }
    let requested = issue.id_token_claims.iter().any(|claim| claim == "sid")
        || issue
            .id_token_claim_requests
            .iter()
            .any(|request| request.name == "sid");
    requested.then_some(issue.oidc_sid.as_deref()).flatten()
}

fn persisted_id_token_sid<'a>(
    issue: &'a TokenIssue,
    issued_id_token_sid: Option<&'a str>,
) -> Option<&'a str> {
    issued_id_token_sid.or_else(|| {
        issue
            .refresh_id_token_sid
            .as_ref()
            .and_then(|contract| contract.as_deref())
    })
}

fn claim_request_value_matches(request: &nazo_auth::OidcClaimRequest, actual: &Value) -> bool {
    match (&request.value, request.values.as_slice()) {
        (Some(expected), _) => expected == actual,
        (None, []) => true,
        (None, values) => values.iter().any(|expected| expected == actual),
    }
}

fn refreshed_id_token_essential_claims_satisfied(
    issue: &TokenIssue,
    client: &ClientRow,
    frontchannel_logout_enabled: bool,
    extra_claims: Option<&Value>,
) -> bool {
    issue
        .id_token_claim_requests
        .iter()
        .filter(|request| request.essential)
        .all(|request| {
            let actual = match request.name.as_str() {
                "auth_time" => issue.auth_time.map(|value| json!(value)),
                "amr" if !issue.amr.is_empty() => Some(json!(&issue.amr)),
                "acr" => issue.acr.as_ref().map(|value| json!(value)),
                "sid" => id_token_session_sid(client, issue, frontchannel_logout_enabled)
                    .map(|value| json!(value)),
                _ => extra_claims
                    .and_then(Value::as_object)
                    .and_then(|claims| claims.get(&request.name))
                    .cloned(),
            };
            actual.is_some_and(|actual| claim_request_value_matches(request, &actual))
        })
}

fn id_token_signing_alg_for_client(client: &ClientRow) -> jsonwebtoken::Algorithm {
    client
        .id_token_signed_response_alg
        .as_deref()
        .and_then(signing_algorithm_from_name)
        .unwrap_or_else(|| {
            if client.require_dpop_bound_tokens
                || client.require_mtls_bound_tokens
                || client.require_par_request_object
            {
                jsonwebtoken::Algorithm::PS256
            } else {
                jsonwebtoken::Algorithm::RS256
            }
        })
}

async fn persist_access_token_subject_mapping(
    service: &ServerTokenService,
    access_token_ttl_seconds: i64,
    jti: &str,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
    subject: &str,
) -> anyhow::Result<()> {
    let Some(user_id) = user_id else {
        return Ok(());
    };
    if subject == user_id.to_string() {
        return Ok(());
    }
    service
        .store_access_token_subject(
            tenant_id,
            jti,
            user_id,
            access_token_ttl_seconds.max(1) as u64,
        )
        .await?;
    Ok(())
}

fn issuance_request_digest(client: &ClientRow, issue: &TokenIssue, grant_key: &str) -> String {
    // This digest is deliberately built from the normalized issue, not from
    // raw form fields.  A retry with a different client, subject, scope,
    // resource, sender binding or OIDC contract therefore cannot reuse a
    // response belonging to another logical grant.
    let refresh_token_policy = match issue.refresh_token_policy {
        RefreshTokenPolicy::IssueNew => json!({ "kind": "issue_new" }),
        RefreshTokenPolicy::Rotate {
            family_id,
            rotated_from_id,
        } => json!({
            "kind": "rotate",
            "family_id": family_id,
            "rotated_from_id": rotated_from_id,
        }),
        RefreshTokenPolicy::RotateLostResponse {
            family_id,
            original_id,
            successor_id,
            retry_started_at,
        } => json!({
            "kind": "rotate_lost_response",
            "family_id": family_id,
            "original_id": original_id,
            "successor_id": successor_id,
            "retry_started_at": retry_started_at,
        }),
        RefreshTokenPolicy::PreserveExisting => json!({ "kind": "preserve_existing" }),
    };
    // Native SSO device secrets are server-generated response material. A retry
    // reconstructs the normalized issue with fresh secret bytes before looking
    // up the durable issuance, so binding those bytes would turn a legitimate
    // idempotent retry into a digest conflict. The session identifier is the
    // stable flow identity and still separates Native SSO from ordinary grants.
    let native_sso_sid = issue.native_sso.as_ref().map(|binding| &binding.sid);
    let material = json!({
        "client_id": client.id,
        "tenant_id": client.tenant_id,
        "grant_key": grant_key,
        "subject": issue.subject,
        "user_id": issue.user_id,
        "scopes": issue.scopes,
        "audiences": issue.audiences,
        "authorization_details": issue.authorization_details,
        "nonce": issue.nonce,
        "auth_time": issue.auth_time,
        "amr": issue.amr,
        "oidc_sid": issue.oidc_sid,
        "acr": issue.acr,
        "userinfo_claims": issue.userinfo_claims,
        "userinfo_claim_requests": issue.userinfo_claim_requests,
        "id_token_claims": issue.id_token_claims,
        "id_token_claim_requests": issue.id_token_claim_requests,
        "refresh_id_token_sid": issue.refresh_id_token_sid,
        "include_refresh": issue.include_refresh,
        "refresh_token_policy": refresh_token_policy,
        "dpop_jkt": issue.dpop_jkt,
        "refresh_token_dpop_jkt": issue.refresh_token_dpop_jkt,
        "mtls_x5t_s256": issue.mtls_x5t_s256,
        "refresh_token_mtls_x5t_s256": issue.refresh_token_mtls_x5t_s256,
        "refresh_token_client_attestation_jkt": issue.refresh_token_client_attestation_jkt,
        "refresh_token_scopes": issue.refresh_token_scopes,
        "authorization_code_hash": issue.authorization_code_hash,
        "actor": issue.actor,
        "issued_token_type": issue.issued_token_type,
        "native_sso_sid": native_sso_sid,
    });
    blake3_hex(
        &serde_json::to_string(&material)
            .expect("normalized token issue digest payload must serialize"),
    )
}

fn response_from_token_issuance(record: &TokenIssuanceRecord) -> Option<TokenEndpointSuccess> {
    let body = record.response_body.as_ref()?.clone();
    Some(TokenEndpointSuccess::Replayed { body })
}

pub use issue_grant::issue_token_response;
#[cfg(test)]
#[path = "../../tests/unit/token/issue.rs"]
pub(crate) mod tests;
