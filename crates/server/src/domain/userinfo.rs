use actix_web::HttpRequest;
use nazo_key_management::KeyManager;
use serde_json::Value;

use crate::settings::{DpopNoncePolicy, Settings};
use crate::support::{
    DpopError, IpCidr, request_mtls_thumbprint_from_trusted_proxy, token_audience_contains,
    validate_dpop_proof_with_store,
};

#[derive(Clone)]
pub(crate) struct UserinfoConfig {
    issuer: Box<str>,
    default_audience: Box<str>,
    mtls_endpoint_base_url: Box<str>,
    dpop_nonce_policy: DpopNoncePolicy,
    trusted_proxy_cidrs: Box<[IpCidr]>,
}

impl From<&Settings> for UserinfoConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            issuer: settings.endpoint.issuer.as_str().into(),
            default_audience: settings.protocol.default_audience.as_str().into(),
            mtls_endpoint_base_url: settings.endpoint.mtls_endpoint_base_url.as_str().into(),
            dpop_nonce_policy: settings.protocol.dpop_nonce_policy,
            trusted_proxy_cidrs: settings.endpoint.trusted_proxy_cidrs.clone().into(),
        }
    }
}

impl UserinfoConfig {
    pub(crate) fn audience_allowed(&self, audience: &Value) -> bool {
        let userinfo_url = format!("{}/userinfo", self.issuer.trim_end_matches('/'));
        token_audience_contains(audience, &self.default_audience)
            || token_audience_contains(audience, &userinfo_url)
    }
}

/// Non-storage dependencies for the UserInfo protected-resource endpoint.
///
/// Token, subject, revocation and client reads remain on `ServerTokenService`;
/// this handle only owns DPoP replay state, response signing, and focused policy.
pub(crate) struct UserinfoHandles {
    replay: nazo_valkey::ReplayStore,
    keys: KeyManager,
    config: UserinfoConfig,
}

impl UserinfoHandles {
    pub(crate) fn new(
        replay: nazo_valkey::ReplayStore,
        keys: KeyManager,
        config: UserinfoConfig,
    ) -> Self {
        Self {
            replay,
            keys,
            config,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_state(state: &super::AppState) -> Self {
        Self::new(
            nazo_valkey::ReplayStore::new(&state.valkey_connection()),
            state.keyset.clone(),
            UserinfoConfig::from(state.settings.as_ref()),
        )
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.config.issuer
    }

    pub(crate) fn audience_allowed(&self, audience: &Value) -> bool {
        self.config.audience_allowed(audience)
    }

    pub(crate) async fn validate_dpop_proof(
        &self,
        req: &HttpRequest,
        token: &str,
        expected_jkt: Option<&str>,
    ) -> Result<Option<String>, DpopError> {
        validate_dpop_proof_with_store(
            &self.replay,
            self.issuer(),
            &self.config.mtls_endpoint_base_url,
            self.config.dpop_nonce_policy,
            req,
            Some(token),
            expected_jkt,
        )
        .await
    }

    pub(crate) async fn issue_dpop_nonce(&self) -> Result<String, DpopError> {
        crate::support::issue_dpop_nonce_with_store(&self.replay).await
    }

    pub(crate) fn request_mtls_thumbprint(&self, req: &HttpRequest) -> Option<String> {
        request_mtls_thumbprint_from_trusted_proxy(req, &self.config.trusted_proxy_cidrs)
    }

    pub(crate) async fn sign_response_jwt(
        &self,
        purpose: nazo_auth::SigningPurpose,
        claims: &Value,
        typ: &str,
        signing_alg: jsonwebtoken::Algorithm,
    ) -> jsonwebtoken::errors::Result<String> {
        let mut header = jsonwebtoken::Header::new(signing_alg);
        header.typ = Some(typ.to_owned());
        self.keys.encode_jwt(purpose, &header, claims).await
    }
}
