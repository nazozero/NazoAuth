use anyhow::{bail, ensure};
use nazo_auth::{
    validate_cors_origin, validate_frontend_base_url, validate_issuer_url,
    validate_protected_resource_identifier,
};

use super::{Configuration, MtlsCertificateSourceMode, Openid4vcRevocationPolicy};

/// Recovery must be able to wait out every stateless access or ID token.
pub const MAX_ACCESS_TOKEN_TTL_SECONDS: i64 = 3_600;
pub const MAX_ID_TOKEN_TTL_SECONDS: i64 = 3_600;

/// Shared by product admission and the host's signing-key retirement policy.
pub fn validate_token_lifetimes(access: i64, id: i64) -> anyhow::Result<()> {
    ensure!(access > 0, "ACCESS_TOKEN_TTL_SECONDS must be positive");
    ensure!(
        access <= MAX_ACCESS_TOKEN_TTL_SECONDS,
        "ACCESS_TOKEN_TTL_SECONDS must not exceed {MAX_ACCESS_TOKEN_TTL_SECONDS} so recovery can bound stateless JWT expiry"
    );
    ensure!(id > 0, "ID_TOKEN_TTL_SECONDS must be positive");
    ensure!(
        id <= MAX_ID_TOKEN_TTL_SECONDS,
        "ID_TOKEN_TTL_SECONDS must not exceed {MAX_ID_TOKEN_TTL_SECONDS} so recovery can bound signed token expiry"
    );
    Ok(())
}

impl Configuration {
    /// Validate product invariants before constructing services or accessing providers.
    /// Process configuration, file loading, and listener policy remain with the host.
    pub fn validate(&self) -> anyhow::Result<()> {
        let issuer = validate_issuer_url(&self.endpoint.issuer)?;
        validate_issuer_url(&self.endpoint.mtls_endpoint_base_url)?;
        validate_frontend_base_url(&self.endpoint.frontend_base_url)?;
        validate_protected_resource_identifier(&self.protocol.protected_resource_identifier)?;
        for origin in &self.endpoint.cors_allowed_origins {
            validate_cors_origin(origin)?;
        }
        ensure!(
            self.endpoint.mtls_certificate_source != MtlsCertificateSourceMode::Rfc9440
                || !self.endpoint.trusted_proxy_cidrs.is_empty(),
            "MTLS_CERTIFICATE_SOURCE=rfc9440 requires TRUSTED_PROXY_CIDRS"
        );
        // Issuer validation already restricts HTTP to loopback development.
        let loopback_http = issuer.scheme() == "http";
        ensure!(
            self.session.cookie_secure || loopback_http,
            "COOKIE_SECURE=false 只允许用于 loopback HTTP 本地开发 issuer"
        );
        ensure!(
            self.session.cookie_secure
                || (!self.session.session_cookie_name.starts_with("__Host-")
                    && !self.session.csrf_cookie_name.starts_with("__Host-")),
            "__Host- cookie names require COOKIE_SECURE=true"
        );
        ensure!(
            self.protocol.client_secret_pepper.len() >= 32,
            "CLIENT_SECRET_PEPPER must be at least 32 bytes"
        );
        if let Some(secret) = &self.protocol.pairwise_subject_secret {
            ensure!(
                secret.len() >= 32,
                "pairwise_subject_secret must be at least 32 bytes"
            );
        }
        for scope in &self.protocol.additional_scopes_supported {
            ensure!(
                !scope.is_empty()
                    && scope
                        .bytes()
                        .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e)),
                "ADDITIONAL_SCOPES_SUPPORTED must contain space-separated OAuth scope tokens"
            );
        }
        validate_token_lifetimes(
            self.protocol.access_token_ttl_seconds,
            self.protocol.id_token_ttl_seconds,
        )?;
        ensure!(
            self.protocol.refresh_token_ttl_seconds > 0,
            "REFRESH_TOKEN_TTL_SECONDS must be positive"
        );
        for (value, name) in [
            (self.protocol.auth_code_ttl_seconds, "AUTH_CODE_TTL_SECONDS"),
            (self.protocol.par_ttl_seconds, "PAR_TTL_SECONDS"),
            (self.session.session_ttl_seconds, "SESSION_TTL_SECONDS"),
            (
                self.session.pending_mfa_session_ttl_seconds,
                "PENDING_MFA_SESSION_TTL_SECONDS",
            ),
            (
                self.device.device_authorization_ttl_seconds,
                "DEVICE_AUTHORIZATION_TTL_SECONDS",
            ),
            (
                self.device.device_authorization_poll_interval_seconds,
                "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS",
            ),
            (
                self.ciba.ciba_auth_req_id_ttl_seconds,
                "CIBA_AUTH_REQ_ID_TTL_SECONDS",
            ),
            (
                self.ciba.ciba_poll_interval_seconds,
                "CIBA_POLL_INTERVAL_SECONDS",
            ),
            (
                self.storage.client_delivery_ttl_seconds,
                "CLIENT_DELIVERY_TTL_SECONDS",
            ),
            (
                self.openid4vc.transaction_ttl_seconds,
                "OPENID4VC_TRANSACTION_TTL_SECONDS",
            ),
            (
                self.identity.email.code_ttl_seconds,
                "EMAIL_CODE_TTL_SECONDS",
            ),
            (
                self.identity.email.send_cooldown_seconds,
                "EMAIL_CODE_SEND_COOLDOWN_SECONDS",
            ),
            (
                self.identity.email.send_peer_cooldown_seconds,
                "EMAIL_CODE_PEER_COOLDOWN_SECONDS",
            ),
        ] {
            ensure!(value > 0, "{name} must be positive");
        }
        if self
            .protocol
            .authorization_server_profile
            .requires_fapi2_security()
        {
            ensure!(
                self.protocol.auth_code_ttl_seconds <= 60,
                "AUTH_CODE_TTL_SECONDS must be 60 or less for FAPI2 profiles"
            );
            ensure!(
                self.protocol.par_ttl_seconds < 600,
                "PAR_TTL_SECONDS must be less than 600 for FAPI2 profiles"
            );
        }
        ensure!(
            self.session.pending_mfa_session_ttl_seconds < self.session.session_ttl_seconds,
            "PENDING_MFA_SESSION_TTL_SECONDS must be less than SESSION_TTL_SECONDS"
        );
        ensure!(
            self.device.device_authorization_poll_interval_seconds
                < self.device.device_authorization_ttl_seconds,
            "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS must be less than DEVICE_AUTHORIZATION_TTL_SECONDS"
        );
        ensure!(
            self.ciba.ciba_poll_interval_seconds < self.ciba.ciba_auth_req_id_ttl_seconds,
            "CIBA_POLL_INTERVAL_SECONDS must be less than CIBA_AUTH_REQ_ID_TTL_SECONDS"
        );
        ensure!(
            (1..=300).contains(&self.protocol.fapi_http_signature_max_age_seconds),
            "FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS must be between 1 and 300"
        );
        ensure!(
            (3_600..=2_592_000).contains(&self.storage.scim_event_retention_seconds),
            "SCIM_EVENT_RETENTION_SECONDS must be between 3600 and 2592000"
        );

        let rate = &self.identity.rate_limit;
        ensure!(
            rate.scim_denial_max_requests > 0,
            "SCIM_DENIAL_RATE_LIMIT_MAX_REQUESTS must be positive"
        );
        ensure!(
            rate.window_seconds > 0
                && rate.login_failure_window_seconds > 0
                && rate.mfa_failure_window_seconds > 0,
            "rate limit windows must be greater than 0"
        );
        ensure!(
            rate.auth_max_requests > 0
                && rate.token_max_requests > 0
                && rate.token_management_max_requests > 0
                && rate.login_failure_ip_email_max_attempts > 0
                && rate.mfa_failure_max_attempts > 0,
            "rate limit request caps must be greater than 0"
        );
        ensure!(
            !self.identity.email_code_dev_response_enabled
                || (cfg!(debug_assertions) && loopback_http),
            "EMAIL_CODE_DEV_RESPONSE_ENABLED=true requires a debug build and loopback HTTP issuer"
        );
        let passkey = &self.identity.passkey;
        validate_issuer_url(&passkey.origin)?;
        ensure!(
            !passkey.rp_id.trim().is_empty()
                && !passkey.rp_id.contains("://")
                && !passkey.rp_id.contains('/')
                && !passkey.rp_id.contains(':'),
            "PASSKEY_RP_ID must be a bare host name without scheme, port, or path"
        );
        passkey_auth::Webauthn::try_new(&passkey.rp_id, &passkey.rp_name, &passkey.origin)
            .map_err(|error| anyhow::anyhow!("invalid PASSKEY_RP_ID/PASSKEY_ORIGIN: {error}"))?;
        if let Some(saml) = &self.identity.federation.saml_gateway {
            ensure!(
                saml.secret.len() >= 32,
                "FEDERATION_SAML_GATEWAY_SECRET must be at least 32 bytes"
            );
        }
        self.validate_openid4vc()
    }

    fn validate_openid4vc(&self) -> anyhow::Result<()> {
        let vc = &self.openid4vc;
        let issuer_enabled = self.modules.enable_openid4vci_issuer;
        let verifier_enabled = self.modules.enable_openid4vp_verifier;
        ensure!(
            !(issuer_enabled || verifier_enabled) || vc.data_encryption_key.is_some(),
            "OpenID4VC modules require a data encryption root"
        );
        for (token, name) in [
            (
                &vc.issuer_management_token,
                "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
            ),
            (
                &vc.verifier_management_token,
                "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN",
            ),
        ] {
            if let Some(token) = token {
                ensure!(token.len() >= 32, "{name} must be at least 32 bytes");
            }
        }
        ensure!(
            vc.issuer_management_token.is_none()
                || vc.issuer_management_token != vc.verifier_management_token,
            "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN and OPENID4VP_VERIFIER_MANAGEMENT_TOKEN must differ"
        );
        ensure!(
            !issuer_enabled || vc.issuer_management_token.is_some(),
            "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN is required when the VCI issuer is enabled"
        );
        ensure!(
            !issuer_enabled || !vc.credential_configurations.is_empty(),
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON is required when the VCI issuer is enabled"
        );
        ensure!(
            !verifier_enabled || vc.verifier_management_token.is_some(),
            "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN is required when the VP verifier is enabled"
        );
        ensure!(
            !verifier_enabled || vc.revocation_policy == Openid4vcRevocationPolicy::Required,
            "ENABLE_OPENID4VP_VERIFIER=true requires OPENID4VC_REVOCATION_POLICY=required"
        );
        for configuration in vc.credential_configurations.values() {
            configuration.validate()?;
        }
        ensure!(
            vc.deferred_credential_configurations
                .iter()
                .all(|id| vc.credential_configurations.contains_key(id)),
            "OPENID4VCI_DEFERRED_CREDENTIAL_CONFIGURATIONS must reference configured credentials"
        );
        for origin in &vc.wallet_authorization_origins {
            validate_cors_origin(origin)?;
        }
        if let Some(jwks) = &vc.client_attestation_jwks {
            validate_attestation_jwk_set(jwks, "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON", false)?;
        }
        if let Some(jwks) = &vc.key_attestation_jwks {
            validate_attestation_jwk_set(jwks, "OPENID4VC_KEY_ATTESTATION_JWKS_JSON", true)?;
        }
        ensure!(
            vc.client_attestation_issuer.is_none() || vc.client_attestation_jwks.is_some(),
            "OPENID4VC_CLIENT_ATTESTATION_ISSUER requires OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON"
        );
        Ok(())
    }
}

fn validate_attestation_jwk_set(
    jwks: &serde_json::Value,
    name: &str,
    holder_key: bool,
) -> anyhow::Result<()> {
    let keys = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} must be a non-empty JWK Set"))?;
    let mut key_ids = std::collections::BTreeSet::new();
    for jwk in keys {
        let object = jwk
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{name} must contain JWK objects"))?;
        ensure!(
            !["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|field| object.contains_key(*field)),
            "{name} must contain public verification keys only"
        );
        let kid = object
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .filter(|kid| !kid.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{name} keys must have a non-empty kid"))?;
        ensure!(
            key_ids.insert(kid),
            "{name} must not contain duplicate kid values"
        );
        let supported = match (
            object.get("kty").and_then(serde_json::Value::as_str),
            object.get("crv").and_then(serde_json::Value::as_str),
        ) {
            (Some("EC"), Some("P-256")) => {
                object.get("x").is_some_and(serde_json::Value::is_string)
                    && object.get("y").is_some_and(serde_json::Value::is_string)
            }
            (Some("OKP"), Some("Ed25519")) if holder_key => {
                object.get("x").is_some_and(serde_json::Value::is_string)
            }
            _ => false,
        };
        if !supported {
            let purpose = if holder_key {
                "holder key attestation"
            } else {
                "client attestation"
            };
            bail!("{name} contains a key unsupported for {purpose}");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/config.rs"]
mod tests;
