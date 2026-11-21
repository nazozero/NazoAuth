use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_identity::TenantContext;
use nazo_key_management::SigningKeyWrappingKeyRing;
use nazo_runtime_modules::ModuleId;
use serde::Deserialize;
use zeroize::Zeroizing;

/// Deployment configuration. Secret values are supplied separately by the host.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfiguration {
    pub tenant: TenantContext,
    pub issuer: String,
    pub frontend_base_url: String,
    pub ingress: Ingress,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default)]
    /// Capabilities constructed by this deployment. Mutable desired state lives
    /// in D1 and cannot enable a capability outside this set.
    pub modules: Vec<ModuleId>,
    #[serde(default)]
    pub machine_only: bool,
    #[serde(default)]
    pub passkey_only: bool,
    #[serde(default)]
    pub services: WorkerServices,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerServices {
    #[serde(default)]
    pub mtls: bool,
    #[serde(default)]
    pub outbound_origins: Vec<String>,
    pub email_relay: Option<EmailRelay>,
    #[serde(default)]
    pub credential_configurations:
        std::collections::BTreeMap<String, nazo_openid4vci::CredentialConfiguration>,
    #[serde(default)]
    pub deferred_credential_configurations: std::collections::BTreeSet<String>,
    #[serde(default)]
    pub wallet_authorization_origins: Vec<String>,
    pub client_attestation_jwks: Option<serde_json::Value>,
    pub key_attestation_jwks: Option<serde_json::Value>,
    pub client_attestation_issuer: Option<String>,
    #[serde(default)]
    pub mdoc_crls: std::collections::BTreeMap<String, WorkerMdocCrl>,
}

/// Public CRL signed by the offline IACA and bound to one exact authority view.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerMdocCrl {
    pub der_base64: String,
    pub public_material_blake3: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailRelay {
    pub endpoint: String,
    pub from: String,
}

/// Secret JSON is loaded exclusively from NAZO_SERVICE_SECRETS by the host.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSecrets {
    pub previous_signing_wrapping_key: Option<WorkerPreviousSigningWrappingKey>,
    pub data_encryption_key: Option<String>,
    pub issuer_management_token: Option<String>,
    pub verifier_management_token: Option<String>,
    pub email_relay_token: Option<String>,
    pub federation_provider_configs: Option<serde_json::Value>,
    pub saml_gateway: Option<WorkerSamlGateway>,
    pub openid4vc_import: Option<WorkerOpenid4vcImport>,
}

/// Temporary read authority for a generation sealed before a wrapping-key change.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPreviousSigningWrappingKey {
    pub id: String,
}

impl WorkerSecrets {
    /// Consume the transition secret before handing the remaining service secrets
    /// to application composition. Key management owns generation authentication
    /// and resealing; the host only decodes deployment-provided key material.
    pub fn take_signing_wrapping_keys(
        &mut self,
        current_id: String,
        current_base64: String,
        previous_base64: Option<String>,
    ) -> anyhow::Result<SigningKeyWrappingKeyRing> {
        let previous_base64 = previous_base64.map(Zeroizing::new);
        let current = decode_signing_wrapping_key(Zeroizing::new(current_base64))?;
        let previous = match (self.previous_signing_wrapping_key.take(), previous_base64) {
            (Some(previous), Some(encoded)) => {
                Some((previous.id, decode_signing_wrapping_key(encoded)?))
            }
            (None, None) => None,
            _ => anyhow::bail!(
                "previous signing wrapping key id and NAZO_PREVIOUS_SIGNING_KEY must be configured together"
            ),
        };
        Ok(SigningKeyWrappingKeyRing::new(
            current_id,
            *current,
            previous.as_ref().map(|(id, key)| (id.clone(), **key)),
        )?)
    }
}

fn decode_signing_wrapping_key(encoded: Zeroizing<String>) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0_u8; 32]);
    ensure!(
        STANDARD
            .decode_slice(encoded.as_bytes(), key.as_mut_slice())
            .ok()
            == Some(32),
        "signing wrapping key must be standard Base64 encoding of exactly 32 bytes"
    );
    Ok(key)
}

/// Operator-only, one-generation import through the existing encrypted key
/// repository. Remove this field from the secret after a successful import.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerOpenid4vcImport {
    pub expected_revision: i64,
    pub material: nazo_key_management::Openid4vcMaterial,
    pub signing_key_pem: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSamlGateway {
    pub issuer: String,
    pub audience: String,
    pub secret: String,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Ingress {
    DirectCloudflare,
    Local,
}

impl WorkerConfiguration {
    pub fn application(
        &self,
        client_secret_pepper: String,
    ) -> anyhow::Result<nazoauth::config::Configuration> {
        ensure!(
            client_secret_pepper.len() >= 32,
            "client-secret pepper must contain at least 32 bytes"
        );
        ensure!(
            !(self.machine_only && self.passkey_only),
            "Worker cannot select both machine-only and passkey-only profiles"
        );
        let profile = if self.machine_only {
            nazo_auth::DeploymentProfile::MachineToMachine
        } else if self.passkey_only {
            nazo_auth::DeploymentProfile::PasskeyOnly
        } else {
            nazo_auth::DeploymentProfile::Full
        };
        for module in &self.modules {
            ensure!(
                profile.allows_module(*module),
                "module {module:?} is unavailable in the selected deployment profile"
            );
        }
        ensure!(
            !self.modules.contains(&ModuleId::NativeSso)
                || self.modules.contains(&ModuleId::TokenExchange),
            "Native SSO requires Token Exchange"
        );
        let issuer = url::Url::parse(&self.issuer).context("invalid issuer URL")?;
        ensure!(
            issuer.path() == "/",
            "Workers issuer must use the origin root"
        );
        ensure!(
            issuer.scheme() == "https"
                || (issuer.scheme() == "http"
                    && matches!(issuer.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))),
            "Workers issuer must use HTTPS (HTTP is allowed only for local development)"
        );
        ensure!(
            self.ingress != Ingress::Local
                || matches!(issuer.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
            "local ingress is restricted to a loopback issuer"
        );
        let mut settings =
            nazoauth::config::Configuration::new(self.tenant, &self.issuer, client_secret_pepper)?;
        settings.protocol.deployment_profile = profile;
        settings.protocol.backchannel_logout_supported = !self.services.outbound_origins.is_empty();
        ensure!(
            !self.services.mtls || self.ingress == Ingress::DirectCloudflare,
            "Worker mTLS requires direct Cloudflare certificate metadata"
        );
        if self.services.mtls {
            settings.endpoint.mtls_certificate_source =
                nazoauth::config::MtlsCertificateSourceMode::DirectTls;
        }
        let registration_grants = profile
            .grant_types(|module| self.modules.contains(&module))
            .into_iter()
            .map(str::to_owned)
            .collect();
        settings.modules.dynamic_client_registration_capabilities =
            nazo_auth::DynamicRegistrationCapabilities {
                remote_documents: !self.services.outbound_origins.is_empty(),
                mtls: self.services.mtls,
                backchannel_logout: !self.services.outbound_origins.is_empty(),
                grant_types: Some(registration_grants),
            };
        settings
            .endpoint
            .frontend_base_url
            .clone_from(&self.frontend_base_url);
        if !self.cors_allowed_origins.is_empty() {
            settings
                .endpoint
                .cors_allowed_origins
                .clone_from(&self.cors_allowed_origins);
        }
        settings.validate()?;
        Ok(settings)
    }

    /// Admit the configured issuer authority before selecting its tenant graph.
    /// Forwarded headers never select a tenant in this single-tenant host.
    pub fn accepts_authority(&self, uri: &http::Uri, headers: &http::HeaderMap) -> bool {
        let Ok(issuer) = self.issuer.parse::<http::Uri>() else {
            return false;
        };
        let Some(expected) = issuer.authority() else {
            return false;
        };
        let Some(actual) = uri.authority() else {
            return false;
        };
        let default_port = if issuer.scheme_str() == Some("http") {
            80
        } else {
            443
        };
        let same_authority = |candidate: &http::uri::Authority| {
            authority_port(candidate, default_port).is_some_and(|port| {
                candidate.host().eq_ignore_ascii_case(expected.host())
                    && Some(port) == authority_port(expected, default_port)
            })
        };
        uri.scheme() == issuer.scheme()
            && same_authority(actual)
            && headers.get_all(http::header::HOST).iter().all(|host| {
                host.to_str()
                    .ok()
                    .and_then(|value| value.parse::<http::uri::Authority>().ok())
                    .is_some_and(|authority| same_authority(&authority))
            })
    }
}

fn authority_port(authority: &http::uri::Authority, default: u16) -> Option<u16> {
    // Authority::host omits userinfo, and port_u16 maps malformed explicit
    // ports to None. Neither may be interpreted as the configured origin.
    if authority.as_str().contains('@') {
        return None;
    }
    match authority.as_str().strip_prefix(authority.host())? {
        "" => Some(default),
        suffix => {
            let port = suffix.strip_prefix(':')?;
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            port.parse().ok()
        }
    }
}
