use anyhow::{Context, ensure};
use nazo_identity::TenantContext;
use nazo_runtime_modules::ModuleId;
use serde::Deserialize;

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
    pub data_encryption_key: Option<String>,
    pub issuer_management_token: Option<String>,
    pub verifier_management_token: Option<String>,
    pub email_relay_token: Option<String>,
    pub federation_provider_configs: Option<serde_json::Value>,
    pub saml_gateway: Option<WorkerSamlGateway>,
    pub openid4vc_import: Option<WorkerOpenid4vcImport>,
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
        ensure!(
            !self.machine_only
                || self.modules.iter().all(|module| {
                    matches!(
                        module,
                        ModuleId::TokenExchange
                            | ModuleId::JwtBearerGrant
                            | ModuleId::HttpMessageSignatures
                            | ModuleId::DynamicClientRegistration
                    )
                }),
            "machine-only profile cannot enable interactive modules"
        );
        for module in &self.modules {
            ensure!(
                matches!(
                    module,
                    ModuleId::RequestObjects
                        | ModuleId::DeviceAuthorization
                        | ModuleId::DynamicClientRegistration
                        | ModuleId::Jarm
                        | ModuleId::SessionManagement
                        | ModuleId::TokenExchange
                        | ModuleId::JwtBearerGrant
                        | ModuleId::NativeSso
                        | ModuleId::AuthorizationDetails
                        | ModuleId::FrontchannelLogout
                        | ModuleId::HttpMessageSignatures
                        | ModuleId::Ciba
                        | ModuleId::Scim
                        | ModuleId::ScimSecurityEvents
                        | ModuleId::Openid4vciIssuer
                        | ModuleId::Openid4vpVerifier
                ),
                "module {module:?} is unavailable in the Workers deployment profile"
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
        settings.protocol.backchannel_logout_supported = !self.services.outbound_origins.is_empty();
        ensure!(
            !self.services.mtls || self.ingress == Ingress::DirectCloudflare,
            "Worker mTLS requires direct Cloudflare certificate metadata"
        );
        if self.services.mtls {
            settings.endpoint.mtls_certificate_source =
                nazoauth::config::MtlsCertificateSourceMode::DirectTls;
        }
        let mut registration_grants = vec!["client_credentials".to_owned()];
        if !self.machine_only {
            registration_grants
                .extend(["authorization_code".to_owned(), "refresh_token".to_owned()]);
        }
        for (module, grant) in [
            (
                ModuleId::TokenExchange,
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            (
                ModuleId::JwtBearerGrant,
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ),
            (
                ModuleId::DeviceAuthorization,
                "urn:ietf:params:oauth:grant-type:device_code",
            ),
            (ModuleId::Ciba, "urn:openid:params:grant-type:ciba"),
        ] {
            if self.modules.contains(&module) {
                registration_grants.push(grant.to_owned());
            }
        }
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

    /// Metadata for the machine-only OAuth issuer, without browser grant claims.
    #[must_use]
    pub fn machine_metadata(&self) -> serde_json::Value {
        let root = self.issuer.trim_end_matches('/');
        let mut grants = vec!["client_credentials"];
        if self.modules.contains(&ModuleId::TokenExchange) {
            grants.push("urn:ietf:params:oauth:grant-type:token-exchange");
        }
        if self.modules.contains(&ModuleId::JwtBearerGrant) {
            grants.push("urn:ietf:params:oauth:grant-type:jwt-bearer");
        }
        let mut metadata = serde_json::json!({
            "issuer": self.issuer,
            "token_endpoint": format!("{root}/token"),
            "jwks_uri": format!("{root}/jwks.json"),
            "revocation_endpoint": format!("{root}/revoke"),
            "introspection_endpoint": format!("{root}/introspect"),
            "response_types_supported": [],
            "grant_types_supported": grants,
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": nazo_auth::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
            "dpop_signing_alg_values_supported": ["ES256", "EdDSA"]
        });
        if self.modules.contains(&ModuleId::DynamicClientRegistration) {
            metadata["registration_endpoint"] = serde_json::json!(format!("{root}/register"));
        }
        if self.services.mtls {
            metadata["token_endpoint_auth_methods_supported"] = serde_json::json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "tls_client_auth",
                "self_signed_tls_client_auth"
            ]);
            metadata["tls_client_certificate_bound_access_tokens"] = serde_json::json!(true);
        }
        metadata
    }

    /// Admit routes for the deployment's selected login and service profile.
    pub fn allows_route(&self, method: &http::Method, path: &str) -> bool {
        if matches!(
            path,
            "/device" | "/device_authorization" | "/device/verification" | "/device/decision"
        ) && !self.modules.contains(&ModuleId::DeviceAuthorization)
        {
            return false;
        }
        if path == "/register" || path.starts_with("/register/") {
            return self.modules.contains(&ModuleId::DynamicClientRegistration)
                && if path == "/register" {
                    matches!(*method, http::Method::POST | http::Method::OPTIONS)
                } else {
                    path.strip_prefix("/register/")
                        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
                        && matches!(
                            *method,
                            http::Method::GET
                                | http::Method::PUT
                                | http::Method::DELETE
                                | http::Method::OPTIONS
                        )
                };
        }
        if !self.machine_only && !self.passkey_only {
            return true;
        }
        // Keep the shared facade responsible for endpoint-specific CORS policy.
        // A preflight can reach only a path admitted for an actual operation.
        if method == http::Method::OPTIONS {
            return [
                http::Method::GET,
                http::Method::POST,
                http::Method::PATCH,
                http::Method::DELETE,
            ]
            .iter()
            .any(|method| self.allows_route(method, path));
        }
        if self.passkey_only {
            return match *method {
                http::Method::GET => matches!(
                    path,
                    "/.well-known/openid-configuration"
                        | "/.well-known/oauth-authorization-server"
                        | "/.well-known/oauth-protected-resource"
                        | "/health"
                        | "/live"
                        | "/startup"
                        | "/check_session"
                        | "/check_session/status"
                        | "/fapi/resource"
                        | "/device"
                        | "/device/verification"
                        | "/jwks.json"
                        | "/authorize"
                        | "/authorize/consent"
                        | "/authorize/client-presentation"
                        | "/userinfo"
                        | "/auth/me"
                        | "/auth/me/passkeys"
                        | "/auth/csrf"
                        | "/auth"
                        | "/consent"
                        | "/auth/setup"
                        | "/auth/passkey"
                        | "/auth/setup.js"
                        | "/logout"
                ),
                http::Method::POST => matches!(
                    path,
                    "/token"
                        | "/revoke"
                        | "/introspect"
                        | "/par"
                        | "/authorize"
                        | "/authorize/decision"
                        | "/userinfo"
                        | "/auth/passkey/begin"
                        | "/auth/passkey/finish"
                        | "/auth/mfa/verify"
                        | "/auth/me/mfa/totp/begin"
                        | "/auth/me/mfa/totp/confirm"
                        | "/auth/me/mfa/step-up"
                        | "/auth/me/mfa/backup-codes/regenerate"
                        | "/auth/me/mfa/disable"
                        | "/auth/me/passkeys/registration/begin"
                        | "/auth/me/passkeys/registration/finish"
                        | "/auth/logout"
                        | "/auth/setup/claim"
                        | "/logout"
                        | "/fapi/resource"
                        | "/device_authorization"
                        | "/device/decision"
                ),
                http::Method::PATCH => path == "/auth/me",
                http::Method::DELETE => path
                    .strip_prefix("/auth/me/passkeys/")
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()),
                _ => false,
            };
        }
        if method == http::Method::GET {
            matches!(
                path,
                "/health"
                    | "/live"
                    | "/startup"
                    | "/jwks.json"
                    | "/.well-known/oauth-authorization-server"
                    | "/.well-known/oauth-protected-resource"
                    | "/fapi/resource"
            )
        } else if method == http::Method::POST {
            matches!(
                path,
                "/token" | "/revoke" | "/introspect" | "/fapi/resource"
            )
        } else {
            false
        }
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
