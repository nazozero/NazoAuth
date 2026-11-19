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
        for module in &self.modules {
            ensure!(
                matches!(
                    module,
                    ModuleId::RequestObjects | ModuleId::Jarm | ModuleId::SessionManagement
                ),
                "module {module:?} is unavailable in the Workers deployment profile"
            );
        }
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
