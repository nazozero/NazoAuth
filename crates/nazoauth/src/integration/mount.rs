//! One deployment's external paths over the canonical protocol route manifest.
use anyhow::ensure;
use std::borrow::Cow;

use super::{Endpoint, Route};
use crate::config::Configuration;

/// Prepared path projection. Matching borrows the original URI; it never rewrites
/// the request used by proof verification, ingress policy or endpoint handlers.
#[derive(Debug)]
pub struct Mount {
    prefix: String,
    discovery: Vec<DiscoveryRoute>,
}

#[derive(Debug)]
struct DiscoveryRoute {
    path: String,
    route: &'static Route,
}

impl Mount {
    pub(crate) fn new(settings: &Configuration, path: &str) -> anyhow::Result<Self> {
        let prefix = canonical_prefix(path)?;
        let issuer = url::Url::parse(&settings.endpoint.issuer)?;
        ensure!(
            nazo_auth::issuer_path(&settings.endpoint.issuer) == prefix,
            "mount path must match the configured public issuer path"
        );
        ensure!(
            nazo_auth::issuer_path(&settings.endpoint.mtls_endpoint_base_url) == prefix,
            "mTLS endpoint base URL must use the same mount path as the issuer"
        );
        let resource = url::Url::parse(&settings.protocol.protected_resource_identifier)?;
        ensure!(
            resource.origin() == issuer.origin(),
            "protected resource metadata must be hosted on the public issuer origin"
        );
        ensure!(
            resource.query().is_none(),
            "this mount serves one protected resource identifier and does not support query-based resource selection"
        );
        let resource_path =
            nazo_auth::issuer_path(&settings.protocol.protected_resource_identifier);
        ensure!(
            resource_path == resource.path() || resource_path.is_empty() && resource.path() == "/",
            "protected resource identifier must use its literal canonical URL path"
        );
        for provider in settings
            .identity
            .federation
            .providers
            .enabled_public_providers()
        {
            let redirect_uri = match &provider.adapter {
                crate::config::ExternalLoginProviderAdapter::Oidc(settings) => {
                    &settings.redirect_uri
                }
                crate::config::ExternalLoginProviderAdapter::Social(settings) => {
                    &settings.redirect_uri
                }
            };
            let callback = redirect_uri
                .split_once('?')
                .map_or(redirect_uri.as_str(), |(callback, _)| callback);
            ensure!(
                callback
                    == format!(
                        "{}/auth/federation/{}/callback",
                        settings.endpoint.issuer, provider.provider_id
                    ),
                "federation provider {} redirect_uri must match its mounted callback",
                provider.provider_id
            );
        }
        let mut discovery = Vec::with_capacity(3);
        for route in super::routes() {
            let endpoint = route.methods[0].endpoint;
            let suffix = match endpoint {
                Endpoint::OauthAuthorizationServerMetadata => prefix,
                Endpoint::OauthProtectedResourceMetadata => {
                    if resource.path() == "/" {
                        ""
                    } else {
                        resource.path()
                    }
                }
                Endpoint::CredentialIssuerMetadata
                    if settings.modules.enable_openid4vci_issuer
                        && settings.modules.register_openid4vci_routes =>
                {
                    prefix
                }
                _ => continue,
            };
            discovery.push(DiscoveryRoute {
                path: format!("{}{suffix}", route.path),
                route,
            });
        }
        let mount = Self {
            prefix: prefix.to_owned(),
            discovery,
        };
        for entry in &mount.discovery {
            if let Some(path) = mount.relative_path(&entry.path) {
                let path = crate::routes::routing_path(path);
                ensure!(
                    crate::routes::match_path(&path).is_none_or(|(route, _)| relocated(route)),
                    "discovery path {:?} conflicts with an endpoint in NazoAuth mount {:?}",
                    entry.path,
                    mount.path()
                );
            }
        }
        Ok(mount)
    }

    /// Canonical mount path, without a trailing slash except for the root `/`.
    pub fn path(&self) -> &str {
        if self.prefix.is_empty() {
            "/"
        } else {
            &self.prefix
        }
    }

    /// Exact discovery resources registered alongside the ordinary prefix scope.
    /// Their locations follow the configured issuer/resource identifiers.
    pub fn discovery_paths(&self) -> impl Iterator<Item = &str> {
        self.discovery.iter().map(|entry| entry.path.as_str())
    }

    /// Whether the mount owns a raw external path. `/ui` below the mount belongs
    /// to the host. At `/`, adapters also exclude the host's reserved namespaces.
    pub fn owns_path(&self, raw_path: &str) -> bool {
        if self
            .relative_path(raw_path)
            .is_some_and(|path| !in_scope(path, "/ui"))
        {
            return true;
        }
        self.discovery.iter().any(|entry| entry.path == raw_path)
    }

    /// Reject overlap with the host's occupied literal path namespaces. A host
    /// declares `/api` for all of its `/api/*` handlers, not NazoAuth's endpoints.
    /// Frameworks with opaque routers must supply these reservations explicitly.
    pub fn check_conflicts(&self, reserved_paths: &[&str]) -> anyhow::Result<()> {
        for &reserved in reserved_paths {
            ensure!(
                reserved.starts_with('/') && !reserved.contains(['?', '#']),
                "reserved paths must start with / and contain no query or fragment"
            );
            // These are literal external namespaces, including exact discovery
            // paths from other mounts. Resource identifiers may contain escapes
            // and other path characters that are not accepted in mount prefixes.
            let reserved = reserved.trim_end_matches('/');
            let ui = self
                .relative_path(reserved)
                .is_some_and(|path| in_scope(path, "/ui"));
            // Framework routers can match decoded path aliases before our raw
            // guards run. Reserve the same escape-normalized namespace too.
            let normalized = crate::routes::routing_path(reserved);
            let discovery_conflict = self
                .discovery
                .iter()
                .any(|entry| in_scope(&crate::routes::routing_path(&entry.path), &normalized));
            if ui && !discovery_conflict {
                continue;
            }
            let ordinary_conflict = if self.prefix.is_empty() {
                super::routes().iter().any(|route| {
                    if relocated(route) {
                        return false;
                    }
                    let literal = route.path.split('{').next().expect("route literal");
                    overlaps(&normalized, literal.trim_end_matches('/'))
                })
            } else {
                overlaps(&normalized, &self.prefix)
            };
            ensure!(
                !discovery_conflict && !ordinary_conflict,
                "host path namespace {reserved:?} conflicts with NazoAuth mount {:?}",
                self.path()
            );
        }
        Ok(())
    }

    /// Transport metadata for an unchanged external request target.
    pub fn route_for_path(&self, raw_path: &str) -> Option<&'static Route> {
        let path = self.routing_path(raw_path)?;
        crate::routes::match_path(&path).map(|(route, _)| route)
    }

    /// Project a canonical manifest path for host registration and conformance.
    /// Disabled discovery resources and noncanonical aliases have no location.
    pub fn route_path(&self, route: &Route) -> Option<String> {
        if relocated(route) {
            return self
                .discovery
                .iter()
                .find(|entry| std::ptr::eq(entry.route, route))
                .map(|entry| entry.path.clone());
        }
        Some(format!("{}{}", self.prefix, route.path))
    }

    pub(crate) fn routing_path<'a>(&self, raw_path: &'a str) -> Option<Cow<'a, str>> {
        if raw_path.starts_with("/.well-known/")
            && let Some(entry) = self.discovery.iter().find(|entry| entry.path == raw_path)
        {
            return Some(Cow::Borrowed(entry.route.path));
        }
        let path = self.relative_path(raw_path)?;
        // Relocated metadata is published only at the identifier-derived path.
        // Normalization happens after prefix selection, so escaped mount aliases
        // cannot select another tenant or turn an escaped slash into a boundary.
        let normalized = crate::routes::routing_path(path);
        if matches!(
            normalized.as_ref(),
            "/.well-known/oauth-authorization-server" | "/.well-known/openid-credential-issuer"
        ) || in_scope(&normalized, "/.well-known/oauth-protected-resource")
        {
            return None;
        }
        Some(normalized)
    }

    fn relative_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        let suffix = path.strip_prefix(&self.prefix)?;
        if suffix.is_empty() {
            Some("/")
        } else if suffix.starts_with('/') {
            Some(suffix)
        } else {
            None
        }
    }
}

fn relocated(route: &Route) -> bool {
    matches!(
        route.methods[0].endpoint,
        Endpoint::OauthAuthorizationServerMetadata
            | Endpoint::OauthProtectedResourceMetadata
            | Endpoint::CredentialIssuerMetadata
    )
}

fn in_scope(path: &str, scope: &str) -> bool {
    path == scope
        || path
            .strip_prefix(scope)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn overlaps(a: &str, b: &str) -> bool {
    in_scope(a, b) || in_scope(b, a)
}

fn canonical_prefix(path: &str) -> anyhow::Result<&str> {
    ensure!(path.starts_with('/'), "mount paths must start with /");
    let path = path.strip_suffix('/').unwrap_or(path);
    ensure!(
        path.is_empty()
            || path[1..].split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
            }),
        "mount paths must contain unescaped URL path segments without dot segments"
    );
    Ok(path)
}

#[cfg(test)]
#[path = "../../tests/unit/integration/mount.rs"]
mod tests;
