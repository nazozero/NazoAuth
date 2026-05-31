//! OAuth/OIDC URL policy checks.
//! These helpers encode the boundary between production HTTPS URLs and
//! loopback/native-app exceptions that are explicitly allowed by OAuth BCP.

use anyhow::bail;
use url::Url;

pub(crate) fn validate_issuer_url(value: &str) -> anyhow::Result<()> {
    let url = parse_url("issuer", value)?;
    if !url.has_host() {
        bail!("issuer 必须包含 host");
    }
    reject_url_credentials("issuer", &url)?;
    if url.query().is_some() || url.fragment().is_some() {
        bail!("issuer 不能包含 query 或 fragment");
    }
    validate_https_or_loopback_http("issuer", &url)
}

pub(crate) fn validate_frontend_base_url(value: &str) -> anyhow::Result<()> {
    let url = parse_url("FRONTEND_BASE_URL", value)?;
    if !url.has_host() {
        bail!("FRONTEND_BASE_URL 必须包含 host");
    }
    reject_url_credentials("FRONTEND_BASE_URL", &url)?;
    if url.query().is_some() || url.fragment().is_some() {
        bail!("FRONTEND_BASE_URL 不能包含 query 或 fragment");
    }
    validate_https_or_loopback_http("FRONTEND_BASE_URL", &url)
}

pub(crate) fn validate_cors_origin(value: &str) -> anyhow::Result<()> {
    let url = parse_url("CORS_ALLOWED_ORIGINS", value)?;
    if !url.has_host() {
        bail!("CORS_ALLOWED_ORIGINS 必须包含 host");
    }
    reject_url_credentials("CORS_ALLOWED_ORIGINS", &url)?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        bail!("CORS_ALLOWED_ORIGINS 只能配置 origin，不能包含 path、query 或 fragment");
    }
    validate_https_or_loopback_http("CORS_ALLOWED_ORIGINS", &url)
}

pub(crate) fn validate_oauth_redirect_uri(client_type: &str, value: &str) -> anyhow::Result<()> {
    if value.contains('*') {
        bail!("redirect_uri 不支持通配符");
    }
    let uri = parse_url("redirect_uri", value)?;
    reject_url_credentials("redirect_uri", &uri)?;
    if uri.fragment().is_some() {
        bail!("redirect_uri 不能包含 fragment");
    }

    match uri.scheme() {
        "https" => {
            if !uri.has_host() {
                bail!("https redirect_uri 必须包含 host");
            }
            Ok(())
        }
        "http" => {
            if client_type != "public" || !is_loopback_host(&uri) {
                bail!("http redirect_uri 只允许 public native client 使用 loopback 地址");
            }
            Ok(())
        }
        scheme if client_type == "public" && is_private_use_scheme(scheme) => Ok(()),
        _ => bail!("redirect_uri 必须使用 https、loopback http 或 public native 私有 scheme"),
    }
}

pub(crate) fn oauth_redirect_uri_matches(
    client_type: &str,
    registered: &str,
    requested: &str,
) -> bool {
    if registered == requested {
        return true;
    }
    if client_type != "public" {
        return false;
    }

    let (Ok(registered), Ok(requested)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    registered.scheme() == "http"
        && requested.scheme() == "http"
        && is_loopback_host(&registered)
        && is_loopback_host(&requested)
        && registered.host_str() == requested.host_str()
        && registered.path() == requested.path()
        && registered.query() == requested.query()
}

pub(crate) fn is_loopback_http_url(value: &str) -> bool {
    Url::parse(value)
        .ok()
        .is_some_and(|url| url.scheme() == "http" && is_loopback_host(&url))
}

fn parse_url(name: &str, value: &str) -> anyhow::Result<Url> {
    Url::parse(value).map_err(|_| anyhow::anyhow!("{name} 必须是绝对 URI"))
}

fn validate_https_or_loopback_http(name: &str, url: &Url) -> anyhow::Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url) => Ok(()),
        _ => bail!("{name} 必须使用 https，只有 loopback 本地开发地址允许 http"),
    }
}

fn reject_url_credentials(name: &str, url: &Url) -> anyhow::Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{name} 不能包含用户名或密码");
    }
    Ok(())
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn is_private_use_scheme(scheme: &str) -> bool {
    scheme.contains('.')
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_requires_https_except_loopback_http() {
        assert!(validate_issuer_url("https://auth.example").is_ok());
        assert!(validate_issuer_url("http://127.0.0.1:8000").is_ok());
        assert!(validate_issuer_url("http://auth.example").is_err());
        assert!(validate_issuer_url("https://auth.example?x=1").is_err());
        assert!(validate_issuer_url("https://user:pass@auth.example").is_err());
        assert!(validate_frontend_base_url("https://frontend.example/app?x=1").is_err());
        assert!(validate_cors_origin("https://user@frontend.example").is_err());
    }

    #[test]
    fn redirect_uri_policy_allows_only_oauth_bcp_exceptions() {
        assert!(validate_oauth_redirect_uri("confidential", "https://client.example/cb").is_ok());
        assert!(validate_oauth_redirect_uri("public", "http://127.0.0.1:49152/cb").is_ok());
        assert!(validate_oauth_redirect_uri("public", "com.example.app:/oauth2redirect").is_ok());
        assert!(validate_oauth_redirect_uri("confidential", "http://127.0.0.1:49152/cb").is_err());
        assert!(validate_oauth_redirect_uri("public", "http://client.example/cb").is_err());
        assert!(validate_oauth_redirect_uri("public", "https://client.example/cb#frag").is_err());
        assert!(validate_oauth_redirect_uri("public", "https://user@client.example/cb").is_err());
    }

    #[test]
    fn loopback_redirect_matching_ignores_only_port() {
        assert!(oauth_redirect_uri_matches(
            "public",
            "http://127.0.0.1:3000/callback?x=1",
            "http://127.0.0.1:49152/callback?x=1"
        ));
        assert!(!oauth_redirect_uri_matches(
            "public",
            "http://127.0.0.1:3000/callback?x=1",
            "http://127.0.0.1:49152/callback?x=2"
        ));
        assert!(!oauth_redirect_uri_matches(
            "confidential",
            "http://127.0.0.1:3000/callback",
            "http://127.0.0.1:49152/callback"
        ));
    }
}
