//! Local OpenID Foundation conformance seed helpers.
//!
//! The binary performs database writes; this module owns deterministic parsing
//! and URL/JWKS normalization logic that can be tested without external state.

use crate::config::ConfigSource;
use std::{collections::BTreeSet, env};
use url::Url;

const LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER: &str =
    "local-development-client-secret-pepper-00000001";

pub mod client;
pub mod config;
pub mod openid4vc;

pub fn callback_uri(suite_base_url: &str, alias: &str) -> String {
    test_endpoint_uri(suite_base_url, alias, "callback")
}

pub fn test_endpoint_uri(suite_base_url: &str, alias: &str, endpoint: &str) -> String {
    format!(
        "{}/test/a/{}/{}",
        suite_base_url.trim_end_matches('/'),
        alias,
        endpoint.trim_start_matches('/')
    )
}

pub fn suite_base_urls(primary_suite_base_url: &str) -> Result<Vec<String>, String> {
    suite_base_urls_from_extra(
        primary_suite_base_url,
        env::var("OIDF_LOCAL_EXTRA_SUITE_BASE_URLS").ok().as_deref(),
    )
}

pub fn seed_client_secret_pepper(config: &ConfigSource) -> String {
    config.string(
        "CLIENT_SECRET_PEPPER",
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
    )
}

fn suite_base_urls_from_extra(
    primary_suite_base_url: &str,
    extra_urls: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut urls = BTreeSet::new();
    urls.insert(normalize_suite_base_origin(primary_suite_base_url)?);
    urls.insert("https://www.certification.openid.net".to_owned());

    if let Some(extra_urls) = extra_urls {
        for url in extra_urls.split(',') {
            if !url.trim().is_empty() {
                urls.insert(normalize_suite_base_origin(url)?);
            }
        }
    }

    Ok(urls.into_iter().collect())
}

fn normalize_suite_base_origin(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() {
        return Err("OIDF suite base URL must not be empty".to_owned());
    }
    if value.contains(',') {
        return Err(
            "OIDF_SUITE_BASE_URL must contain exactly one HTTPS origin; use OIDF_LOCAL_EXTRA_SUITE_BASE_URLS for additional origins"
                .to_owned(),
        );
    }
    let parsed = Url::parse(value)
        .map_err(|_| "OIDF suite base URL must be an absolute HTTPS origin".to_owned())?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
    {
        return Err(
            "OIDF suite base URL must be an HTTPS origin without path, query, fragment, or userinfo"
                .to_owned(),
        );
    }
    let Some(host) = parsed.host_str() else {
        return Err("OIDF suite base URL must include a host".to_owned());
    };
    let mut origin = format!("https://{host}");
    if let Some(port) = parsed.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

pub fn callback_uris(suite_base_urls: &[String], alias: &str) -> Vec<String> {
    test_endpoint_uris(suite_base_urls, alias, "callback")
}

pub fn callback_uris_for_aliases(suite_base_urls: &[String], aliases: &[&str]) -> Vec<String> {
    aliases
        .iter()
        .flat_map(|alias| callback_uris(suite_base_urls, alias))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn test_endpoint_uris(suite_base_urls: &[String], alias: &str, endpoint: &str) -> Vec<String> {
    suite_base_urls
        .iter()
        .map(|suite_base_url| test_endpoint_uri(suite_base_url, alias, endpoint))
        .collect()
}

#[cfg(test)]
#[path = "../../tests/in_source/src/oidf_seed/tests/oidf_seed.rs"]
mod tests;
