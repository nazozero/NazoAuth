//! 管理端第三方登录 provider 配置视图。
//! 这里只暴露启停状态、展示信息和回调地址，不返回 secret 或第三方 token。
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use crate::http::json_response_no_store;

use crate::config::{Configuration, ExternalLoginProviderAdapter};
use crate::endpoints::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};

use serde::Serialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Clone)]
pub struct AdminFederationConfig {
    pub providers: Arc<[Value]>,
}

impl AdminFederationConfig {
    pub fn from_settings(settings: &Configuration) -> Self {
        Self {
            providers: settings
                .identity
                .federation
                .providers
                .configured_providers()
                .map(admin_provider_view)
                .collect::<Vec<_>>()
                .into(),
        }
    }

    fn providers(&self) -> &[Value] {
        &self.providers
    }
}

pub async fn admin_federation_providers(
    admin_sessions: &AdminSessionHandles,
    config: &AdminFederationConfig,
    req: &HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden_with_handles(admin_sessions, req).await {
        return response;
    }
    // 管理端 onboarding 需要能核对 callback 与 adapter 类型，但不能读取
    // client_secret、第三方 access token 或 JWKS 原始内容。
    #[derive(Serialize)]
    struct ProvidersResponse<'a> {
        providers: &'a [Value],
    }
    json_response_no_store(ProvidersResponse {
        providers: config.providers(),
    })
}

pub fn admin_provider_view(provider: &crate::config::ExternalLoginProvider) -> Value {
    match &provider.adapter {
        ExternalLoginProviderAdapter::Oidc(oidc) => json!({
            "provider_id": &provider.provider_id,
            "enabled": provider.enabled,
            "display_name": &provider.display_name,
            "adapter_type": provider.adapter_type(),
            "display_order": provider.display_order,
            "redirect_uri": &oidc.redirect_uri,
            "issuer": &oidc.issuer,
            "authorization_endpoint": &oidc.authorization_endpoint,
            "token_endpoint_configured": true,
            "jwks_url_configured": true,
            "userinfo_endpoint_configured": oidc.userinfo_endpoint.is_some(),
            "secret_configured": true,
        }),
        ExternalLoginProviderAdapter::Social(social) => json!({
            "provider_id": &provider.provider_id,
            "enabled": provider.enabled,
            "display_name": &provider.display_name,
            "adapter_type": provider.adapter_type(),
            "display_order": provider.display_order,
            "redirect_uri": &social.redirect_uri,
            "provider_kind": format!("{:?}", social.kind).to_ascii_lowercase(),
            "authorization_endpoint": &social.authorization_endpoint,
            "token_endpoint_configured": true,
            "userinfo_endpoint": &social.userinfo_endpoint,
            "openid_endpoint_configured": social.openid_endpoint.is_some(),
            "secret_configured": true,
        }),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/endpoints/admin/federation.rs"]
mod tests;
