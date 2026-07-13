//! 管理端 OAuth 客户端 handler 聚合模块。
// 列表、创建、详情和更新分别位于独立文件，便于按端点维护。
pub(crate) mod create;
pub(crate) mod detail;
pub(crate) mod list;
pub(crate) mod update;

use crate::settings::Settings;

#[derive(Clone)]
pub(crate) struct AdminClientConfig {
    issuer: Box<str>,
    pairwise_subject_secret: Option<Box<str>>,
    client_secret_pepper: Box<str>,
    client_ip: crate::support::client_ip::ClientIpConfig,
}

impl AdminClientConfig {
    pub(crate) fn from_settings(settings: &Settings) -> Self {
        let protocol = &settings.protocol;
        let endpoint = &settings.endpoint;
        Self {
            issuer: endpoint.issuer.as_str().into(),
            pairwise_subject_secret: protocol.pairwise_subject_secret.as_deref().map(Into::into),
            client_secret_pepper: protocol.client_secret_pepper.as_str().into(),
            client_ip: crate::support::client_ip::ClientIpConfig::new(
                &endpoint.trusted_proxy_cidrs,
                endpoint.client_ip_header_mode,
            ),
        }
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn pairwise_subject_secret(&self) -> Option<&str> {
        self.pairwise_subject_secret.as_deref()
    }

    pub(crate) fn client_secret_pepper(&self) -> &str {
        &self.client_secret_pepper
    }

    pub(crate) fn client_ip(&self) -> &crate::support::client_ip::ClientIpConfig {
        &self.client_ip
    }
}

pub(crate) use create::{
    CreateClientRequest, insert_client_error_response, prepare_client_insert_with_secret_pepper,
};

#[cfg(test)]
pub(crate) struct AdminClientTestDependencies {
    pub(crate) sessions: actix_web::web::Data<crate::support::sessions::AdminSessionHandles>,
    pub(crate) clients: actix_web::web::Data<nazo_postgres::OAuthClientRepository>,
    pub(crate) keyset: actix_web::web::Data<nazo_key_management::KeyManager>,
    pub(crate) config: actix_web::web::Data<AdminClientConfig>,
}

#[cfg(test)]
pub(crate) fn test_dependencies(
    state: &actix_web::web::Data<crate::domain::AppState>,
) -> AdminClientTestDependencies {
    let session = &state.settings.session;
    AdminClientTestDependencies {
        sessions: actix_web::web::Data::new(crate::support::sessions::AdminSessionHandles::new(
            nazo_valkey::SessionStore::new(&state.valkey_connection()),
            nazo_postgres::UserRepository::new(state.diesel_db.clone()),
            crate::support::sessions::SessionHttpConfig::new(
                &session.session_cookie_name,
                &session.csrf_cookie_name,
                session.cookie_secure,
            ),
        )),
        clients: actix_web::web::Data::new(nazo_postgres::OAuthClientRepository::new(
            state.diesel_db.clone(),
        )),
        keyset: actix_web::web::Data::new(state.keyset.clone()),
        config: actix_web::web::Data::new(AdminClientConfig::from_settings(&state.settings)),
    }
}
