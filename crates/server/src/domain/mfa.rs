use crate::settings::Settings;
use crate::support::sessions::SessionProfileHandles;
use crate::support::{client_ip::ClientIpHeaderMode, client_ip::IpCidr};

#[derive(Clone)]
pub(crate) struct MfaProfileConfig {
    pub(crate) issuer: String,
    pub(crate) session_ttl_seconds: u64,
    pub(crate) rate_limit_window_seconds: u64,
    pub(crate) rate_limit_max_requests: u64,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
}

impl From<&Settings> for MfaProfileConfig {
    fn from(settings: &Settings) -> Self {
        let session = &settings.session;
        let identity = &settings.identity;
        let endpoint = &settings.endpoint;
        Self {
            issuer: endpoint.issuer.clone(),
            session_ttl_seconds: session.session_ttl_seconds,
            rate_limit_window_seconds: identity.rate_limit.window_seconds,
            rate_limit_max_requests: identity.rate_limit.auth_max_requests,
            client_ip_header_mode: endpoint.client_ip_header_mode,
            trusted_proxy_cidrs: endpoint.trusted_proxy_cidrs.to_vec(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct MfaProfileHandles {
    pub(crate) config: MfaProfileConfig,
    pub(crate) sessions: SessionProfileHandles,
    pub(crate) mfa: nazo_postgres::MfaRepository,
    pub(crate) rate_limits: nazo_valkey::RateLimitStore,
}

#[cfg(test)]
impl MfaProfileHandles {
    pub(crate) fn from_app_state(state: &super::AppState) -> Self {
        let session = &state.settings.session;
        let sessions = SessionProfileHandles::new(
            nazo_valkey::SessionStore::new(&state.valkey_connection()),
            nazo_postgres::UserRepository::new(state.diesel_db.clone()),
            crate::support::sessions::SessionHttpConfig::new(
                &session.session_cookie_name,
                &session.csrf_cookie_name,
                session.cookie_secure,
            ),
            &state.settings.endpoint.issuer,
            state.settings.modules.enable_session_management,
        );
        Self {
            config: MfaProfileConfig::from(state.settings.as_ref()),
            sessions,
            mfa: nazo_postgres::MfaRepository::new(state.diesel_db.clone()),
            rate_limits: nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
        }
    }
}
