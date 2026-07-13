#[cfg(not(test))]
use std::sync::Arc;

use actix_web::HttpRequest;
use chrono::{DateTime, Utc};
use nazo_auth::{
    BackchannelLogoutClaimsInput, BackchannelLogoutDelivery, OAuthClient,
    PendingBackchannelLogoutDelivery,
};
use nazo_key_management::KeyManager;
use nazo_postgres::{AuditRepository, OAuthClientRepository};
use uuid::Uuid;

#[cfg(not(test))]
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::Settings;
use crate::support::sessions::{CurrentSession, SessionHttpConfig, SessionProfileHandles};
use crate::support::{jwt_decoding_key_from_jwk, signing_algorithm_name};

#[derive(Clone)]
pub(crate) struct OidcLogoutConfig {
    issuer: Box<str>,
    pairwise_subject_secret: Option<Box<str>>,
}

impl From<&Settings> for OidcLogoutConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            issuer: settings.endpoint.issuer.as_str().into(),
            pairwise_subject_secret: settings
                .protocol
                .pairwise_subject_secret
                .as_deref()
                .map(Into::into),
        }
    }
}

/// OIDC logout dependencies assembled once at the composition root.
///
/// Transport code can resolve the current session and invoke logout operations,
/// but cannot obtain the database pool, Valkey connection, or complete settings.
#[derive(Clone)]
pub(crate) struct OidcLogoutHandles {
    sessions: SessionProfileHandles,
    clients: OAuthClientRepository,
    deliveries: AuditRepository,
    keys: KeyManager,
    config: OidcLogoutConfig,
    #[cfg(not(test))]
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    #[cfg(test)]
    frontchannel_logout_enabled: bool,
}

impl OidcLogoutHandles {
    #[cfg(not(test))]
    pub(crate) fn new(
        sessions: SessionProfileHandles,
        clients: OAuthClientRepository,
        deliveries: AuditRepository,
        keys: KeyManager,
        config: OidcLogoutConfig,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    ) -> Self {
        Self {
            sessions,
            clients,
            deliveries,
            keys,
            config,
            runtime_modules,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        sessions: SessionProfileHandles,
        clients: OAuthClientRepository,
        deliveries: AuditRepository,
        keys: KeyManager,
        config: OidcLogoutConfig,
        frontchannel_logout_enabled: bool,
    ) -> Self {
        Self {
            sessions,
            clients,
            deliveries,
            keys,
            config,
            frontchannel_logout_enabled,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_state(state: &super::AppState) -> Self {
        Self::new(
            SessionProfileHandles::from_test_state(state),
            OAuthClientRepository::new(state.diesel_db.clone()),
            AuditRepository::new(state.diesel_db.clone()),
            state.keyset.clone(),
            OidcLogoutConfig::from(state.settings.as_ref()),
            state.settings.modules.enable_frontchannel_logout,
        )
    }

    pub(crate) fn http_config(&self) -> &SessionHttpConfig {
        self.sessions.http_config()
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.config.issuer
    }

    pub(crate) fn pairwise_subject_secret(&self) -> Option<&str> {
        self.config.pairwise_subject_secret.as_deref()
    }

    pub(crate) fn has_valid_csrf_token(&self, req: &HttpRequest) -> bool {
        self.sessions.has_valid_csrf_token(req, None)
    }

    pub(crate) async fn current_session(
        &self,
        req: &HttpRequest,
    ) -> anyhow::Result<Option<CurrentSession>> {
        self.sessions.current_session(req).await
    }

    pub(crate) async fn delete_request_session(
        &self,
        req: &HttpRequest,
    ) -> Result<(), nazo_valkey::Error> {
        self.sessions.delete_request_session(req).await
    }

    #[cfg(not(test))]
    pub(crate) fn permits_existing_frontchannel_transaction(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.snapshot(),
            nazo_runtime_modules::ModuleId::FrontchannelLogout,
            nazo_auth::CapabilityAdmission::ExistingTransaction,
        )
    }

    #[cfg(test)]
    pub(crate) fn permits_existing_frontchannel_transaction(&self) -> bool {
        self.frontchannel_logout_enabled
    }

    pub(crate) fn decode_id_token_hint(&self, token: &str) -> Option<nazo_auth::IdTokenHintClaims> {
        let header = jsonwebtoken::decode_header(token).ok()?;
        if header.typ.as_deref().is_some_and(|typ| typ != "JWT")
            || signing_algorithm_name(header.alg).is_none()
        {
            return None;
        }
        let keyset = self.keys.snapshot();
        let verification_key = keyset.verification_key(header.kid.as_deref()?)?;
        let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)?;
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_aud = false;
        validation.set_issuer(&[self.issuer()]);
        jsonwebtoken::decode::<nazo_auth::IdTokenHintClaims>(token, &decoding_key, &validation)
            .ok()
            .map(|data| data.claims)
    }

    pub(crate) async fn logout_client(
        &self,
        client_id: &str,
        tenant_id: Uuid,
    ) -> Result<Option<OAuthClient>, nazo_identity::ports::RepositoryError> {
        self.clients.by_client_id(tenant_id, client_id).await
    }

    pub(crate) async fn active_clients_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OAuthClient>, nazo_identity::ports::RepositoryError> {
        self.clients.active_for_user(user_id).await
    }

    pub(crate) async fn sign_backchannel_logout_token(
        &self,
        client_id: &str,
        subject: Option<&str>,
        sid: Option<&str>,
        ttl: i64,
    ) -> jsonwebtoken::errors::Result<String> {
        let claims = nazo_auth::backchannel_logout_token_claims(
            self.issuer(),
            &BackchannelLogoutClaimsInput {
                client_id,
                subject,
                sid,
                ttl,
            },
            Utc::now().timestamp(),
        );
        let snapshot = self.keys.snapshot();
        let mut header = jsonwebtoken::Header::new(snapshot.active_alg);
        header.typ = Some("logout+jwt".to_owned());
        header.kid = Some(snapshot.active_kid.clone());
        self.keys
            .encode_jwt(
                nazo_auth::SigningPurpose::LogoutToken,
                &header,
                &serde_json::Value::Object(claims),
            )
            .await
    }

    pub(crate) async fn enqueue_backchannel_logout_batch(
        &self,
        deliveries: &[PendingBackchannelLogoutDelivery],
    ) -> Result<(), nazo_identity::ports::RepositoryError> {
        self.deliveries
            .enqueue_backchannel_logout_batch(deliveries)
            .await
    }

    pub(crate) async fn claim_due_backchannel_logout(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> Result<Vec<BackchannelLogoutDelivery>, nazo_identity::ports::RepositoryError> {
        self.deliveries
            .claim_due_backchannel_logout(limit, lock_timeout_seconds)
            .await
    }

    pub(crate) async fn complete_backchannel_logout(
        &self,
        delivery: &BackchannelLogoutDelivery,
    ) -> Result<(), nazo_identity::ports::RepositoryError> {
        self.deliveries
            .complete_backchannel_logout(delivery.id, delivery.attempts)
            .await
    }

    pub(crate) async fn fail_backchannel_logout(
        &self,
        delivery: &BackchannelLogoutDelivery,
        next_attempt_at: Option<DateTime<Utc>>,
        last_error: &str,
    ) -> Result<(), nazo_identity::ports::RepositoryError> {
        self.deliveries
            .fail_backchannel_logout(delivery.id, delivery.attempts, next_attempt_at, last_error)
            .await
    }
}
