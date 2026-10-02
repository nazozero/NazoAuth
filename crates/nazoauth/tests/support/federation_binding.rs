use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use actix_web::web::Data;
use nazo_identity::ports::{FederationStatePort, RepositoryError, RepositoryFuture};
use nazo_identity::{OidcFederationState, SocialFederationState};
use nazo_oauth_server::services::LocalFederationService;

#[derive(Default)]
pub(crate) struct UnavailableFederationStates {
    pub(crate) calls: AtomicUsize,
}

impl FederationStatePort for UnavailableFederationStates {
    fn store_oidc<'a>(
        &'a self,
        _state: &'a str,
        _value: &'a OidcFederationState,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn take_oidc<'a>(
        &'a self,
        _state: &'a str,
        _expected_browser_binding_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<OidcFederationState>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn store_social<'a>(
        &'a self,
        _state: &'a str,
        _value: &'a SocialFederationState,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn take_social<'a>(
        &'a self,
        _state: &'a str,
        _expected_browser_binding_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<SocialFederationState>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn reserve_saml_replay<'a>(
        &'a self,
        _signature: &'a str,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        panic!("browser-binding tests must not enter SAML");
    }
}

pub(crate) fn unavailable_federation_service(
    state: &super::TestInfrastructure,
) -> (
    Data<LocalFederationService>,
    Arc<UnavailableFederationStates>,
) {
    let states = Arc::new(UnavailableFederationStates::default());
    let service = LocalFederationService::new(
        nazo_postgres::FederationRepository::new(state.diesel_db.clone()),
        states.clone() as Arc<dyn FederationStatePort>,
        Arc::new(crate::bootstrap::FederationBootstrapPasswordHasher),
        Arc::new(nazo_valkey::SessionStore::new(&state.valkey_connection())),
        Arc::new(crate::bootstrap::TracingFederationAudit::new(Arc::new(
            crate::adapters::audit::TenantSecurityAudit::new(
                state.settings.tenant.context.tenant_id,
            ),
        ))),
        nazo_identity::FederationServiceConfig {
            tenant: state.settings.tenant.context,
            state_ttl_seconds: crate::http::auth::federation::FEDERATION_STATE_TTL_SECONDS,
            saml_replay_ttl_seconds: crate::http::auth::federation::SAML_REPLAY_TTL_SECONDS,
            session_ttl_seconds: state.settings.session.session_ttl_seconds,
        },
    );
    (Data::new(service), states)
}
