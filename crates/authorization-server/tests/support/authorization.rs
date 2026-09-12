//! Shared application-only authorization test dependencies.
//! Parent modules import the owning crate as `app` before mounting this file.
#![allow(dead_code)]

use super::app::{
    authorization::{AuthorizationApplication, config::AuthorizationConfig},
    contracts::dynamic_client_registration::{RemoteJwksFuture, RemoteJwksResolverPort},
    policy::{AuthorizationServerProfile, RequestObjectJtiPolicy},
    ports::{
        audit::{AuditFuture, SecurityAudit},
        remote_request_object::{RemoteRequestObjectResolverPort, RequestObjectFuture},
    },
    services::ServerAuthorizationService,
    sessions::SessionResolver,
};
use chrono::Utc;
use nazo_auth::{
    AuthorizationCodeState, AuthorizationFuture, AuthorizationPortError,
    AuthorizationRateDimension, AuthorizationRepositoryPort, AuthorizationStateStorePort,
    ConsentPayload, DpopNoncePolicy, GrantWrite, OAuthClient, PushedAuthorizationRequest,
    StoredAuthorizationGrant, ValidatedClientRegistration,
};
use nazo_identity::{
    AccountIdentity, Principal, PublicAccount, SessionId, TenantContext, TenantId, UserId,
    UserProfile, UserRole,
    ports::{RepositoryError, RepositoryFuture, SessionAccountPort, SessionStorePort},
    session::{SessionRecord, SessionSnapshot, SessionVersion},
};
use nazo_key_management::KeyManager;
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleRevision, SnapshotStore};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

pub struct RecordedAuthorizationCode {
    pub hash: String,
    pub state: AuthorizationCodeState,
    pub ttl_seconds: u64,
}

pub struct Ports {
    pub assertion_replay: Mutex<Option<Result<bool, AuthorizationPortError>>>,
    pub client_secret: Mutex<Option<(String, String)>>,
    pub par_rate: Mutex<Option<Result<u64, AuthorizationPortError>>>,
    pub par_write: Mutex<Option<Result<(), AuthorizationPortError>>>,
    pub stored_par: Mutex<Vec<(String, PushedAuthorizationRequest, u64)>>,
    pub record_code_writes: AtomicBool,
    pub stored_codes: Mutex<Vec<RecordedAuthorizationCode>>,
    client: Result<Option<OAuthClient>, AuthorizationPortError>,
    session: Result<Option<SessionSnapshot>, RepositoryError>,
    calls: Mutex<Vec<&'static str>>,
    pub reauth_nonces: Mutex<HashMap<String, i64>>,
    pub reauth_unavailable: AtomicBool,
    pub reauth_ttls: Mutex<Vec<u64>>,
    pub remote_jwks: Mutex<Result<Value, String>>,
}
impl Ports {
    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}
impl AuthorizationRepositoryPort for Ports {
    fn client_by_id<'a>(
        &'a self,
        _client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        self.record("client");
        Box::pin(async { self.client.clone() })
    }
    fn mtls_trust_anchor_bundle(&self, _client_id: Uuid) -> AuthorizationFuture<'_, String> {
        panic!("unexpected AuthorizationRepositoryPort::mtls_trust_anchor_bundle call")
    }
    fn grant<'a>(
        &'a self,
        _user_id: Uuid,
        _client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        panic!("unexpected AuthorizationRepositoryPort::grant call")
    }
    fn upsert_grant<'a>(&'a self, _write: GrantWrite<'a>) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationRepositoryPort::upsert_grant call")
    }
    fn client_secret_salt<'a>(
        &'a self,
        _client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<String>> {
        self.record("secret_salt");
        Box::pin(async {
            Ok(Some(
                self.client_secret
                    .lock()
                    .unwrap()
                    .as_ref()
                    .expect("secret lookup must be configured")
                    .0
                    .clone(),
            ))
        })
    }
    fn client_secret_digest_matches<'a>(
        &'a self,
        _client_id: Uuid,
        candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.record("secret_digest");
        Box::pin(async move {
            Ok(self
                .client_secret
                .lock()
                .unwrap()
                .as_ref()
                .expect("secret lookup must be configured")
                .1
                == candidate_digest)
        })
    }
}
impl AuthorizationStateStorePort for Ports {
    fn load_consent<'a>(
        &'a self,
        _request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.record("consent");
        Box::pin(async { Ok(None) })
    }
    fn load_par<'a>(
        &'a self,
        _request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        panic!("unexpected AuthorizationStateStorePort::load_par call")
    }
    fn take_par<'a>(
        &'a self,
        _request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        panic!("unexpected AuthorizationStateStorePort::take_par call")
    }
    fn compare_and_delete_par<'a>(
        &'a self,
        _request_uri: &'a str,
        _expected: &'a PushedAuthorizationRequest,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::compare_and_delete_par call")
    }
    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.record("store_par");
        Box::pin(async move {
            self.par_write
                .lock()
                .unwrap()
                .expect("unexpected PAR write")?;
            self.stored_par.lock().unwrap().push((
                request_uri.into(),
                payload.clone(),
                ttl_seconds,
            ));
            Ok(())
        })
    }
    fn take_consent<'a>(
        &'a self,
        _request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        panic!("unexpected AuthorizationStateStorePort::take_consent call")
    }
    fn compare_and_delete_consent<'a>(
        &'a self,
        _request_id: &'a str,
        _expected: &'a ConsentPayload,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::compare_and_delete_consent call")
    }
    fn store_consent<'a>(
        &'a self,
        _request_id: &'a str,
        _payload: &'a ConsentPayload,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::store_consent call")
    }
    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        assert!(
            self.record_code_writes.load(Ordering::SeqCst),
            "unexpected authorization code write"
        );
        self.record("store_authorization_code");
        Box::pin(async move {
            self.stored_codes
                .lock()
                .unwrap()
                .push(RecordedAuthorizationCode {
                    hash: code_hash.to_owned(),
                    state: state.clone(),
                    ttl_seconds,
                });
            Ok(())
        })
    }
    fn delete_authorization_code<'a>(&'a self, _code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::delete_authorization_code call")
    }
    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        self.record("take_reauth_nonce");
        Box::pin(async move {
            if self.reauth_unavailable.load(Ordering::SeqCst) {
                return Err(AuthorizationPortError::Unavailable);
            }
            Ok(self.reauth_nonces.lock().unwrap().remove(nonce))
        })
    }
    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.record("store_reauth_nonce");
        Box::pin(async move {
            if self.reauth_unavailable.load(Ordering::SeqCst) {
                return Err(AuthorizationPortError::Unavailable);
            }
            self.reauth_nonces
                .lock()
                .unwrap()
                .insert(nonce.into(), started_at);
            self.reauth_ttls.lock().unwrap().push(ttl_seconds);
            Ok(())
        })
    }
    fn consume_jar<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_jar call")
    }
    fn consume_private_key_jwt<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.record("assertion_replay");
        Box::pin(async {
            *self
                .assertion_replay
                .lock()
                .unwrap()
                .as_ref()
                .expect("replay must be configured")
        })
    }
    fn consume_jwt_bearer<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_jwt_bearer call")
    }
    fn consume_ciba_request_object<'a>(
        &'a self,
        _client_id: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_ciba_request_object call")
    }
    fn consume_dpop<'a>(
        &'a self,
        _thumbprint: &'a str,
        _jti: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::consume_dpop call")
    }
    fn issue_dpop_nonce<'a>(
        &'a self,
        _nonce: &'a str,
        _ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        panic!("unexpected AuthorizationStateStorePort::issue_dpop_nonce call")
    }
    fn validate_dpop_nonce<'a>(&'a self, _nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        panic!("unexpected AuthorizationStateStorePort::validate_dpop_nonce call")
    }
    fn increment_rate<'a>(
        &'a self,
        _dimension: AuthorizationRateDimension,
        _subject: &'a str,
        _window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        self.record("rate");
        Box::pin(async {
            self.par_rate
                .lock()
                .unwrap()
                .expect("unexpected PAR rate lookup")
        })
    }
}
impl SessionStorePort for Ports {
    fn load<'a>(
        &'a self,
        _session_id: &'a SessionId,
    ) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        self.record("session");
        Box::pin(async { self.session.clone() })
    }
    fn delete<'a>(
        &'a self,
        _session_id: &'a nazo_identity::session::SessionId,
    ) -> RepositoryFuture<'a, bool> {
        panic!("unexpected SessionStorePort::delete call")
    }
    fn rotate<'a>(
        &'a self,
        _old_session_id: &'a nazo_identity::session::SessionId,
        _expected: &'a nazo_identity::session::SessionSnapshot,
        _new_session_id: &'a nazo_identity::session::SessionId,
        _replacement: &'a nazo_identity::session::SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, nazo_identity::session::SessionRotationOutcome> {
        panic!("unexpected SessionStorePort::rotate call")
    }
    fn compare_and_set<'a>(
        &'a self,
        _session_id: &'a nazo_identity::session::SessionId,
        _expected: &'a nazo_identity::session::SessionSnapshot,
        _replacement: &'a nazo_identity::session::SessionRecord,
    ) -> RepositoryFuture<'a, nazo_identity::session::SessionUpdateOutcome> {
        panic!("unexpected SessionStorePort::compare_and_set call")
    }
}
impl SessionAccountPort for Ports {
    fn public_account_by_id(
        &self,
        _tenant: TenantId,
        _user: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        self.record("account");
        Box::pin(async { Ok(Some(account())) })
    }
}
impl SecurityAudit for Ports {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        Box::pin(async { Ok(()) })
    }
    fn record(&self, _event: &str, _fields: Map<String, Value>) {}
    fn record_required<'a>(
        &'a self,
        _event: &'a str,
        _fields: Map<String, Value>,
    ) -> AuditFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}
impl RemoteJwksResolverPort for Ports {
    fn resolve<'a>(&'a self, _uri: &'a str, _kid: Option<&'a str>) -> RemoteJwksFuture<'a> {
        self.record("remote_jwks");
        Box::pin(async { self.remote_jwks.lock().unwrap().clone() })
    }
}
impl RemoteRequestObjectResolverPort for Ports {
    fn resolve_request_object<'a>(&'a self, _uri: &'a str) -> RequestObjectFuture<'a> {
        panic!("test request must not resolve a remote request object")
    }
}

pub fn registration(client_id: &str) -> ValidatedClientRegistration {
    ValidatedClientRegistration {
        client_id: client_id.to_owned(),
        client_name: "Test client".to_owned(),
        client_type: "confidential".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: Vec::new(),
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "client_secret_post".to_owned(),
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        backchannel_token_delivery_mode: "poll".to_owned(),
        backchannel_client_notification_endpoint: None,
        backchannel_authentication_request_signing_alg: None,
        backchannel_user_code_parameter: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: Vec::new(),
        tls_client_auth_san_uri: Vec::new(),
        tls_client_auth_san_ip: Vec::new(),
        tls_client_auth_san_email: Vec::new(),
        jwks_uri: None,
        jwks: None,
        request_uris: Vec::new(),
        initiate_login_uri: None,
        presentation: nazo_auth::ClientPresentationMetadata::default(),
        id_token_signed_response_alg: None,
        id_token_encrypted_response_alg: None,
        id_token_encrypted_response_enc: None,
        request_object_signing_alg: None,
        request_object_encryption_alg: None,
        request_object_encryption_enc: None,
        token_endpoint_auth_signing_alg: None,
        introspection_signed_response_alg: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        security_policy: nazo_auth::ClientSecurityPolicy::default(),
    }
}

pub fn client(active: bool) -> OAuthClient {
    let tenant = TenantContext::default_system();
    OAuthClient {
        id: Uuid::from_u128(20),
        tenant_id: tenant.tenant_id.as_uuid(),
        realm_id: tenant.realm_id.as_uuid(),
        organization_id: tenant.organization_id.as_uuid(),
        registration: registration("client-1"),
        require_mtls_bound_tokens: false,
        is_active: active,
    }
}
pub fn account() -> PublicAccount {
    let now = Utc::now();
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::from_u128(10)).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "alice".into(),
            email: "alice@example.test".into(),
            email_verified: true,
            mfa_enabled: false,
        },
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
    }
}
pub fn session() -> SessionSnapshot {
    SessionSnapshot::new(
        SessionRecord::new(
            account().user_id(),
            Utc::now().timestamp(),
            vec!["pwd".into()],
            false,
            Some("oidc-session".into()),
        ),
        SessionVersion::from_storage(b"v1".to_vec().into_boxed_slice()),
    )
}
pub struct Fixture {
    pub service: Arc<ServerAuthorizationService>,
    pub config: AuthorizationConfig,
    pub sessions: Arc<SessionResolver>,
    pub snapshots: Arc<SnapshotStore>,
    pub ports: Arc<Ports>,
    pub keys: KeyManager,
    pub tenant_id: Uuid,
    pub audit: Arc<dyn SecurityAudit>,
    pub remote_client_documents: Arc<dyn RemoteJwksResolverPort>,
    pub request_object_resolver: Arc<dyn RemoteRequestObjectResolverPort>,
}
impl Fixture {
    pub fn new(
        client: Result<Option<OAuthClient>, AuthorizationPortError>,
        session: Result<Option<SessionSnapshot>, RepositoryError>,
    ) -> Self {
        let ports = Arc::new(Ports {
            assertion_replay: Mutex::new(None),
            client_secret: Mutex::new(None),
            par_rate: Mutex::new(None),
            par_write: Mutex::new(None),
            stored_par: Mutex::new(Vec::new()),
            record_code_writes: AtomicBool::new(false),
            stored_codes: Mutex::new(Vec::new()),
            client,
            session,
            calls: Mutex::new(Vec::new()),
            reauth_nonces: Mutex::new(HashMap::new()),
            reauth_unavailable: AtomicBool::new(false),
            reauth_ttls: Mutex::new(Vec::new()),
            remote_jwks: Mutex::new(Err("remote JWKS unavailable".into())),
        });
        let keys = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
        let service = Arc::new(ServerAuthorizationService::from_port(
            ports.clone(),
            ports.clone(),
            keys.clone(),
        ));
        let tenant = TenantContext::default_system().tenant_id;
        Self {
            service,
            config: AuthorizationConfig {
                issuer: "https://issuer.example".into(),
                mtls_endpoint_base_url: "https://mtls.issuer.example".into(),
                frontend_base_url: "https://frontend.example".into(),
                profile: AuthorizationServerProfile::Oauth2Baseline,
                dpop_nonce_policy: DpopNoncePolicy::Optional,
                request_object_jti_policy: RequestObjectJtiPolicy::Optional,
                auth_code_ttl_seconds: 300,
                par_ttl_seconds: 90,
                require_pushed_authorization_requests: false,
                client_secret_pepper: "test-pepper".into(),
                rate_limit_window_seconds: 60,
                token_management_max_requests: 10,
            },
            sessions: Arc::new(SessionResolver::new(ports.clone(), ports.clone(), tenant)),
            snapshots: Arc::new(SnapshotStore::new(ActiveModuleSnapshot {
                revision: ModuleRevision::new(1),
                accepting: BTreeSet::new(),
                draining: BTreeSet::new(),
            })),
            keys,
            tenant_id: tenant.as_uuid(),
            audit: ports.clone(),
            remote_client_documents: ports.clone(),
            request_object_resolver: ports.clone(),
            ports,
        }
    }
    pub fn with_algorithm(mut self, algorithm: jsonwebtoken::Algorithm) -> Self {
        self.keys = KeyManager::for_test(algorithm);
        self.service = Arc::new(ServerAuthorizationService::from_port(
            self.ports.clone(),
            self.ports.clone(),
            self.keys.clone(),
        ));
        self
    }
    pub fn make_application(&self) -> AuthorizationApplication {
        AuthorizationApplication::new(
            self.service.clone(),
            self.audit.clone(),
            Arc::new(self.config.clone()),
            self.sessions.clone(),
            self.snapshots.clone(),
            self.remote_client_documents.clone(),
            self.request_object_resolver.clone(),
            self.keys.clone(),
            self.tenant_id,
            None,
        )
    }
}
