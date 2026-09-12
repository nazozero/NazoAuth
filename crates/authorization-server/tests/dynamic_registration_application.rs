use futures_executor::block_on;
use http::StatusCode;
use nazo_auth::{
    AdminClientCryptoPort, ClientSecretDigesterPort, DynamicRegistrationClientStore,
    DynamicRegistrationDependencyError, DynamicRegistrationFuture, DynamicRegistrationSecretPort,
    OAuthClient, PreparedClientRegistration, RequestRateLimitBucket, RequestRateLimitError,
    RequestRateLimitFuture, RequestRateLimitPort, SectorIdentifierFuture,
    SectorIdentifierResolverPort,
};
use nazo_identity::TenantContext;
use nazo_oauth_server::{
    contracts::{
        dynamic_client_registration::{
            DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard,
            DynamicRegistrationSecurityServices, RemoteJwksFuture, RemoteJwksResolverPort,
        },
        oauth_error::OAuthEndpointError,
    },
    domain::dynamic_registration::{
        DynamicRegistrationApplication, DynamicRegistrationConfig, DynamicRegistrationResponse,
        DynamicRegistrationResult, ServerDynamicRegistrationRequestGuard,
        ServerDynamicRegistrationTokens,
    },
    ports::audit::{AuditFuture, SecurityAudit},
};
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision, SnapshotStore};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Copy)]
struct FakeSecurity;

impl SectorIdentifierResolverPort for FakeSecurity {
    fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl RemoteJwksResolverPort for FakeSecurity {
    fn resolve<'a>(
        &'a self,
        _uri: &'a str,
        _expected_kid: Option<&'a str>,
    ) -> RemoteJwksFuture<'a> {
        Box::pin(async { Ok(json!({"keys": []})) })
    }
}

impl AdminClientCryptoPort for FakeSecurity {
    fn response_signing_algorithms(&self) -> Vec<String> {
        vec!["RS256".to_owned(), "PS256".to_owned()]
    }

    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        static NEXT_SECRET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let secret = format!(
            "issued-secret-{}",
            NEXT_SECRET.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let hash = format!("stored:{secret}");
        (secret, hash)
    }

    fn validate_jwks(&self, _jwks: &Value) -> Result<(), String> {
        Ok(())
    }

    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        (!value.trim().is_empty() && value.contains('='))
            .then_some(())
            .ok_or_else(|| "invalid RFC 4514 DN".to_owned())
    }

    fn matching_encryption_key_count(&self, _jwks: &Value, _algorithm: &str) -> usize {
        1
    }

    fn contains_signing_key(&self, _jwks: &Value) -> bool {
        true
    }

    fn valid_self_signed_mtls_jwks(&self, _jwks: &Value) -> bool {
        true
    }
}

impl ClientSecretDigesterPort for FakeSecurity {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
        format!("digest:{secret}:{pepper}:{salt}")
    }
}

fn application_config() -> DynamicRegistrationConfig {
    DynamicRegistrationConfig {
        tenant: TenantContext::default_system(),
        issuer: "https://issuer.example".to_owned(),
        default_audience: "https://api.example".to_owned(),
        pairwise_subject_secret: None,
        client_secret_pepper: "pepper".to_owned(),
        initial_access_token: Some("initial-token".to_owned()),
        rate_limit_window_seconds: 60,
        rate_limit_max_requests: 100,
        id_token_signing_algs: vec!["RS256", "PS256"],
        response_signing_algs: vec!["RS256", "PS256"],
        request_object_encryption_algs: vec!["RSA-OAEP-256"],
        request_object_encryption_encs: vec!["A256GCM"],
    }
}

#[derive(Default)]
struct StoreState {
    client: Option<OAuthClient>,
    token_hash: String,
    secret_hash: Option<String>,
    stale_next_write: bool,
}

#[derive(Default)]
struct Store(Mutex<StoreState>);

impl DynamicRegistrationClientStore for Store {
    fn insert<'a>(
        &'a self,
        prepared: &'a PreparedClientRegistration,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            let client = OAuthClient {
                id: Uuid::now_v7(),
                tenant_id: prepared.tenant.tenant_id.as_uuid(),
                realm_id: prepared.tenant.realm_id.as_uuid(),
                organization_id: prepared.tenant.organization_id.as_uuid(),
                registration: prepared.registration.clone(),
                require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
                is_active: true,
            };
            let mut state = self.0.lock().unwrap();
            state.client = Some(client.clone());
            state.token_hash = prepared.registration_access_token_blake3.clone().unwrap();
            state.secret_hash = prepared.client_secret_hash.clone();
            Ok(client)
        })
    }
    fn by_registration_access_token<'a>(
        &'a self,
        tenant: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            let state = self.0.lock().unwrap();
            Ok(state.client.clone().filter(|client| {
                client.is_active
                    && client.tenant_id == tenant
                    && client.client_id == client_id
                    && state.token_hash == token_hash
            }))
        })
    }
    fn has_client_secret(&self, tenant: Uuid, id: Uuid) -> DynamicRegistrationFuture<'_, bool> {
        Box::pin(async move {
            let state = self.0.lock().unwrap();
            assert!(
                state
                    .client
                    .as_ref()
                    .is_some_and(|client| client.tenant_id == tenant && client.id == id)
            );
            Ok(state.secret_hash.is_some())
        })
    }
    fn client_secret_salt(
        &self,
        _tenant: Uuid,
        _id: Uuid,
    ) -> DynamicRegistrationFuture<'_, Option<String>> {
        Box::pin(async { Ok(Some("salt".to_owned())) })
    }
    fn client_secret_digest_matches<'a>(
        &'a self,
        _tenant: Uuid,
        _id: Uuid,
        digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        Box::pin(async move {
            let candidate = digest
                .strip_prefix("digest:")
                .and_then(|value| value.strip_suffix(":pepper:salt"))
                .map(|secret| format!("stored:{secret}"));
            Ok(candidate.is_some() && candidate == self.0.lock().unwrap().secret_hash)
        })
    }
    fn rotate_credentials<'a>(
        &'a self,
        _tenant: Uuid,
        _id: Uuid,
        _secret: Option<&'a str>,
        _expected: &'a str,
        _new: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async { panic!("configuration updates must use atomic replacement") })
    }
    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        secret: Option<&'a str>,
        expected: &'a str,
        new: Option<&'a str>,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            if std::mem::take(&mut state.stale_next_write) || state.token_hash != expected {
                return Err(DynamicRegistrationDependencyError::StaleCredentials);
            }
            let old = state.client.as_ref().unwrap();
            assert_eq!(
                (
                    client.id,
                    client.tenant_id,
                    client.realm_id,
                    client.organization_id,
                    client.is_active
                ),
                (
                    old.id,
                    old.tenant_id,
                    old.realm_id,
                    old.organization_id,
                    old.is_active
                )
            );
            assert_eq!(client.security_policy, old.security_policy);
            assert_ne!(new, Some(expected));
            // The repository replaces metadata and credentials, retaining the stored identity.
            let mut persisted = client.clone();
            persisted.registration.client_id = old.client_id.clone();
            state.client = Some(persisted.clone());
            state.token_hash = new.unwrap().to_owned();
            state.secret_hash = secret.map(str::to_owned);
            Ok(persisted)
        })
    }
    fn deactivate<'a>(
        &'a self,
        tenant: Uuid,
        id: Uuid,
        expected: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            if std::mem::take(&mut state.stale_next_write) || state.token_hash != expected {
                return Err(DynamicRegistrationDependencyError::StaleCredentials);
            }
            let client = state.client.as_mut().unwrap();
            assert_eq!((tenant, id), (client.tenant_id, client.id));
            client.is_active = false;
            Ok(true)
        })
    }
}

#[derive(Default)]
struct Guard {
    events: Mutex<Vec<&'static str>>,
    limit: Option<DynamicRegistrationRateLimitError>,
}
impl DynamicRegistrationRequestGuard for Guard {
    fn accepts_new_requests(&self) -> bool {
        true
    }
    fn enforce_rate_limit<'a>(
        &'a self,
        _ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
    {
        self.events.lock().unwrap().push("rate_limit");
        Box::pin(async move { self.limit.map_or(Ok(()), Err) })
    }
    fn audit(&self, event: &'static str, _client: &OAuthClient, _ip: &str) {
        self.events.lock().unwrap().push(event);
    }
}
fn application(store: Arc<Store>, guard: Arc<Guard>) -> DynamicRegistrationApplication {
    DynamicRegistrationApplication::new(
        application_config(),
        store,
        Arc::new(FakeSecurity),
        DynamicRegistrationSecurityServices::new(
            Arc::new(FakeSecurity),
            Arc::new(FakeSecurity),
            Arc::new(FakeSecurity),
            Arc::new(ServerDynamicRegistrationTokens),
        ),
        guard,
    )
}
async fn create(app: &DynamicRegistrationApplication) -> DynamicRegistrationResponse {
    let payload = serde_json::from_value(
        json!({"client_name":"Original", "redirect_uris":["https://client.example/callback"]}),
    )
    .unwrap();
    let DynamicRegistrationResult::Created(result) = app
        .create(payload, Some("initial-token"), "203.0.113.77")
        .await
        .unwrap()
    else {
        panic!("created result")
    };
    result
}
fn update_payload(client: &OAuthClient, secret: &str) -> Value {
    json!({"client_id":client.client_id, "client_secret":secret, "client_name":"Updated", "redirect_uris":["https://client.example/callback"]})
}
fn assert_denied(result: Result<DynamicRegistrationResult, OAuthEndpointError>) {
    assert!(
        matches!(result, Err(OAuthEndpointError::Bearer(fields)) if fields.status == StatusCode::UNAUTHORIZED && fields.error == "invalid_token")
    );
}

#[test]
fn application_create_read_update_delete_preserves_credentials_and_audit_order() {
    block_on(async {
        let store = Arc::new(Store::default());
        let guard = Arc::new(Guard::default());
        let app = application(store.clone(), guard.clone());
        let created = create(&app).await;
        let token = &created.registration_access_token;
        assert!(
            created
                .issued_secret
                .as_ref()
                .is_some_and(|secret| !secret.is_empty())
        );
        assert_eq!(
            store.0.lock().unwrap().token_hash,
            ServerDynamicRegistrationTokens.token_hash(token)
        );
        let DynamicRegistrationResult::Read(read) = app
            .read(&created.client.client_id, Some(token), "203.0.113.77")
            .await
            .unwrap()
        else {
            panic!("read result")
        };
        assert_eq!(&read.registration_access_token, token);
        assert!(read.issued_secret.is_none());
        let DynamicRegistrationResult::Updated(updated) = app
            .update(
                &created.client.client_id,
                update_payload(&created.client, created.issued_secret.as_deref().unwrap()),
                Some(token),
                "203.0.113.77",
            )
            .await
            .unwrap()
        else {
            panic!("updated result")
        };
        assert_eq!(updated.client.client_id, created.client.client_id);
        assert_eq!(updated.client.client_name, "Updated");
        assert_ne!(updated.issued_secret, created.issued_secret);
        assert_ne!(&updated.registration_access_token, token);
        assert_denied(
            app.read(&created.client.client_id, Some(token), "203.0.113.77")
                .await,
        );
        assert!(matches!(
            app.delete(
                &created.client.client_id,
                Some(&updated.registration_access_token),
                "203.0.113.77"
            )
            .await
            .unwrap(),
            DynamicRegistrationResult::Deleted
        ));
        assert_denied(
            app.read(
                &created.client.client_id,
                Some(&updated.registration_access_token),
                "203.0.113.77",
            )
            .await,
        );
        assert_eq!(
            *guard.events.lock().unwrap(),
            [
                "rate_limit",
                "dynamic_client_registered",
                "rate_limit",
                "dynamic_client_configuration_read",
                "rate_limit",
                "dynamic_client_configuration_updated",
                "rate_limit",
                "rate_limit",
                "dynamic_client_deleted",
                "rate_limit"
            ]
        );
    });
}

#[test]
fn stale_update_and_delete_fail_without_mutation_or_success_audit() {
    block_on(async {
        let store = Arc::new(Store::default());
        let guard = Arc::new(Guard::default());
        let app = application(store.clone(), guard.clone());
        let created = create(&app).await;
        let token = &created.registration_access_token;
        let old_hash = store.0.lock().unwrap().token_hash.clone();
        store.0.lock().unwrap().stale_next_write = true;
        assert_denied(
            app.update(
                &created.client.client_id,
                update_payload(&created.client, created.issued_secret.as_deref().unwrap()),
                Some(token),
                "203.0.113.77",
            )
            .await,
        );
        {
            let state = store.0.lock().unwrap();
            assert_eq!(state.client.as_ref().unwrap().client_name, "Original");
            assert_eq!(state.token_hash, old_hash);
            assert_eq!(
                state.secret_hash.as_deref(),
                Some(format!("stored:{}", created.issued_secret.as_ref().unwrap()).as_str())
            );
        }
        store.0.lock().unwrap().stale_next_write = true;
        assert_denied(
            app.delete(&created.client.client_id, Some(token), "203.0.113.77")
                .await,
        );
        assert!(store.0.lock().unwrap().client.as_ref().unwrap().is_active);
        assert_eq!(
            *guard.events.lock().unwrap(),
            [
                "rate_limit",
                "dynamic_client_registered",
                "rate_limit",
                "rate_limit"
            ]
        );
    });
}

#[test]
fn limiter_precedes_initial_token_and_metadata_validation() {
    block_on(async {
        let guard = Arc::new(Guard {
            limit: Some(DynamicRegistrationRateLimitError::Limited {
                retry_after_seconds: 37,
            }),
            ..Guard::default()
        });
        let store = Arc::new(Store::default());
        let app = application(store.clone(), guard.clone());
        let payload = serde_json::from_value(json!({})).unwrap();
        assert_eq!(
            app.create(payload, None, "203.0.113.77").await.unwrap_err(),
            OAuthEndpointError::RateLimited {
                retry_after_seconds: 37
            }
        );
        assert!(store.0.lock().unwrap().client.is_none());
        assert_eq!(*guard.events.lock().unwrap(), ["rate_limit"]);
    });
}

#[derive(Clone, Copy)]
struct FakeRateLimiter(Result<u64, RequestRateLimitError>);
impl RequestRateLimitPort for FakeRateLimiter {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        _subject: &'a str,
        window_seconds: u64,
    ) -> RequestRateLimitFuture<'a> {
        Box::pin(async move {
            assert_eq!(bucket, RequestRateLimitBucket::TokenManagement);
            assert_eq!(window_seconds, 37);
            self.0
        })
    }
}
#[derive(Default)]
struct Audit(Mutex<Vec<(String, Map<String, Value>)>>);
impl SecurityAudit for Audit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        Box::pin(async { Ok(()) })
    }
    fn record(&self, event: &str, fields: Map<String, Value>) {
        self.0.lock().unwrap().push((event.to_owned(), fields));
    }
    fn record_required<'a>(
        &'a self,
        event: &'a str,
        fields: Map<String, Value>,
    ) -> AuditFuture<'a> {
        Box::pin(async move {
            self.record(event, fields);
            Ok(())
        })
    }
}
fn server_guard(
    enabled: bool,
    result: Result<u64, RequestRateLimitError>,
) -> ServerDynamicRegistrationRequestGuard {
    let mut config = application_config();
    config.rate_limit_window_seconds = 37;
    config.rate_limit_max_requests = 1;
    let accepting = if enabled {
        BTreeSet::from([ModuleId::DynamicClientRegistration])
    } else {
        BTreeSet::new()
    };
    ServerDynamicRegistrationRequestGuard::new(
        Arc::new(FakeRateLimiter(result)),
        &config,
        Arc::new(SnapshotStore::new(ActiveModuleSnapshot {
            revision: ModuleRevision::new(1),
            accepting,
            draining: BTreeSet::new(),
        })),
        Arc::new(Audit::default()),
    )
}
#[test]
fn dynamic_registration_secret_port_hashes_and_compares_without_plaintext_reuse() {
    let secrets = ServerDynamicRegistrationTokens;
    let token = secrets.random_token();
    let hash = secrets.token_hash(&token);
    assert!(!token.is_empty());
    assert_ne!(hash, token);
    assert!(secrets.constant_time_eq(hash.as_bytes(), hash.as_bytes()));
    assert!(!secrets.constant_time_eq(hash.as_bytes(), token.as_bytes()));
}
#[test]
fn dynamic_registration_guard_fails_closed_for_unavailable_dependencies() {
    let guard = server_guard(true, Err(RequestRateLimitError));
    assert!(guard.accepts_new_requests());
    assert_eq!(
        block_on(guard.enforce_rate_limit("203.0.113.77")),
        Err(DynamicRegistrationRateLimitError::Unavailable)
    );
}
#[test]
fn dynamic_registration_guard_rejects_new_requests_when_module_is_disabled() {
    assert!(!server_guard(false, Ok(1)).accepts_new_requests());
}
#[test]
fn dynamic_registration_guard_preserves_fixed_window_threshold() {
    assert_eq!(
        block_on(server_guard(true, Ok(1)).enforce_rate_limit("203.0.113.77")),
        Ok(())
    );
    assert_eq!(
        block_on(server_guard(true, Ok(2)).enforce_rate_limit("203.0.113.77")),
        Err(DynamicRegistrationRateLimitError::Limited {
            retry_after_seconds: 37
        })
    );
}
