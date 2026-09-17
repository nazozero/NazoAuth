use std::sync::{Arc, Mutex};

use actix_web::{
    http::{StatusCode, header},
    web::Data,
};
use nazo_http_actix::ClientIpHeaderMode;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct CasRegistrationStore {
    hash_after_authentication: Arc<Mutex<Option<String>>>,
    state: Arc<Mutex<(Option<nazo_auth::OAuthClient>, Option<String>)>>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl nazo_http_actix::DynamicRegistrationClientStore for CasRegistrationStore {
    fn insert<'a>(
        &'a self,
        prepared: &'a nazo_auth::PreparedClientRegistration,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        let client = nazo_auth::OAuthClient {
            id: uuid::Uuid::now_v7(),
            tenant_id: prepared.tenant.tenant_id.as_uuid(),
            realm_id: prepared.tenant.realm_id.as_uuid(),
            organization_id: prepared.tenant.organization_id.as_uuid(),
            registration: prepared.registration.clone(),
            require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
            is_active: true,
        };
        *self.state.lock().unwrap() = (
            Some(client.clone()),
            prepared.registration_access_token_blake3.clone(),
        );
        self.calls.lock().unwrap().push("insert");
        Box::pin(async move { Ok(client) })
    }

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: uuid::Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, Option<nazo_auth::OAuthClient>> {
        self.calls.lock().unwrap().push("lookup");
        let state = self.state.lock().unwrap();
        let found = state.0.clone().filter(|client| {
            client.tenant_id == tenant_id
                && client.client_id == client_id
                && client.is_active
                && state.1.as_deref() == Some(token_hash)
        });
        Box::pin(async move { Ok(found) })
    }

    fn has_client_secret(
        &self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'_, bool> {
        self.calls.lock().unwrap().push("has_secret");
        // Model a concurrent rotation after the handler authenticated its snapshot.
        if let Some(hash) = self.hash_after_authentication.lock().unwrap().take() {
            self.state.lock().unwrap().1 = Some(hash);
        }
        Box::pin(async { Ok(false) })
    }

    fn client_secret_salt(
        &self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'_, Option<String>> {
        Box::pin(async { Ok(None) })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
        _candidate_digest: &'a str,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    fn rotate_credentials<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
        _client_secret_hash: Option<&'a str>,
        _expected_registration_access_token_hash: &'a str,
        _new_registration_access_token_hash: &'a str,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        panic!("PUT must use replace_registration CAS")
    }

    fn replace_registration<'a>(
        &'a self,
        client: &'a nazo_auth::OAuthClient,
        _client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: Option<&'a str>,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        self.calls.lock().unwrap().push("replace_cas");
        let mut state = self.state.lock().unwrap();
        if !state.0.as_ref().is_some_and(|stored| {
            stored.tenant_id == client.tenant_id && stored.id == client.id && stored.is_active
        }) || state.1.as_deref() != Some(expected_registration_access_token_hash)
        {
            return Box::pin(async {
                Err(nazo_auth::DynamicRegistrationDependencyError::StaleCredentials)
            });
        }
        // PostgreSQL replaces metadata, then rereads the row with its stored identity.
        let stored = state.0.as_mut().unwrap();
        let client_id = stored.client_id.clone();
        stored.registration = client.registration.clone();
        stored.registration.client_id = client_id;
        stored.require_mtls_bound_tokens = client.require_mtls_bound_tokens;
        let updated = stored.clone();
        state.1 = new_registration_access_token_hash.map(str::to_owned);
        Box::pin(async move { Ok(updated) })
    }

    fn deactivate<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
        _expected_registration_access_token_hash: &'a str,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, bool> {
        panic!("DELETE must not run")
    }
}

#[derive(Clone, Default)]
struct RegistrationSecurity {
    issued: Arc<Mutex<u8>>,
}

impl nazo_auth::SectorIdentifierResolverPort for RegistrationSecurity {
    fn resolve<'a>(&'a self, _uri: &'a str) -> nazo_auth::SectorIdentifierFuture<'a> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksResolverPort
    for RegistrationSecurity
{
    fn resolve<'a>(
        &'a self,
        _uri: &'a str,
        _expected_kid: Option<&'a str>,
    ) -> nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksFuture<'a> {
        Box::pin(async { Ok(json!({"keys": []})) })
    }
}

impl nazo_auth::AdminClientCryptoPort for RegistrationSecurity {
    fn response_signing_algorithms(&self) -> Vec<String> {
        vec!["RS256".to_owned(), "PS256".to_owned()]
    }
    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        ("issued-secret".to_owned(), "stored-secret-hash".to_owned())
    }
    fn validate_jwks(&self, _jwks: &Value) -> Result<(), String> {
        Ok(())
    }
    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        (!value.trim().is_empty())
            .then_some(())
            .ok_or_else(|| "invalid DN".to_owned())
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

impl nazo_auth::DynamicRegistrationSecretPort for RegistrationSecurity {
    fn random_token(&self) -> String {
        let mut issued = self.issued.lock().unwrap();
        *issued += 1;
        format!("registration-token-{issued}")
    }
    fn token_hash(&self, token: &str) -> String {
        format!("token-hash:{token}")
    }
    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
        left == right
    }
}

impl nazo_auth::ClientSecretDigesterPort for RegistrationSecurity {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
        format!("digest:{secret}:{pepper}:{salt}")
    }
}

impl nazo_oauth_server::contracts::dynamic_client_registration::DynamicRegistrationRequestGuard
    for RegistrationSecurity
{
    fn accepts_new_requests(&self) -> bool {
        true
    }
    fn enforce_rate_limit<'a>(
        &'a self,
        _source_ip: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), nazo_oauth_server::contracts::dynamic_client_registration::DynamicRegistrationRateLimitError>,
                > + Send
                + 'a,
        >,
    >{
        Box::pin(async { Ok(()) })
    }
    fn audit(&self, _event: &'static str, _client: &nazo_auth::OAuthClient, _source_ip: &str) {}
}

fn cas_registration_endpoint(
    store: CasRegistrationStore,
    security: RegistrationSecurity,
) -> nazo_http_actix::DynamicRegistrationEndpoint {
    let application = Arc::new(nazo_oauth_server::domain::dynamic_registration::DynamicRegistrationApplication::new(
        nazo_oauth_server::domain::dynamic_registration::DynamicRegistrationConfig {
            tenant: nazo_identity::TenantContext::default_system(),
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
        },
        Arc::new(store),
        Arc::new(security.clone()),
        nazo_oauth_server::contracts::dynamic_client_registration::DynamicRegistrationSecurityServices::new(
            Arc::new(security.clone()),
            Arc::new(security.clone()),
            Arc::new(security.clone()),
            Arc::new(security.clone()),
        ),
        Arc::new(security),
    ));
    nazo_http_actix::DynamicRegistrationEndpoint::new(
        application,
        nazo_http_actix::ClientIpConfig::new(&[], ClientIpHeaderMode::None),
    )
}

#[actix_web::test]
async fn framework_boundary_transport_dcr_put_cas_revokes_old_registration_token() {
    use actix_web::{App, test, web};
    let store = CasRegistrationStore::default();
    let endpoint = cas_registration_endpoint(store.clone(), RegistrationSecurity::default());
    let app = test::init_service(
        App::new()
            .app_data(Data::new(endpoint))
            .route(
                "/register",
                web::post().to(nazo_http_actix::dynamic_client_registration),
            )
            .service(
                web::resource("/register/{client_id}")
                    .route(web::put().to(nazo_http_actix::client_configuration_put))
                    .route(web::get().to(nazo_http_actix::client_configuration_get)),
            ),
    )
    .await;
    let created = test::call_service(&app, test::TestRequest::post().uri("/register")
        .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
        .set_json(json!({"grant_types":["authorization_code"],"redirect_uris":["https://client.example/callback"],"scope":"profile"})).to_request()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body: Value = test::read_body_json(created).await;
    let client_id = created_body["client_id"].as_str().unwrap();
    let old_token = created_body["registration_access_token"].as_str().unwrap();
    let path = format!("/register/{client_id}");
    let identity = {
        let state = store.state.lock().unwrap();
        let client = state.0.as_ref().unwrap();
        (
            client.id,
            client.tenant_id,
            client.realm_id,
            client.organization_id,
        )
    };
    let updated = test::call_service(&app, test::TestRequest::put().uri(&path)
        .insert_header((header::AUTHORIZATION, format!("Bearer {old_token}")))
        .set_json(json!({"client_id":client_id,"client_name":"Updated Client","grant_types":["authorization_code"],"redirect_uris":["https://client.example/callback"],"scope":"profile"})).to_request()).await;
    assert_eq!(updated.status(), StatusCode::OK);
    let updated_body: Value = test::read_body_json(updated).await;
    let new_token = updated_body["registration_access_token"].as_str().unwrap();
    assert_ne!(new_token, old_token);
    assert_eq!(updated_body["client_id"], client_id);
    assert_eq!(updated_body["client_name"], "Updated Client");
    assert_eq!(
        updated_body["registration_client_uri"],
        format!("https://issuer.example{path}")
    );
    assert_eq!(
        store.state.lock().unwrap().0.as_ref().unwrap().client_id,
        client_id
    );
    assert_eq!(
        store
            .state
            .lock()
            .unwrap()
            .0
            .as_ref()
            .unwrap()
            .client_name
            .as_str(),
        "Updated Client"
    );
    assert_eq!(
        store.state.lock().unwrap().1.as_deref(),
        Some(format!("token-hash:{new_token}").as_str())
    );
    assert_eq!(
        store.state.lock().unwrap().0.as_ref().unwrap().tenant_id,
        nazo_identity::TenantContext::default_system()
            .tenant_id
            .as_uuid()
    );
    let stale = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&path)
            .insert_header((header::AUTHORIZATION, format!("Bearer {old_token}")))
            .to_request(),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        test::read_body(stale).await.as_ref(),
        br#"{"error":"invalid_token","error_description":"Registration access token is missing or invalid."}"#
    );
    let current = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&path)
            .insert_header((header::AUTHORIZATION, format!("Bearer {new_token}")))
            .to_request(),
    )
    .await;
    assert_eq!(current.status(), StatusCode::OK);
    let current_body: Value = test::read_body_json(current).await;
    assert_eq!(current_body["client_id"], client_id);
    assert_eq!(current_body["client_name"], "Updated Client");
    assert_eq!(current_body["registration_access_token"], new_token);
    {
        let state = store.state.lock().unwrap();
        let client = state.0.as_ref().unwrap();
        assert_eq!(
            (
                client.id,
                client.tenant_id,
                client.realm_id,
                client.organization_id
            ),
            identity
        );
    }
    let calls = store.calls.lock().unwrap();
    assert_eq!(
        calls.as_slice(),
        &[
            "insert",
            "lookup",
            "has_secret",
            "replace_cas",
            "lookup",
            "lookup"
        ]
    );
    assert_eq!(
        store.state.lock().unwrap().1.as_deref(),
        Some(format!("token-hash:{new_token}").as_str())
    );
}

#[actix_web::test]
async fn framework_boundary_transport_dcr_put_stale_cas_preserves_registration() {
    use actix_web::{App, test, web};
    let store = CasRegistrationStore::default();
    let app = test::init_service(
        App::new()
            .app_data(Data::new(cas_registration_endpoint(
                store.clone(),
                RegistrationSecurity::default(),
            )))
            .route(
                "/register",
                web::post().to(nazo_http_actix::dynamic_client_registration),
            )
            .route(
                "/register/{client_id}",
                web::put().to(nazo_http_actix::client_configuration_put),
            ),
    )
    .await;
    let created = test::call_service(&app, test::TestRequest::post().uri("/register")
        .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
        .set_json(json!({"client_name":"Original Client","grant_types":["authorization_code"],"redirect_uris":["https://client.example/callback"],"scope":"profile"})).to_request()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body: Value = test::read_body_json(created).await;
    let client_id = created_body["client_id"].as_str().unwrap();
    let old_token = created_body["registration_access_token"].as_str().unwrap();
    let before = format!("{:?}", store.state.lock().unwrap().0.as_ref().unwrap());
    let concurrent_hash = "token-hash:concurrently-rotated-token";
    *store.hash_after_authentication.lock().unwrap() = Some(concurrent_hash.to_owned());
    let rejected = test::call_service(&app, test::TestRequest::put().uri(&format!("/register/{client_id}"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {old_token}")))
        .set_json(json!({"client_id":client_id,"client_name":"Rejected Update","grant_types":["authorization_code"],"redirect_uris":["https://client.example/changed"],"scope":"profile"})).to_request()).await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(test::read_body(rejected).await.as_ref(), br#"{"error":"invalid_token","error_description":"Registration access token is missing or invalid."}"#);
    let state = store.state.lock().unwrap();
    assert_eq!(format!("{:?}", state.0.as_ref().unwrap()), before);
    assert_eq!(state.1.as_deref(), Some(concurrent_hash));
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        &["insert", "lookup", "has_secret", "replace_cas"]
    );
}
