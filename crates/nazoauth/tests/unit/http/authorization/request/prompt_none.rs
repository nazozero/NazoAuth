use super::endpoint::LiveAuthorizationFixture;
use super::*;
use crate::http::authorization::test_support::TestAuthorizationDependencies;
use crate::test_support::valkey::valkey_del;
use diesel::sql_query;
use diesel_async::RunQueryDsl;
use nazo_auth::{
    AuthorizationFuture, AuthorizationRateDimension, AuthorizationRepositoryPort,
    AuthorizationStateStorePort, ConsentPayload, GrantWrite, OAuthClient, StoredAuthorizationGrant,
};
use nazo_oauth_server::{
    authorization::{AuthorizationOutcome, AuthorizationRequestFacts},
    services::ServerAuthorizationService,
};
use nazo_postgres::{AuthorizationFlowRepository, create_pool, get_conn};
use nazo_valkey::test_support::par_storage_key;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy)]
pub(super) enum Fault {
    None,
    CodeWrite,
    ParMissing,
    ParMalformed,
    ParRead,
}
struct GrantFailureRepository {
    live: AuthorizationFlowRepository,
    failed: AuthorizationFlowRepository,
    reached: Arc<AtomicUsize>,
}
struct PromptNoneStore {
    live: nazo_valkey::AuthorizationStateAdapter,
    failed: nazo_valkey::AuthorizationStateAdapter,
    valkey: fred::prelude::Client,
    fault: Fault,
    reached: Arc<AtomicUsize>,
}
impl AuthorizationRepositoryPort for GrantFailureRepository {
    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        self.live.client_by_id(client_id)
    }
    fn mtls_trust_anchor_bundle(&self, client_id: Uuid) -> AuthorizationFuture<'_, String> {
        self.live.mtls_trust_anchor_bundle(client_id)
    }
    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<StoredAuthorizationGrant>> {
        self.reached.fetch_add(1, Ordering::SeqCst);
        self.failed.grant(user_id, client_id)
    }
    fn upsert_grant<'a>(&'a self, write: GrantWrite<'a>) -> AuthorizationFuture<'a, ()> {
        self.live.upsert_grant(write)
    }
    fn client_secret_salt<'a>(
        &'a self,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<String>> {
        self.live.client_secret_salt(client_id)
    }
    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        self.live
            .client_secret_digest_matches(client_id, candidate_digest)
    }
}

impl AuthorizationStateStorePort for PromptNoneStore {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        self.live.load_par(request_uri)
    }
    fn take_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<PushedAuthorizationRequest>> {
        Box::pin(async move {
            self.reached.fetch_add(1, Ordering::SeqCst);
            match self.fault {
                Fault::ParMissing => {
                    valkey_del(&self.valkey, par_storage_key(request_uri))
                        .await
                        .expect("remove PAR between validation and consumption");
                }
                Fault::ParMalformed => {
                    valkey_set_ex(
                        &self.valkey,
                        par_storage_key(request_uri),
                        "{not-json".to_owned(),
                        60,
                    )
                    .await
                    .expect("corrupt PAR between validation and consumption");
                }
                Fault::ParRead => return self.failed.take_par(request_uri).await,
                _ => {}
            }
            self.live.take_par(request_uri).await
        })
    }
    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a PushedAuthorizationRequest,
    ) -> AuthorizationFuture<'a, bool> {
        self.live.compare_and_delete_par(request_uri, expected)
    }
    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.live.store_par(request_uri, payload, ttl_seconds)
    }
    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.live.load_consent(request_id)
    }
    fn take_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<ConsentPayload>> {
        self.live.take_consent(request_id)
    }
    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a ConsentPayload,
    ) -> AuthorizationFuture<'a, bool> {
        self.live.compare_and_delete_consent(request_id, expected)
    }
    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.live.store_consent(request_id, payload, ttl_seconds)
    }
    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        if matches!(self.fault, Fault::CodeWrite) {
            self.reached.fetch_add(1, Ordering::SeqCst);
            self.failed
                .store_authorization_code(code_hash, state, ttl_seconds)
        } else {
            self.live
                .store_authorization_code(code_hash, state, ttl_seconds)
        }
    }
    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        self.live.delete_authorization_code(code_hash)
    }
    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        self.live.take_reauth_nonce(nonce)
    }
    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.live.store_reauth_nonce(nonce, started_at, ttl_seconds)
    }
    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.live.consume_jar(client_id, jti, ttl_seconds)
    }
    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.live
            .consume_private_key_jwt(client_id, jti, ttl_seconds)
    }
    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.live.consume_jwt_bearer(client_id, jti, ttl_seconds)
    }
    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.live
            .consume_ciba_request_object(client_id, jti, ttl_seconds)
    }
    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        self.live.consume_dpop(thumbprint, jti, ttl_seconds)
    }
    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        self.live.issue_dpop_nonce(nonce, ttl_seconds)
    }
    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        self.live.validate_dpop_nonce(nonce)
    }
    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        self.live.increment_rate(dimension, subject, window_seconds)
    }
}
fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

async fn exec_sql(state: &TestInfrastructure, sql: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
}

async fn create_isolated_schema(state: &TestInfrastructure, schema: &str, tables: &[&str]) {
    exec_sql(
        state,
        &format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema),
    )
    .await;
    for table in tables {
        exec_sql(
            state,
            &format!(
                r#"CREATE TABLE "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                schema, table, table
            ),
        )
        .await;
    }
}

async fn rename_column(
    state: &TestInfrastructure,
    schema: &str,
    table: &str,
    from: &str,
    to: &str,
) {
    exec_sql(
        state,
        &format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ),
    )
    .await;
}

async fn drop_schema(state: &TestInfrastructure, schema: &str) {
    exec_sql(
        state,
        &format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema),
    )
    .await;
}

fn redirect_query(response: &HttpResponse) -> std::collections::HashMap<String, String> {
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("authorization response should redirect")
        .to_str()
        .expect("Location should be valid UTF-8");
    url::Url::parse(location)
        .expect("Location should be absolute")
        .query_pairs()
        .into_owned()
        .collect()
}

pub(super) struct PromptNoneFixture {
    pub(super) live: LiveAuthorizationFixture,
    pub(super) dependencies: TestAuthorizationDependencies,
    pub(super) user_id: Uuid,
    pub(super) client_id: String,
    pub(super) sid: String,
    pub(super) q: HashMap<String, String>,
    pub(super) reached: Arc<AtomicUsize>,
}
impl PromptNoneFixture {
    pub(super) async fn new(
        fault: Fault,
        failed_database: Option<nazo_postgres::DbPool>,
    ) -> Option<Self> {
        let live = LiveAuthorizationFixture::new().await?;
        let suffix = Uuid::now_v7().simple().to_string();
        let user = live.create_user(&suffix, "user", 0).await;
        let client_id = format!("prompt-none-{suffix}");
        live.insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
        )
        .await;
        let sid = format!("prompt-none-session-{suffix}");
        live.store_session(&user, &sid, Utc::now().timestamp())
            .await;
        let repository =
            AuthorizationFlowRepository::new(live.state.diesel_db.clone(), DEFAULT_TENANT_ID);
        let client = repository
            .client_by_id(&client_id)
            .await
            .expect("client read")
            .expect("client exists");
        repository
            .upsert_grant(GrantWrite {
                tenant_id: DEFAULT_TENANT_ID,
                user_id: user.id,
                client_id: client.id,
                scopes: &["openid".to_owned(), "profile".to_owned()],
                resource_indicators: &[],
                authorization_details: &json!([]),
            })
            .await
            .expect("prior consent should persist");
        let mut dependencies = TestAuthorizationDependencies::new(&live.state);
        let reached = Arc::new(AtomicUsize::new(0));
        let connection = live.state.valkey_connection();
        let unavailable = TestInfrastructure {
            diesel_db: live.state.diesel_db.clone(),
            valkey: disconnected_valkey_client(),
            settings: live.state.settings.clone(),
            keyset: live.state.keyset.clone(),
        };
        let store: Arc<dyn AuthorizationStateStorePort> = Arc::new(PromptNoneStore {
            live: nazo_valkey::AuthorizationStateAdapter::new(&connection),
            failed: nazo_valkey::AuthorizationStateAdapter::new(&unavailable.valkey_connection()),
            valkey: live.state.valkey.clone(),
            fault,
            reached: reached.clone(),
        });
        dependencies.fixture.service = Arc::new(match failed_database {
            Some(database) => ServerAuthorizationService::new(
                GrantFailureRepository {
                    live: repository,
                    failed: AuthorizationFlowRepository::new(database, DEFAULT_TENANT_ID),
                    reached: reached.clone(),
                },
                store,
                live.state.keyset.clone(),
            ),
            None => ServerAuthorizationService::new(repository, store, live.state.keyset.clone()),
        });
        let q = HashMap::from([
            ("client_id".to_owned(), client_id.clone()),
            ("response_type".to_owned(), "code".to_owned()),
            (
                "redirect_uri".to_owned(),
                "https://client.example/callback".to_owned(),
            ),
            ("scope".to_owned(), "openid profile".to_owned()),
            ("prompt".to_owned(), "none".to_owned()),
            ("state".to_owned(), "opaque-state".to_owned()),
            ("nonce".to_owned(), "nonce-1".to_owned()),
            (
                "claims".to_owned(),
                json!({"id_token":{"name":null}}).to_string(),
            ),
            (
                "code_challenge".to_owned(),
                pkce_s256("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"),
            ),
            ("code_challenge_method".to_owned(), "S256".to_owned()),
        ]);
        Some(Self {
            live,
            dependencies,
            user_id: user.id,
            client_id,
            sid,
            q,
            reached,
        })
    }
    pub(super) async fn push(&mut self) -> String {
        let uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
        let now = Utc::now();
        let pushed = PushedAuthorizationRequest {
            client_id: self.client_id.clone(),
            params: self.q.clone(),
            dpop_jkt: None,
            mtls_x5t_s256: None,
            issued_at: now,
            expires_at: now + Duration::seconds(60),
        };
        self.dependencies
            .fixture
            .service
            .store_par(&uri, &pushed, 60)
            .await
            .expect("PAR stores");
        self.q = HashMap::from([
            ("client_id".to_owned(), self.client_id.clone()),
            ("request_uri".to_owned(), uri.clone()),
        ]);
        uri
    }
    pub(super) async fn authorize(&mut self) -> HttpResponse {
        let sid = nazo_identity::SessionId::new(self.sid.clone());
        let facts = AuthorizationRequestFacts {
            source_ip: "127.0.0.1",
            session_id: Some(&sid),
            user_agent: None,
        };
        match self
            .dependencies
            .fixture
            .application()
            .authorize(&facts, &mut self.q)
            .await
        {
            Ok(AuthorizationOutcome::Redirect { location }) => {
                nazo_http_actix::redirect_found(location)
            }
            Ok(AuthorizationOutcome::FormPost { .. }) => panic!("query response must redirect"),
            Err(error) => nazo_http_actix::oauth_endpoint_error_response(error),
        }
    }
}
async fn assert_storage_failure(response: HttpResponse) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_oauth_error_code(response).await.as_deref(),
        Some("server_error")
    );
}
#[actix_web::test]
async fn prompt_none_grant_lookup_fails_closed_when_database_connection_fails() {
    let failed = create_pool("postgres://invalid:invalid@127.0.0.1:1/nazo".to_owned(), 1)
        .expect("pool builds without connecting");
    let Some(mut fixture) = PromptNoneFixture::new(Fault::None, Some(failed)).await else {
        return;
    };
    let response = fixture.authorize().await;
    assert_storage_failure(response).await;
    assert_eq!(
        fixture.reached.as_ref().load(Ordering::SeqCst),
        1,
        "grant lookup must reach the failed database"
    );
}
#[actix_web::test]
async fn prompt_none_grant_lookup_fails_closed_when_query_fails() {
    let schema = format!(
        "prompt_none_grant_query_failure_{}",
        Uuid::now_v7().simple()
    );
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let failed = create_pool(database_url, 1).expect("isolated pool");
    let Some(mut fixture) = PromptNoneFixture::new(Fault::None, Some(failed)).await else {
        return;
    };
    create_isolated_schema(&fixture.live.state, &schema, &["user_client_grants"]).await;
    rename_column(
        &fixture.live.state,
        &schema,
        "user_client_grants",
        "last_scopes",
        "last_scopes_broken",
    )
    .await;
    let response = fixture.authorize().await;
    drop_schema(&fixture.live.state, &schema).await;
    assert_storage_failure(response).await;
    assert_eq!(
        fixture.reached.as_ref().load(Ordering::SeqCst),
        1,
        "grant lookup must reach the malformed schema"
    );
}
#[actix_web::test]
async fn prompt_none_issues_single_use_authorization_code_without_user_interaction() {
    let Some(mut fixture) = PromptNoneFixture::new(Fault::None, None).await else {
        return;
    };
    let response = fixture.authorize().await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let query = redirect_query(&response);
    let code = query.get("code").expect("prompt=none issues a code");
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        query.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(!query.contains_key("error"));
    let raw = valkey_get(&fixture.live.state.valkey, authorization_code_key(code))
        .await
        .expect("code readable")
        .expect("code exists");
    match serde_json::from_str::<AuthorizationCodeState>(&raw).expect("code deserializes") {
        AuthorizationCodeState::Pending { payload } => {
            assert_eq!(payload.user_id, fixture.user_id);
            assert_eq!(payload.client_id, fixture.client_id);
            assert_eq!(payload.scopes, vec!["openid", "profile"]);
            assert_eq!(payload.nonce.as_deref(), Some("nonce-1"));
            assert_eq!(payload.oidc_sid, Some(format!("oidc-{}", fixture.sid)));
            assert_eq!(payload.id_token_claims, vec!["name"]);
        }
        _ => panic!("prompt=none creates a pending code"),
    }
}
#[actix_web::test]
async fn prompt_none_consumes_valid_pushed_request_uri_before_issuing_code() {
    let Some(mut fixture) = PromptNoneFixture::new(Fault::None, None).await else {
        return;
    };
    let uri = fixture.push().await;
    let response = fixture.authorize().await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let query = redirect_query(&response);
    assert!(query.contains_key("code"));
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        valkey_get(&fixture.live.state.valkey, par_storage_key(&uri))
            .await
            .expect("PAR lookup"),
        None,
        "PAR consumed exactly once"
    );
    assert_eq!(fixture.reached.as_ref().load(Ordering::SeqCst), 1);
}
#[actix_web::test]
async fn prompt_none_fails_closed_when_authorization_code_cannot_be_persisted() {
    let Some(mut fixture) = PromptNoneFixture::new(Fault::CodeWrite, None).await else {
        return;
    };
    let response = fixture.authorize().await;
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "no redirect with unstored code"
    );
    assert_storage_failure(response).await;
    assert_eq!(
        fixture.reached.as_ref().load(Ordering::SeqCst),
        1,
        "code write must reach unavailable Valkey"
    );
}
async fn assert_par_consumption_failure(fault: Fault, expected_error: &str) {
    let Some(mut fixture) = PromptNoneFixture::new(fault, None).await else {
        return;
    };
    fixture.push().await;
    let response = fixture.authorize().await;
    let query = redirect_query(&response);
    assert_eq!(query.get("error").map(String::as_str), Some(expected_error));
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
    assert!(!query.contains_key("code"));
    assert_eq!(
        fixture.reached.as_ref().load(Ordering::SeqCst),
        1,
        "fault must occur at PAR consumption after successful validation"
    );
}
#[actix_web::test]
async fn prompt_none_redirects_invalid_request_uri_when_request_uri_is_missing() {
    assert_par_consumption_failure(Fault::ParMissing, "invalid_request_uri").await;
}
#[actix_web::test]
async fn prompt_none_redirects_server_error_when_request_uri_is_malformed() {
    assert_par_consumption_failure(Fault::ParMalformed, "server_error").await;
}
#[actix_web::test]
async fn prompt_none_redirects_server_error_when_request_uri_read_fails() {
    assert_par_consumption_failure(Fault::ParRead, "server_error").await;
}
