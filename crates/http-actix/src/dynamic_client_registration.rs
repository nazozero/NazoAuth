use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    FromRequest, HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Json, Path, Payload},
};
use chrono::Utc;
use nazo_auth::{
    AdminClientError, AdminClientPolicy, CreateClientRequest, DynamicClientRegistrationRequest,
    DynamicRegistrationError, DynamicRegistrationPolicy, OAuthClient, PreparedClientRegistration,
    parse_client_configuration_update, prepare_dynamic_client_registration,
    response_types_from_client,
};
use nazo_identity::TenantContext;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    authorization_error_response, empty_response, empty_response_no_store, json_response_no_store,
    json_response_status_no_store, oauth_bearer_error, oauth_error,
};

pub type DynamicRegistrationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DynamicRegistrationDependencyError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicRegistrationDependencyError {
    Unavailable,
}

pub trait DynamicRegistrationClientStore: Send + Sync {
    fn insert<'a>(
        &'a self,
        prepared: &'a PreparedClientRegistration,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<OAuthClient>>;

    fn has_client_secret(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, bool>;

    fn client_secret_salt(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, Option<String>>;

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool>;

    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_hash: Option<&'a str>,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn deactivate(&self, tenant_id: Uuid, client_id: Uuid) -> DynamicRegistrationFuture<'_, bool>;
}

pub trait DynamicRegistrationSecurity: Send + Sync {
    fn prepare_registration<'a>(
        &'a self,
        request: CreateClientRequest,
        policy: AdminClientPolicy,
        registration_access_token: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<PreparedClientRegistration, AdminClientError>> + Send + 'a>,
    >;

    fn random_token(&self) -> String;
    fn token_hash(&self, token: &str) -> String;
    fn issue_client_secret(&self, pepper: &str) -> (String, String);
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String;
    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicRegistrationRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

pub trait DynamicRegistrationRequestGuard: Send + Sync {
    fn accepts_new_requests(&self) -> bool;

    fn enforce_rate_limit<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>;

    fn audit(&self, event: &'static str, client: &OAuthClient, request: &HttpRequest);
}

#[derive(Clone)]
pub struct DynamicRegistrationEndpointConfig {
    pub issuer: String,
    pub default_audience: String,
    pub pairwise_subject_secret: Option<String>,
    pub client_secret_pepper: String,
    pub initial_access_token: Option<String>,
}

#[derive(Clone)]
pub struct DynamicRegistrationEndpoint {
    config: DynamicRegistrationEndpointConfig,
    clients: Arc<dyn DynamicRegistrationClientStore>,
    security: Arc<dyn DynamicRegistrationSecurity>,
    request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
}

impl DynamicRegistrationEndpoint {
    pub fn new(
        config: DynamicRegistrationEndpointConfig,
        clients: Arc<dyn DynamicRegistrationClientStore>,
        security: Arc<dyn DynamicRegistrationSecurity>,
        request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
    ) -> Self {
        Self {
            config,
            clients,
            security,
            request_guard,
        }
    }
}

pub async fn dynamic_client_registration(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    body: Payload,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) =
        match Json::<DynamicClientRegistrationRequest>::from_request(&request, &mut body).await {
            Ok(payload) => payload,
            Err(error) => return error.error_response(),
        };
    if let Err(response) = enforce_rate_limit(&endpoint, &request).await {
        return response;
    }
    if !initial_access_token_authorized(
        endpoint.security.as_ref(),
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        endpoint.config.initial_access_token.as_deref(),
    ) {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Initial access token is missing or invalid.",
        );
    }

    let prepared = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationPolicy {
            default_audience: &endpoint.config.default_audience,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = prepared.response_types.clone();
    let registration_access_token = endpoint.security.random_token();
    let prepared_insert =
        match prepare_insert(&endpoint, prepared, &registration_access_token).await {
            Ok(prepared) => prepared,
            Err(AdminClientError::InvalidRequest(message)) => {
                return dynamic_registration_error_response(map_insert_error(message));
            }
            Err(_error) => {
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Dynamic client registration failed.",
                );
            }
        };
    let issued_secret = prepared_insert.issued_secret.clone();
    match endpoint.clients.insert(&prepared_insert).await {
        Ok(client) => {
            endpoint
                .request_guard
                .audit("dynamic_client_registered", &client, &request);
            dynamic_registration_created_response(
                &client,
                &response_types,
                issued_secret,
                &endpoint.config.issuer,
                &registration_access_token,
            )
        }
        Err(_error) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Dynamic client registration failed.",
        ),
    }
}

pub async fn client_configuration_get(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_rate_limit(&endpoint, &request).await {
        return response;
    }
    let current = match authenticate_registration_client(&endpoint, &request, &path).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let response_types = response_types_from_client(&current);
    let registration_access_token = endpoint.security.random_token();
    let (issued_secret, client_secret_hash) = issue_client_secret(&endpoint, &current);
    let client = match endpoint
        .clients
        .rotate_credentials(
            current.tenant_id,
            current.id,
            client_secret_hash.as_deref(),
            &endpoint.security.token_hash(&registration_access_token),
        )
        .await
    {
        Ok(client) => client,
        Err(_error) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            );
        }
    };
    endpoint
        .request_guard
        .audit("dynamic_client_configuration_read", &client, &request);
    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &endpoint.config.issuer,
        &registration_access_token,
    ))
}

pub async fn client_configuration_put(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
    body: Payload,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) = match Json::<Value>::from_request(&request, &mut body).await {
        Ok(payload) => payload,
        Err(error) => return error.error_response(),
    };
    if let Err(response) = enforce_rate_limit(&endpoint, &request).await {
        return response;
    }
    let current = match authenticate_registration_client(&endpoint, &request, &path).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let has_secret = match endpoint.clients.has_client_secret(current.id).await {
        Ok(has_secret) => has_secret,
        Err(_error) => {
            return lookup_failed();
        }
    };
    let secret_matches = match submitted_secret_matches(&endpoint, &current, &payload).await {
        Ok(matches) => matches,
        Err(_error) => {
            return lookup_failed();
        }
    };
    let payload =
        match parse_client_configuration_update(payload, &current, has_secret, secret_matches) {
            Ok(payload) => payload,
            Err(error) => return dynamic_registration_error_response(error),
        };
    let registration = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationPolicy {
            default_audience: &endpoint.config.default_audience,
        },
    ) {
        Ok(registration) => registration,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = registration.response_types.clone();
    let registration_access_token = endpoint.security.random_token();
    let prepared = match prepare_insert(&endpoint, registration, &registration_access_token).await {
        Ok(prepared) => prepared,
        Err(AdminClientError::InvalidRequest(message)) => {
            return dynamic_registration_error_response(map_insert_error(message));
        }
        Err(_error) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            );
        }
    };
    let issued_secret = prepared.issued_secret.clone();
    let updated = OAuthClient {
        id: current.id,
        tenant_id: current.tenant_id,
        realm_id: current.realm_id,
        organization_id: current.organization_id,
        registration: prepared.registration.clone(),
        require_mtls_bound_tokens: current.require_mtls_bound_tokens,
        is_active: current.is_active,
    };
    let client = match endpoint
        .clients
        .replace_registration(
            &updated,
            prepared.client_secret_hash.as_deref(),
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await
    {
        Ok(client) => client,
        Err(_error) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            );
        }
    };
    endpoint
        .request_guard
        .audit("dynamic_client_configuration_updated", &client, &request);
    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &endpoint.config.issuer,
        &registration_access_token,
    ))
}

pub async fn client_configuration_delete(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_rate_limit(&endpoint, &request).await {
        return response;
    }
    let current = match authenticate_registration_client(&endpoint, &request, &path).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    match endpoint
        .clients
        .deactivate(current.tenant_id, current.id)
        .await
    {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client deletion failed.",
            );
        }
    }
    endpoint
        .request_guard
        .audit("dynamic_client_deleted", &current, &request);
    empty_response_no_store(StatusCode::NO_CONTENT)
}

async fn prepare_insert(
    endpoint: &DynamicRegistrationEndpoint,
    registration: nazo_auth::PreparedDynamicClientRegistration,
    registration_access_token: &str,
) -> Result<PreparedClientRegistration, AdminClientError> {
    let policy = AdminClientPolicy {
        tenant: TenantContext::default_system(),
        pairwise_subject_secret: endpoint.config.pairwise_subject_secret.clone(),
        client_secret_pepper: endpoint.config.client_secret_pepper.clone(),
    };
    endpoint
        .security
        .prepare_registration(
            registration.into_create_client_request(),
            policy,
            registration_access_token,
        )
        .await
}

async fn authenticate_registration_client(
    endpoint: &DynamicRegistrationEndpoint,
    request: &HttpRequest,
    client_id: &str,
) -> Result<OAuthClient, HttpResponse> {
    let Some(token) = bearer_token(request) else {
        return Err(registration_access_denied());
    };
    match endpoint
        .clients
        .by_registration_access_token(
            TenantContext::default_system().tenant_id.as_uuid(),
            client_id,
            &endpoint.security.token_hash(token),
        )
        .await
    {
        Ok(Some(client)) => Ok(client),
        Ok(None) => Err(registration_access_denied()),
        Err(_error) => Err(lookup_failed()),
    }
}

async fn submitted_secret_matches(
    endpoint: &DynamicRegistrationEndpoint,
    current: &OAuthClient,
    payload: &Value,
) -> Result<bool, DynamicRegistrationDependencyError> {
    let Some(secret) = payload.get("client_secret").and_then(Value::as_str) else {
        return Ok(false);
    };
    let Some(salt) = endpoint.clients.client_secret_salt(current.id).await? else {
        return Ok(false);
    };
    let candidate = endpoint.security.client_secret_digest(
        secret,
        &endpoint.config.client_secret_pepper,
        &salt,
    );
    endpoint
        .clients
        .client_secret_digest_matches(current.id, &candidate)
        .await
}

fn issue_client_secret(
    endpoint: &DynamicRegistrationEndpoint,
    client: &OAuthClient,
) -> (Option<String>, Option<String>) {
    if client.client_type != "confidential"
        || !matches!(
            client.token_endpoint_auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        )
    {
        return (None, None);
    }
    let (secret, digest) = endpoint
        .security
        .issue_client_secret(&endpoint.config.client_secret_pepper);
    (Some(secret), Some(digest))
}

async fn enforce_rate_limit(
    endpoint: &DynamicRegistrationEndpoint,
    request: &HttpRequest,
) -> Result<(), HttpResponse> {
    match endpoint.request_guard.enforce_rate_limit(request).await {
        Ok(()) => Ok(()),
        Err(DynamicRegistrationRateLimitError::Unavailable) => Err(oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        )),
        Err(DynamicRegistrationRateLimitError::Limited {
            retry_after_seconds,
        }) => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "请求过于频繁，请稍后重试.",
            );
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            Err(response)
        }
    }
}

fn initial_access_token_authorized(
    security: &dyn DynamicRegistrationSecurity,
    authorization_header: Option<&str>,
    expected_token: Option<&str>,
) -> bool {
    let Some(expected_token) = expected_token else {
        return false;
    };
    let Some(actual) = authorization_header.and_then(parse_bearer) else {
        return false;
    };
    security.constant_time_eq(actual.as_bytes(), expected_token.as_bytes())
}

fn bearer_token(request: &HttpRequest) -> Option<&str> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_bearer)
}

fn parse_bearer(value: &str) -> Option<&str> {
    value
        .trim()
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn registration_access_denied() -> HttpResponse {
    oauth_bearer_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Registration access token is missing or invalid.",
    )
}

fn lookup_failed() -> HttpResponse {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "Client configuration lookup failed.",
    )
}

fn map_insert_error(message: String) -> DynamicRegistrationError {
    let error = if message.contains("redirect_uri") {
        "invalid_redirect_uri"
    } else {
        "invalid_client_metadata"
    };
    DynamicRegistrationError::new(error, message)
}

fn dynamic_registration_error_response(error: DynamicRegistrationError) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, error.error, &error.description)
}

fn dynamic_registration_created_response(
    client: &OAuthClient,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
) -> HttpResponse {
    let mut body = dynamic_registration_response(
        client,
        response_types,
        issued_secret,
        issuer,
        registration_access_token,
    );
    body["client_id_issued_at"] = json!(Utc::now().timestamp());
    json_response_status_no_store(StatusCode::CREATED, body)
}

fn dynamic_registration_response(
    client: &OAuthClient,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
) -> Value {
    let mut body = json!({
        "client_id": client.client_id,
        "client_name": client.client_name,
        "registration_access_token": registration_access_token,
        "registration_client_uri": format!("{issuer}/register/{}", encode_path_segment(&client.client_id)),
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": response_types,
        "scope": client.scopes.join(" "),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "subject_type": client.subject_type,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "backchannel_logout_session_required": client.backchannel_logout_session_required,
        "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
    });
    if let Some(uri) = &client.backchannel_logout_uri {
        body["backchannel_logout_uri"] = json!(uri);
    }
    if let Some(uri) = &client.frontchannel_logout_uri {
        body["frontchannel_logout_uri"] = json!(uri);
    }
    if let Some(jwks) = &client.jwks {
        body["jwks"] = jwks.clone();
    }
    for (field, value) in [
        (
            "userinfo_signed_response_alg",
            client.userinfo_signed_response_alg.as_ref(),
        ),
        (
            "userinfo_encrypted_response_alg",
            client.userinfo_encrypted_response_alg.as_ref(),
        ),
        (
            "userinfo_encrypted_response_enc",
            client.userinfo_encrypted_response_enc.as_ref(),
        ),
        (
            "authorization_signed_response_alg",
            client.authorization_signed_response_alg.as_ref(),
        ),
        (
            "authorization_encrypted_response_alg",
            client.authorization_encrypted_response_alg.as_ref(),
        ),
        (
            "authorization_encrypted_response_enc",
            client.authorization_encrypted_response_enc.as_ref(),
        ),
    ] {
        if let Some(value) = value {
            body[field] = json!(value);
        }
    }
    if let Some(secret) = issued_secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    body
}

fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use actix_web::{App, http::header, test, web};
    use nazo_auth::{
        AdminClientCryptoPort, CreateClientRequest, SectorIdentifierFuture,
        SectorIdentifierResolverPort, ValidatedClientRegistration,
    };
    use serde_json::{Value, json};

    use super::*;

    #[derive(Clone)]
    struct FakeStore {
        client: Arc<Mutex<Option<OAuthClient>>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                client: Arc::new(Mutex::new(Some(client()))),
            }
        }
    }

    impl DynamicRegistrationClientStore for FakeStore {
        fn insert<'a>(
            &'a self,
            prepared: &'a PreparedClientRegistration,
        ) -> DynamicRegistrationFuture<'a, OAuthClient> {
            let inserted = OAuthClient {
                id: Uuid::now_v7(),
                tenant_id: prepared.tenant.tenant_id.as_uuid(),
                realm_id: prepared.tenant.realm_id.as_uuid(),
                organization_id: prepared.tenant.organization_id.as_uuid(),
                registration: prepared.registration.clone(),
                require_mtls_bound_tokens: false,
                is_active: true,
            };
            *self.client.lock().expect("client lock") = Some(inserted.clone());
            Box::pin(async move { Ok(inserted) })
        }

        fn by_registration_access_token<'a>(
            &'a self,
            _tenant_id: Uuid,
            client_id: &'a str,
            _token_hash: &'a str,
        ) -> DynamicRegistrationFuture<'a, Option<OAuthClient>> {
            let found = self
                .client
                .lock()
                .expect("client lock")
                .clone()
                .filter(|client| client.client_id == client_id);
            Box::pin(async move { Ok(found) })
        }

        fn has_client_secret(&self, _client_id: Uuid) -> DynamicRegistrationFuture<'_, bool> {
            Box::pin(async { Ok(true) })
        }

        fn client_secret_salt(
            &self,
            _client_id: Uuid,
        ) -> DynamicRegistrationFuture<'_, Option<String>> {
            Box::pin(async { Ok(Some("salt".to_owned())) })
        }

        fn client_secret_digest_matches<'a>(
            &'a self,
            _client_id: Uuid,
            candidate_digest: &'a str,
        ) -> DynamicRegistrationFuture<'a, bool> {
            let matches = candidate_digest == "digest:current-secret:pepper:salt";
            Box::pin(async move { Ok(matches) })
        }

        fn rotate_credentials<'a>(
            &'a self,
            _tenant_id: Uuid,
            _client_id: Uuid,
            _client_secret_hash: Option<&'a str>,
            _registration_access_token_hash: &'a str,
        ) -> DynamicRegistrationFuture<'a, OAuthClient> {
            let client = self.client.lock().expect("client lock").clone();
            Box::pin(async move { client.ok_or(DynamicRegistrationDependencyError::Unavailable) })
        }

        fn replace_registration<'a>(
            &'a self,
            client: &'a OAuthClient,
            _client_secret_hash: Option<&'a str>,
            _registration_access_token_hash: Option<&'a str>,
        ) -> DynamicRegistrationFuture<'a, OAuthClient> {
            *self.client.lock().expect("client lock") = Some(client.clone());
            Box::pin(async move { Ok(client.clone()) })
        }

        fn deactivate(
            &self,
            _tenant_id: Uuid,
            _client_id: Uuid,
        ) -> DynamicRegistrationFuture<'_, bool> {
            *self.client.lock().expect("client lock") = None;
            Box::pin(async { Ok(true) })
        }
    }

    #[derive(Clone, Copy)]
    struct FakeSecurity;

    impl SectorIdentifierResolverPort for FakeSecurity {
        fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    impl AdminClientCryptoPort for FakeSecurity {
        fn response_signing_algorithms(&self) -> Vec<String> {
            vec!["RS256".to_owned(), "PS256".to_owned()]
        }

        fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
            ("issued-secret".to_owned(), "stored-secret-hash".to_owned())
        }

        fn validate_jwks(&self, _jwks: &Value, _allow_missing_kid: bool) -> Result<(), String> {
            Ok(())
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

    impl DynamicRegistrationSecurity for FakeSecurity {
        fn prepare_registration<'a>(
            &'a self,
            request: CreateClientRequest,
            policy: AdminClientPolicy,
            registration_access_token: &'a str,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<PreparedClientRegistration, AdminClientError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let mut prepared =
                    nazo_auth::prepare_client_registration(request, &policy, self, self).await?;
                prepared.registration_access_token_blake3 =
                    Some(self.token_hash(registration_access_token));
                Ok(prepared)
            })
        }

        fn random_token(&self) -> String {
            "registration-token".to_owned()
        }

        fn token_hash(&self, token: &str) -> String {
            format!("token-hash:{token}")
        }

        fn issue_client_secret(&self, pepper: &str) -> (String, String) {
            <Self as AdminClientCryptoPort>::issue_client_secret(self, pepper)
        }

        fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
            format!("digest:{secret}:{pepper}:{salt}")
        }

        fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
            left == right
        }
    }

    #[derive(Clone)]
    struct FakeGuard {
        enabled: bool,
        rate_limit: Option<DynamicRegistrationRateLimitError>,
    }

    impl DynamicRegistrationRequestGuard for FakeGuard {
        fn accepts_new_requests(&self) -> bool {
            self.enabled
        }

        fn enforce_rate_limit<'a>(
            &'a self,
            _request: &'a HttpRequest,
        ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
        {
            let result = self.rate_limit.map_or(Ok(()), Err);
            Box::pin(async move { result })
        }

        fn audit(&self, _event: &'static str, _client: &OAuthClient, _request: &HttpRequest) {}
    }

    fn endpoint(enabled: bool) -> DynamicRegistrationEndpoint {
        DynamicRegistrationEndpoint::new(
            DynamicRegistrationEndpointConfig {
                issuer: "https://issuer.example".to_owned(),
                default_audience: "https://api.example".to_owned(),
                pairwise_subject_secret: None,
                client_secret_pepper: "pepper".to_owned(),
                initial_access_token: Some("initial-token".to_owned()),
            },
            Arc::new(FakeStore::new()),
            Arc::new(FakeSecurity),
            Arc::new(FakeGuard {
                enabled,
                rate_limit: None,
            }),
        )
    }

    fn configure(config: &mut web::ServiceConfig) {
        config.route("/register", web::post().to(dynamic_client_registration));
        config.service(
            web::resource("/register/{client_id}")
                .route(web::get().to(client_configuration_get))
                .route(web::put().to(client_configuration_put))
                .route(web::delete().to(client_configuration_delete)),
        );
    }

    #[actix_web::test]
    async fn disabled_module_rejects_every_method_before_body_or_credentials() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(false)))
                .configure(configure),
        )
        .await;
        for request in [
            test::TestRequest::post()
                .uri("/register")
                .set_payload("not-json")
                .to_request(),
            test::TestRequest::get()
                .uri("/register/client-test")
                .to_request(),
            test::TestRequest::put()
                .uri("/register/client-test")
                .set_payload("not-json")
                .to_request(),
            test::TestRequest::delete()
                .uri("/register/client-test")
                .to_request(),
        ] {
            let response = test::call_service(&service, request).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[actix_web::test]
    async fn registration_authentication_error_keeps_bearer_and_no_store_contract() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(true)))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/register")
                .set_json(json!({}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&header::HeaderValue::from_static(
                "Bearer error=\"invalid_token\", error_description=\"Initial access token is missing or invalid.\""
            ))
        );
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "invalid_token");
    }

    #[actix_web::test]
    async fn registration_and_management_methods_keep_wire_contracts() {
        let endpoint = endpoint(true);
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint))
                .configure(configure),
        )
        .await;
        let created = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/register")
                .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
                .set_json(json!({
                    "client_name": "Registered Client",
                    "redirect_uris": ["https://client.example/callback"]
                }))
                .to_request(),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(
            created.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
        let created: Value = test::read_body_json(created).await;
        let client_id = created["client_id"].as_str().expect("client id");
        assert_eq!(created["registration_access_token"], "registration-token");
        assert_eq!(created["client_secret"], "issued-secret");
        assert!(created["client_id_issued_at"].is_i64());
        assert_eq!(
            created["registration_client_uri"],
            format!("https://issuer.example/register/{client_id}")
        );

        let read = test::call_service(
            &service,
            test::TestRequest::get()
                .uri(&format!("/register/{client_id}"))
                .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
                .to_request(),
        )
        .await;
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(
            read.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );

        let update = test::call_service(
            &service,
            test::TestRequest::put()
                .uri(&format!("/register/{client_id}"))
                .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
                .set_json(json!({
                    "client_id": client_id,
                    "client_secret": "current-secret",
                    "client_name": "Updated Client",
                    "redirect_uris": ["https://client.example/callback"]
                }))
                .to_request(),
        )
        .await;
        assert_eq!(update.status(), StatusCode::OK);
        let updated: Value = test::read_body_json(update).await;
        assert_eq!(updated["client_name"], "Updated Client");
        let updated_client_id = updated["client_id"].as_str().expect("updated client id");

        let deleted = test::call_service(
            &service,
            test::TestRequest::delete()
                .uri(&format!("/register/{updated_client_id}"))
                .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
                .to_request(),
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            deleted.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
    }

    #[actix_web::test]
    async fn rate_limit_error_keeps_oauth_code_and_retry_after() {
        let mut endpoint = endpoint(true);
        endpoint.request_guard = Arc::new(FakeGuard {
            enabled: true,
            rate_limit: Some(DynamicRegistrationRateLimitError::Limited {
                retry_after_seconds: 30,
            }),
        });
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/register")
                .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
                .set_json(json!({}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "30");
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "temporarily_unavailable");
    }

    fn client() -> OAuthClient {
        OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            realm_id: Uuid::nil(),
            organization_id: Uuid::nil(),
            registration: ValidatedClientRegistration {
                client_id: "client-test".to_owned(),
                client_name: "Client".to_owned(),
                client_type: "confidential".to_owned(),
                redirect_uris: vec!["https://client.example/callback".to_owned()],
                post_logout_redirect_uris: Vec::new(),
                scopes: vec!["openid".to_owned()],
                allowed_audiences: vec!["https://api.example".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                token_endpoint_auth_method: "client_secret_basic".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier_uri: None,
                sector_identifier_host: None,
                require_dpop_bound_tokens: false,
                allow_client_assertion_audience_array: false,
                allow_client_assertion_endpoint_audience: false,
                require_par_request_object: false,
                allow_authorization_code_without_pkce: true,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                tls_client_auth_subject_dn: None,
                tls_client_auth_cert_sha256: None,
                tls_client_auth_san_dns: Vec::new(),
                tls_client_auth_san_uri: Vec::new(),
                tls_client_auth_san_ip: Vec::new(),
                tls_client_auth_san_email: Vec::new(),
                jwks: None,
                introspection_encrypted_response_alg: None,
                introspection_encrypted_response_enc: None,
                userinfo_signed_response_alg: None,
                userinfo_encrypted_response_alg: None,
                userinfo_encrypted_response_enc: None,
                authorization_signed_response_alg: None,
                authorization_encrypted_response_alg: None,
                authorization_encrypted_response_enc: None,
            },
            require_mtls_bound_tokens: false,
            is_active: true,
        }
    }
}
