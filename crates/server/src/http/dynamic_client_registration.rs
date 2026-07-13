//! RFC 7591 dynamic client registration endpoint.
use nazo_http_actix::{
    empty_response, empty_response_no_store, json_response_no_store, json_response_status_no_store,
    oauth_bearer_error, oauth_error,
};

use crate::domain::{ClientRow, DynamicRegistrationHandles};
use crate::http::admin::clients::ServerSectorIdentifierResolver;
use crate::support::{
    DEFAULT_TENANT_ID, RateLimitPolicy, audit_event, audit_fields, blake3_hex,
    client_ip_with_context, client_secret_digest, constant_time_eq, enforce_rate_limit_with_store,
    hash_client_secret, json_array_to_strings, parse_scope, random_urlsafe_token,
};
use actix_web::http::StatusCode;
use actix_web::http::header;
#[cfg(test)]
use actix_web::http::header::HeaderValue;
use actix_web::web::{Data, Json, Payload};
use actix_web::{FromRequest, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use nazo_auth::{
    AdminClientCryptoPort, AdminClientError, AdminClientPolicy, CreateClientRequest,
    PreparedClientRegistration,
};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct DynamicClientRegistrationRequest {
    #[serde(default)]
    pub(crate) redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) response_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) application_type: Option<String>,
    #[serde(default)]
    pub(crate) client_name: Option<String>,
    #[serde(default)]
    pub(crate) scope: Option<String>,
    #[serde(default)]
    pub(crate) token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub(crate) subject_type: Option<String>,
    #[serde(default)]
    pub(crate) sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub(crate) post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub(crate) backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub(crate) backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub(crate) frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub(crate) frontchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub(crate) dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_dns: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_uri: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_ip: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_email: Vec<String>,
    #[serde(default)]
    pub(crate) jwks_uri: Option<String>,
    #[serde(default)]
    pub(crate) jwks: Option<Value>,
    #[serde(default)]
    pub(crate) userinfo_signed_response_alg: Option<String>,
    #[serde(default)]
    pub(crate) userinfo_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub(crate) userinfo_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub(crate) authorization_signed_response_alg: Option<String>,
    #[serde(default)]
    pub(crate) authorization_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub(crate) authorization_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub(crate) request_uris: Vec<String>,
    #[serde(default)]
    pub(crate) software_statement: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct DynamicRegistrationDefaults<'a> {
    pub(crate) default_audience: &'a str,
}

#[derive(Debug)]
pub(crate) struct PreparedDynamicClientRegistration {
    pub(crate) client_name: String,
    pub(crate) client_type: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) post_logout_redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_audiences: Vec<String>,
    pub(crate) grant_types: Vec<String>,
    pub(crate) response_types: Vec<String>,
    pub(crate) token_endpoint_auth_method: String,
    pub(crate) subject_type: Option<String>,
    pub(crate) sector_identifier_uri: Option<String>,
    pub(crate) require_dpop_bound_tokens: bool,
    pub(crate) backchannel_logout_uri: Option<String>,
    pub(crate) backchannel_logout_session_required: bool,
    pub(crate) frontchannel_logout_uri: Option<String>,
    pub(crate) frontchannel_logout_session_required: bool,
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    pub(crate) tls_client_auth_san_dns: Vec<String>,
    pub(crate) tls_client_auth_san_uri: Vec<String>,
    pub(crate) tls_client_auth_san_ip: Vec<String>,
    pub(crate) tls_client_auth_san_email: Vec<String>,
    pub(crate) jwks: Option<Value>,
    pub(crate) userinfo_signed_response_alg: Option<String>,
    pub(crate) userinfo_encrypted_response_alg: Option<String>,
    pub(crate) userinfo_encrypted_response_enc: Option<String>,
    pub(crate) authorization_signed_response_alg: Option<String>,
    pub(crate) authorization_encrypted_response_alg: Option<String>,
    pub(crate) authorization_encrypted_response_enc: Option<String>,
}

#[derive(Debug)]
pub(crate) struct DynamicRegistrationError {
    error: &'static str,
    description: String,
}

pub(crate) async fn dynamic_client_registration(
    handles: Data<DynamicRegistrationHandles>,
    req: HttpRequest,
    body: Payload,
) -> HttpResponse {
    if !handles.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) =
        match Json::<DynamicClientRegistrationRequest>::from_request(&req, &mut body).await {
            Ok(payload) => payload,
            Err(error) => return error.error_response(),
        };
    if let Err(response) = enforce_dynamic_registration_rate_limit(&handles, &req).await {
        return response;
    }
    if !initial_access_token_authorized(
        req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        handles.config.initial_access_token.as_deref(),
    ) {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Initial access token is missing or invalid.",
        );
    }

    let prepared = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationDefaults {
            default_audience: &handles.config.default_audience,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = prepared.response_types.clone();
    let registration_access_token = random_urlsafe_token();
    let response_signing_algorithms = handles
        .keyset
        .snapshot()
        .response_signing_alg_values_supported();
    match prepare_dynamic_client_insert_with_secret_pepper(
        prepared,
        handles.config.pairwise_subject_secret.as_deref(),
        &handles.config.client_secret_pepper,
        &handles.config.issuer,
        &registration_access_token,
        &response_signing_algorithms,
    )
    .await
    {
        Ok(prepared_insert) => {
            let issued_secret = prepared_insert.issued_secret.clone();
            match nazo_auth::insert_prepared_client(&handles.clients, &prepared_insert).await {
                Ok(client) => {
                    audit_dynamic_client_event(
                        "dynamic_client_registered",
                        &client,
                        &req,
                        &handles,
                    );
                    dynamic_registration_created_response(
                        &client,
                        &response_types,
                        issued_secret,
                        &handles.config.issuer,
                        &registration_access_token,
                        Utc::now(),
                    )
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to dynamically register oauth client");
                    oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "Dynamic client registration failed.",
                    )
                }
            }
        }
        Err(AdminClientError::InvalidRequest(message)) => {
            dynamic_registration_error_response(map_insert_error(message))
        }
        Err(error) => {
            tracing::warn!(%error, "failed to dynamically register oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Dynamic client registration failed.",
            )
        }
    }
}

pub(crate) async fn client_configuration_get(
    handles: Data<DynamicRegistrationHandles>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !handles.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_dynamic_registration_rate_limit(&handles, &req).await {
        return response;
    }

    let current = match authenticate_registration_client(&handles, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let response_types = response_types_from_client(&current);
    let registration_access_token = random_urlsafe_token();
    let (issued_secret, secret_hash) = issue_client_secret(
        &current.client_type,
        &current.token_endpoint_auth_method,
        &handles.config.client_secret_pepper,
    );
    let client = match rotate_client_management_credentials(
        &handles,
        &current,
        blake3_hex(&registration_access_token),
        secret_hash,
    )
    .await
    {
        Ok(client) => client,
        Err(response) => return response,
    };
    audit_dynamic_client_event("dynamic_client_configuration_read", &client, &req, &handles);

    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &handles.config.issuer,
        &registration_access_token,
    ))
}

pub(crate) async fn client_configuration_put(
    handles: Data<DynamicRegistrationHandles>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
    body: Payload,
) -> HttpResponse {
    if !handles.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) = match Json::<Value>::from_request(&req, &mut body).await {
        Ok(payload) => payload,
        Err(error) => return error.error_response(),
    };
    if let Err(response) = enforce_dynamic_registration_rate_limit(&handles, &req).await {
        return response;
    }

    let current = match authenticate_registration_client(&handles, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let repository = &handles.clients;
    let submitted_secret = payload.get("client_secret").and_then(Value::as_str);
    let has_secret = match repository.has_client_secret(current.id).await {
        Ok(has_secret) => has_secret,
        Err(error) => {
            tracing::warn!(%error, "failed to inspect dynamic client secret state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration lookup failed.",
            );
        }
    };
    let secret_matches = if let Some(secret) = submitted_secret {
        let candidate_match = match repository.client_secret_salt(current.id).await {
            Ok(Some(salt)) => {
                let candidate_digest =
                    client_secret_digest(secret, &handles.config.client_secret_pepper, &salt);
                repository
                    .client_secret_digest_matches(current.id, &candidate_digest)
                    .await
            }
            Ok(None) => Ok(false),
            Err(error) => Err(error),
        };
        match candidate_match {
            Ok(matches) => matches,
            Err(error) => {
                tracing::warn!(%error, "failed to verify dynamic client secret");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Client configuration lookup failed.",
                );
            }
        }
    } else {
        false
    };
    let payload =
        match parse_client_configuration_update(payload, &current, has_secret, secret_matches) {
            Ok(payload) => payload,
            Err(error) => return dynamic_registration_error_response(error),
        };
    let registration = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationDefaults {
            default_audience: &handles.config.default_audience,
        },
    ) {
        Ok(registration) => registration,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = registration.response_types.clone();
    let registration_access_token = random_urlsafe_token();
    let response_signing_algorithms = handles
        .keyset
        .snapshot()
        .response_signing_alg_values_supported();
    let prepared = match prepare_dynamic_client_insert_with_secret_pepper(
        registration,
        handles.config.pairwise_subject_secret.as_deref(),
        &handles.config.client_secret_pepper,
        &handles.config.issuer,
        &registration_access_token,
        &response_signing_algorithms,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return insert_error_to_management_response(error),
    };
    let issued_secret = prepared.issued_secret.clone();
    let client = match replace_client_configuration(&handles, &current, &prepared).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    audit_dynamic_client_event(
        "dynamic_client_configuration_updated",
        &client,
        &req,
        &handles,
    );

    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &handles.config.issuer,
        &registration_access_token,
    ))
}

pub(crate) async fn client_configuration_delete(
    handles: Data<DynamicRegistrationHandles>,
    req: HttpRequest,
    path: actix_web::web::Path<String>,
) -> HttpResponse {
    if !handles.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if let Err(response) = enforce_dynamic_registration_rate_limit(&handles, &req).await {
        return response;
    }

    let current = match authenticate_registration_client(&handles, &req, &path.into_inner()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    if let Err(response) = deactivate_dynamic_client(&handles, &current).await {
        return response;
    }
    audit_dynamic_client_event("dynamic_client_deleted", &current, &req, &handles);

    empty_response_no_store(StatusCode::NO_CONTENT)
}

pub(crate) async fn prepare_dynamic_client_insert_with_secret_pepper(
    registration: PreparedDynamicClientRegistration,
    pairwise_subject_secret: Option<&str>,
    client_secret_pepper: &str,
    issuer: &str,
    registration_access_token: &str,
    response_signing_algorithms: &[&'static str],
) -> Result<PreparedClientRegistration, AdminClientError> {
    let _ = issuer;
    let crypto = DynamicRegistrationCrypto {
        response_signing_algorithms,
    };
    let policy = AdminClientPolicy {
        tenant: nazo_identity::TenantContext::default_system(),
        pairwise_subject_secret: pairwise_subject_secret.map(ToOwned::to_owned),
        client_secret_pepper: client_secret_pepper.to_owned(),
    };
    let mut prepared = nazo_auth::prepare_client_registration(
        registration.into_create_client_request(),
        &policy,
        &ServerSectorIdentifierResolver,
        &crypto,
    )
    .await?;
    prepared.registration_access_token_blake3 = Some(blake3_hex(registration_access_token));
    Ok(prepared)
}

fn issue_client_secret(
    client_type: &str,
    token_endpoint_auth_method: &str,
    pepper: &str,
) -> (Option<String>, Option<String>) {
    if client_type != "confidential"
        || !matches!(
            token_endpoint_auth_method,
            "client_secret_basic" | "client_secret_post"
        )
    {
        return (None, None);
    }
    let secret = random_urlsafe_token();
    let digest = hash_client_secret(&secret, pepper);
    (Some(secret), Some(digest))
}

struct DynamicRegistrationCrypto<'a> {
    response_signing_algorithms: &'a [&'static str],
}

impl AdminClientCryptoPort for DynamicRegistrationCrypto<'_> {
    fn response_signing_algorithms(&self) -> Vec<String> {
        self.response_signing_algorithms
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    }

    fn issue_client_secret(&self, pepper: &str) -> (String, String) {
        let secret = random_urlsafe_token();
        let digest = hash_client_secret(&secret, pepper);
        (secret, digest)
    }

    fn validate_jwks(&self, jwks: &Value, allow_missing_kid: bool) -> Result<(), String> {
        crate::support::validate_client_jwks_with_missing_kid_policy(jwks, allow_missing_kid)
            .map_err(|error| error.to_string())
    }

    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
        crate::support::client_jwks_matching_encryption_key_count(jwks, algorithm)
    }

    fn contains_signing_key(&self, jwks: &Value) -> bool {
        crate::support::client_jwks_contains_signing_key(jwks)
    }

    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool {
        crate::support::validate_self_signed_mtls_jwks(jwks)
    }
}

async fn authenticate_registration_client(
    handles: &DynamicRegistrationHandles,
    req: &HttpRequest,
    client_id: &str,
) -> Result<ClientRow, HttpResponse> {
    let Some(token) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(registration_access_denied());
    };
    let found = handles
        .clients
        .by_registration_access_token(DEFAULT_TENANT_ID, client_id, &blake3_hex(token))
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query dynamic client configuration credentials");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration lookup failed.",
            )
        })?;
    let Some(client) = found else {
        return Err(registration_access_denied());
    };
    Ok(client)
}

fn registration_access_denied() -> HttpResponse {
    oauth_bearer_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Registration access token is missing or invalid.",
    )
}

async fn rotate_client_management_credentials(
    handles: &DynamicRegistrationHandles,
    current: &ClientRow,
    registration_access_token_hash: String,
    client_secret_hash: Option<String>,
) -> Result<ClientRow, HttpResponse> {
    handles.clients.rotate_credentials(
        current.tenant_id,
        current.id,
        client_secret_hash.as_deref(),
        &registration_access_token_hash,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, client_id = %current.client_id, "failed to rotate dynamic client management credentials");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client configuration update failed.",
        )
    })
}

async fn replace_client_configuration(
    handles: &DynamicRegistrationHandles,
    current: &ClientRow,
    prepared: &PreparedClientRegistration,
) -> Result<ClientRow, HttpResponse> {
    let updated = ClientRow {
        id: current.id,
        tenant_id: current.tenant_id,
        realm_id: current.realm_id,
        organization_id: current.organization_id,
        registration: prepared.registration.clone(),
        require_mtls_bound_tokens: current.require_mtls_bound_tokens,
        is_active: current.is_active,
    };
    handles.clients.replace_registration(
        &updated,
        prepared.client_secret_hash.as_deref(),
        prepared.registration_access_token_blake3.as_deref(),
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, client_id = %current.client_id, "failed to replace dynamic client configuration");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client configuration update failed.",
        )
    })
}

async fn deactivate_dynamic_client(
    handles: &DynamicRegistrationHandles,
    current: &ClientRow,
) -> Result<(), HttpResponse> {
    handles.clients.deactivate(current.tenant_id, current.id)
    .await
    .and_then(|changed| changed.then_some(()).ok_or(nazo_identity::ports::RepositoryError::NotFound))
    .map_err(|error| {
        tracing::warn!(%error, client_id = %current.client_id, "failed to delete dynamic client");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Client deletion failed.",
        )
    })?;
    Ok(())
}

fn insert_error_to_management_response(error: AdminClientError) -> HttpResponse {
    match error {
        AdminClientError::InvalidRequest(message) => {
            dynamic_registration_error_response(map_insert_error(message))
        }
        error => {
            tracing::warn!(%error, "failed to prepare dynamic client management response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            )
        }
    }
}

fn response_types_from_client(client: &ClientRow) -> Vec<String> {
    let grant_types = json_array_to_strings(&client.grant_types);
    if grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        vec!["code".to_owned()]
    } else {
        Vec::new()
    }
}

fn audit_dynamic_client_event(
    event: &str,
    client: &ClientRow,
    req: &HttpRequest,
    handles: &DynamicRegistrationHandles,
) {
    audit_event(
        event,
        dynamic_client_audit_fields(
            client,
            blake3_hex(&client_ip_with_context(
                req,
                handles.config.client_ip_header_mode,
                &handles.config.trusted_proxy_cidrs,
            )),
        ),
    );
}

async fn enforce_dynamic_registration_rate_limit(
    handles: &DynamicRegistrationHandles,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    enforce_rate_limit_with_store(
        &handles.rate_limits,
        req,
        RateLimitPolicy::TokenManagement,
        handles.config.rate_limit_window_seconds,
        handles.config.rate_limit_max_requests,
        handles.config.client_ip_header_mode,
        &handles.config.trusted_proxy_cidrs,
    )
    .await
}

fn dynamic_client_audit_fields(
    client: &ClientRow,
    source_ip_hash: String,
) -> serde_json::Map<String, Value> {
    audit_fields(&[
        ("client_id", json!(client.client_id)),
        ("client_type", json!(client.client_type)),
        (
            "grant_types",
            json!(json_array_to_strings(&client.grant_types)),
        ),
        (
            "token_endpoint_auth_method",
            json!(client.token_endpoint_auth_method),
        ),
        ("source_ip_hash", json!(source_ip_hash)),
    ])
}

pub(crate) fn prepare_dynamic_client_registration(
    request: DynamicClientRegistrationRequest,
    defaults: DynamicRegistrationDefaults<'_>,
) -> Result<PreparedDynamicClientRegistration, DynamicRegistrationError> {
    if request.software_statement.is_some() {
        return Err(DynamicRegistrationError::new(
            "invalid_software_statement",
            "software_statement is not supported by this registration endpoint.",
        ));
    }
    if request.jwks_uri.is_some() && request.jwks.is_some() {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "jwks_uri and jwks must not both be present.",
        ));
    }
    if request.jwks_uri.is_some() {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "jwks_uri is not supported; register jwks by value.",
        ));
    }
    validate_request_uris(&request.request_uris)?;
    if let Some(application_type) = request.application_type.as_deref()
        && !matches!(application_type, "web" | "native")
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "application_type must be web or native.",
        ));
    }

    let grant_types = request
        .grant_types
        .unwrap_or_else(default_dynamic_client_grant_types);
    let response_types = match request.response_types {
        Some(values) if values.is_empty() => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "response_types must not be empty.",
            ));
        }
        Some(values) => values,
        None if grant_types
            .iter()
            .any(|grant| grant == "authorization_code") =>
        {
            vec!["code".to_owned()]
        }
        None => Vec::new(),
    };
    validate_response_type_relationship(&grant_types, &response_types)?;

    let token_endpoint_auth_method = request
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_basic".to_owned());
    let client_type = if token_endpoint_auth_method == "none" {
        "public".to_owned()
    } else {
        "confidential".to_owned()
    };
    let scopes = request
        .scope
        .as_deref()
        .map(parse_scope)
        .unwrap_or_else(|| default_dynamic_client_scopes(&grant_types));
    let client_name = request
        .client_name
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Dynamic OAuth Client".to_owned());

    Ok(PreparedDynamicClientRegistration {
        client_name,
        client_type,
        redirect_uris: request.redirect_uris.unwrap_or_default(),
        post_logout_redirect_uris: request.post_logout_redirect_uris,
        scopes,
        allowed_audiences: vec![defaults.default_audience.to_owned()],
        grant_types,
        response_types,
        token_endpoint_auth_method,
        subject_type: request.subject_type,
        sector_identifier_uri: request.sector_identifier_uri,
        require_dpop_bound_tokens: request.dpop_bound_access_tokens,
        backchannel_logout_uri: request.backchannel_logout_uri,
        backchannel_logout_session_required: request
            .backchannel_logout_session_required
            .unwrap_or(true),
        frontchannel_logout_uri: request.frontchannel_logout_uri,
        frontchannel_logout_session_required: request
            .frontchannel_logout_session_required
            .unwrap_or(true),
        tls_client_auth_subject_dn: request.tls_client_auth_subject_dn,
        tls_client_auth_cert_sha256: request.tls_client_auth_cert_sha256,
        tls_client_auth_san_dns: request.tls_client_auth_san_dns,
        tls_client_auth_san_uri: request.tls_client_auth_san_uri,
        tls_client_auth_san_ip: request.tls_client_auth_san_ip,
        tls_client_auth_san_email: request.tls_client_auth_san_email,
        jwks: request.jwks,
        userinfo_signed_response_alg: request.userinfo_signed_response_alg,
        userinfo_encrypted_response_alg: request.userinfo_encrypted_response_alg,
        userinfo_encrypted_response_enc: request.userinfo_encrypted_response_enc,
        authorization_signed_response_alg: request.authorization_signed_response_alg,
        authorization_encrypted_response_alg: request.authorization_encrypted_response_alg,
        authorization_encrypted_response_enc: request.authorization_encrypted_response_enc,
    })
}

pub(crate) fn initial_access_token_authorized(
    authorization_header: Option<&str>,
    expected_token: Option<&str>,
) -> bool {
    let Some(expected_token) = expected_token else {
        return false;
    };
    let Some(actual) = authorization_header
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    constant_time_eq(actual.as_bytes(), expected_token.as_bytes())
}

#[cfg(test)]
pub(crate) fn registration_access_token_authorized(
    authorization_header: Option<&str>,
    stored_token_hash: Option<&str>,
) -> bool {
    let Some(stored_token_hash) = stored_token_hash else {
        return false;
    };
    let Some(actual) = authorization_header
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    let actual_hash = blake3_hex(actual);
    constant_time_eq(actual_hash.as_bytes(), stored_token_hash.as_bytes())
}

pub(crate) fn parse_client_configuration_update(
    mut payload: Value,
    current: &ClientRow,
    current_has_secret: bool,
    submitted_secret_matches: bool,
) -> Result<DynamicClientRegistrationRequest, DynamicRegistrationError> {
    let Some(object) = payload.as_object_mut() else {
        return Err(DynamicRegistrationError::new(
            "invalid_request",
            "Client configuration update body must be a JSON object.",
        ));
    };

    for field in [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
    ] {
        if object.contains_key(field) {
            return Err(DynamicRegistrationError::new(
                "invalid_request",
                format!("{field} is managed by the authorization server."),
            ));
        }
    }

    let client_id = object
        .remove("client_id")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            DynamicRegistrationError::invalid_client_metadata(
                "client_id must be present in a client configuration update.",
            )
        })?;
    if client_id != current.client_id {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "client_id must match the client configuration endpoint.",
        ));
    }

    let client_secret = object.remove("client_secret");
    match (current_has_secret, client_secret) {
        (true, Some(Value::String(_))) if submitted_secret_matches => {}
        (true, _) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "client_secret must match the current client secret.",
            ));
        }
        (false, Some(_)) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "public or assertion-based clients must not submit client_secret.",
            ));
        }
        (false, None) => {}
    }

    serde_json::from_value(payload).map_err(|error| {
        DynamicRegistrationError::invalid_client_metadata(format!(
            "Invalid client metadata: {error}"
        ))
    })
}

impl PreparedDynamicClientRegistration {
    fn to_create_client_request(&self) -> CreateClientRequest {
        let allow_authorization_code_without_pkce =
            self.client_type == "confidential" && !self.require_dpop_bound_tokens;
        CreateClientRequest {
            client_name: self.client_name.clone(),
            client_type: self.client_type.clone(),
            redirect_uris: self.redirect_uris.clone(),
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            scopes: self.scopes.clone(),
            allowed_audiences: self.allowed_audiences.clone(),
            grant_types: self.grant_types.clone(),
            token_endpoint_auth_method: self.token_endpoint_auth_method.clone(),
            subject_type: self.subject_type.clone(),
            sector_identifier_uri: self.sector_identifier_uri.clone(),
            require_dpop_bound_tokens: self.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce,
            backchannel_logout_uri: self.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            frontchannel_logout_uri: self.frontchannel_logout_uri.clone(),
            frontchannel_logout_session_required: self.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: self.tls_client_auth_subject_dn.clone(),
            tls_client_auth_cert_sha256: self.tls_client_auth_cert_sha256.clone(),
            tls_client_auth_san_dns: self.tls_client_auth_san_dns.clone(),
            tls_client_auth_san_uri: self.tls_client_auth_san_uri.clone(),
            tls_client_auth_san_ip: self.tls_client_auth_san_ip.clone(),
            tls_client_auth_san_email: self.tls_client_auth_san_email.clone(),
            jwks: self.jwks.clone(),
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: self.userinfo_signed_response_alg.clone(),
            userinfo_encrypted_response_alg: self.userinfo_encrypted_response_alg.clone(),
            userinfo_encrypted_response_enc: self.userinfo_encrypted_response_enc.clone(),
            authorization_signed_response_alg: self.authorization_signed_response_alg.clone(),
            authorization_encrypted_response_alg: self.authorization_encrypted_response_alg.clone(),
            authorization_encrypted_response_enc: self.authorization_encrypted_response_enc.clone(),
            allow_jwks_without_kid: true,
        }
    }

    fn into_create_client_request(self) -> CreateClientRequest {
        self.to_create_client_request()
    }
}

impl DynamicRegistrationError {
    fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }

    fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new("invalid_client_metadata", description)
    }
}

fn validate_response_type_relationship(
    grant_types: &[String],
    response_types: &[String],
) -> Result<(), DynamicRegistrationError> {
    for response_type in response_types {
        if response_type != "code" {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "only code response type is supported.",
            ));
        }
    }
    let has_code_grant = grant_types
        .iter()
        .any(|grant| grant == "authorization_code");
    let has_code_response = response_types.iter().any(|response| response == "code");
    if has_code_grant != has_code_response {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "authorization_code grant requires code response type.",
        ));
    }
    Ok(())
}

fn default_dynamic_client_scopes(grant_types: &[String]) -> Vec<String> {
    if !grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        return Vec::new();
    }
    let mut scopes = ["openid", "profile", "email", "address", "phone"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if grant_types.iter().any(|grant| grant == "refresh_token") {
        scopes.push("offline_access".to_owned());
    }
    scopes
}

fn default_dynamic_client_grant_types() -> Vec<String> {
    ["authorization_code", "refresh_token"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn validate_request_uris(request_uris: &[String]) -> Result<(), DynamicRegistrationError> {
    for request_uri in request_uris {
        let parsed = Url::parse(request_uri).map_err(|_| {
            DynamicRegistrationError::invalid_client_metadata(
                "request_uris values must be absolute HTTPS URLs.",
            )
        })?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "request_uris values must be absolute HTTPS URLs.",
            ));
        }
    }
    Ok(())
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
    client: &ClientRow,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
    issued_at: DateTime<Utc>,
) -> HttpResponse {
    let mut body = dynamic_registration_response(
        client,
        response_types,
        issued_secret,
        issuer,
        registration_access_token,
    );
    body["client_id_issued_at"] = json!(issued_at.timestamp());
    json_response_status_no_store(StatusCode::CREATED, body)
}

fn dynamic_registration_response(
    client: &ClientRow,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
) -> Value {
    let mut body = json!({
        "client_id": client.client_id,
        "client_name": client.client_name,
        "registration_access_token": registration_access_token,
        "registration_client_uri": registration_client_uri(issuer, &client.client_id),
        "redirect_uris": json_array_to_strings(&client.redirect_uris),
        "grant_types": json_array_to_strings(&client.grant_types),
        "response_types": response_types,
        "scope": json_array_to_strings(&client.scopes).join(" "),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "subject_type": client.subject_type,
        "post_logout_redirect_uris": json_array_to_strings(&client.post_logout_redirect_uris),
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

fn registration_client_uri(issuer: &str, client_id: &str) -> String {
    format!("{issuer}/register/{}", urlencoding::encode(client_id))
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/dynamic_client_registration.rs"]
mod tests;
