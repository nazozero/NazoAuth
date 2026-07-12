//! 管理端客户端创建端点。
// confidential 客户端只在创建响应中返回一次明文 secret。
use crate::http::prelude::*;
use nazo_auth::ValidatedClientRegistration;

pub(crate) struct PreparedClientRegistration {
    pub(crate) tenant: nazo_identity::TenantContext,
    pub(crate) registration: ValidatedClientRegistration,
    pub(crate) issued_secret: Option<String>,
    pub(crate) client_secret_hash: Option<String>,
    pub(crate) registration_access_token_blake3: Option<String>,
}

impl std::fmt::Debug for PreparedClientRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedClientRegistration")
            .field("tenant", &self.tenant)
            .field("registration", &self.registration)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for PreparedClientRegistration {
    type Target = ValidatedClientRegistration;

    fn deref(&self) -> &Self::Target {
        &self.registration
    }
}

impl std::ops::DerefMut for PreparedClientRegistration {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.registration
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateClientRequest {
    pub(crate) client_name: String,
    pub(crate) client_type: String,
    pub(crate) redirect_uris: Vec<String>,
    #[serde(default)]
    pub(crate) post_logout_redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_audiences: Vec<String>,
    pub(crate) grant_types: Vec<String>,
    pub(crate) token_endpoint_auth_method: String,
    #[serde(default)]
    pub(crate) subject_type: Option<String>,
    #[serde(default)]
    pub(crate) sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub(crate) require_dpop_bound_tokens: bool,
    #[serde(default)]
    pub(crate) allow_client_assertion_audience_array: bool,
    #[serde(default)]
    pub(crate) allow_client_assertion_endpoint_audience: bool,
    #[serde(default)]
    pub(crate) require_par_request_object: bool,
    #[serde(default)]
    pub(crate) allow_authorization_code_without_pkce: bool,
    #[serde(default)]
    pub(crate) backchannel_logout_uri: Option<String>,
    #[serde(default = "default_backchannel_logout_session_required")]
    pub(crate) backchannel_logout_session_required: bool,
    #[serde(default)]
    pub(crate) frontchannel_logout_uri: Option<String>,
    #[serde(default = "default_frontchannel_logout_session_required")]
    pub(crate) frontchannel_logout_session_required: bool,
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
    pub(crate) jwks: Option<Value>,
    #[serde(default)]
    pub(crate) introspection_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub(crate) introspection_encrypted_response_enc: Option<String>,
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
    #[serde(default, skip_deserializing)]
    pub(crate) allow_jwks_without_kid: bool,
}

#[derive(Debug)]
pub(crate) enum InsertClientError {
    InvalidRequest(String),
    Server(String),
}

/// 创建 OAuth 客户端。
pub(crate) async fn admin_create_client(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<CreateClientRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }

    match insert_client_row(&state, payload).await {
        Ok((client, issued_secret)) => {
            audit_event(
                "client_created",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip(&req, &state.settings))),
                    ),
                ]),
            );
            let mut body = client_json(client);
            if let Some(secret) = issued_secret {
                body["client_secret"] = json!(secret);
            }
            json_response_status(StatusCode::CREATED, body)
        }
        Err(error) => insert_client_error_response(error),
    }
}

pub(crate) fn insert_client_error_response(error: InsertClientError) -> HttpResponse {
    match error {
        InsertClientError::InvalidRequest(message) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端创建失败: {message}"),
        ),
        InsertClientError::Server(message) => {
            tracing::warn!(%message, "failed to create oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端创建失败.",
            )
        }
    }
}

/// 插入客户端行，并在需要时生成一次性返回的 client_secret。
pub(crate) async fn insert_client_row(
    state: &AppState,
    payload: CreateClientRequest,
) -> Result<(ClientRow, Option<String>), InsertClientError> {
    let pairwise_subject_secret = state.settings.pairwise_subject_secret.clone();
    let response_signing_algorithms = state
        .keyset
        .snapshot()
        .response_signing_alg_values_supported();
    let prepared = prepare_client_insert_with_secret_pepper(
        payload,
        pairwise_subject_secret.as_deref(),
        &state.settings.client_secret_pepper,
        &state.settings.issuer,
        &response_signing_algorithms,
    )
    .await?;
    let issued_secret = prepared.issued_secret.clone();
    let client = insert_prepared_client_row(state, &prepared).await?;
    Ok((client, issued_secret))
}

pub(crate) async fn insert_prepared_client_row(
    state: &AppState,
    prepared: &PreparedClientRegistration,
) -> Result<ClientRow, InsertClientError> {
    let client = insert_prepared_client(&state.diesel_db, prepared)
        .await
        .map_err(|error| InsertClientError::Server(format!("客户端写入失败: {error}")))?;
    if client.tenant_id != prepared.tenant.tenant_id.as_uuid()
        || client.realm_id != prepared.tenant.realm_id.as_uuid()
        || client.organization_id != prepared.tenant.organization_id.as_uuid()
    {
        return Err(InsertClientError::Server(
            "客户端写入后租户边界不匹配".to_owned(),
        ));
    }
    Ok(client)
}

pub(crate) async fn prepare_client_insert_with_secret_pepper(
    payload: CreateClientRequest,
    pairwise_subject_secret: Option<&str>,
    client_secret_pepper: &str,
    issuer: &str,
    response_signing_algorithms: &[&'static str],
) -> Result<PreparedClientRegistration, InsertClientError> {
    validate_client_payload(&payload, response_signing_algorithms)
        .map_err(|error| InsertClientError::InvalidRequest(error.to_string()))?;
    let (issued_secret, secret_hash) = issue_client_secret(
        &payload.client_type,
        &payload.token_endpoint_auth_method,
        client_secret_pepper,
    );

    let subject_type = payload.subject_type.unwrap_or_else(|| "public".to_owned());
    let redirect_uris = payload.redirect_uris;
    let (sector_identifier_uri, sector_identifier_host) = validate_pairwise_subject(
        &subject_type,
        payload.sector_identifier_uri,
        &redirect_uris,
        pairwise_subject_secret,
        issuer,
    )
    .await?;

    Ok(PreparedClientRegistration {
        tenant: nazo_identity::TenantContext::default_system(),
        registration: ValidatedClientRegistration {
            client_id: format!("client-{}", Uuid::now_v7()),
            client_name: payload.client_name,
            client_type: payload.client_type,
            redirect_uris,
            post_logout_redirect_uris: trim_string_vec(payload.post_logout_redirect_uris),
            scopes: payload.scopes,
            allowed_audiences: payload.allowed_audiences,
            grant_types: payload.grant_types,
            token_endpoint_auth_method: payload.token_endpoint_auth_method,
            subject_type,
            sector_identifier_uri,
            sector_identifier_host,
            require_dpop_bound_tokens: payload.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: payload.allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience: payload
                .allow_client_assertion_endpoint_audience,
            require_par_request_object: payload.require_par_request_object,
            allow_authorization_code_without_pkce: payload.allow_authorization_code_without_pkce,
            backchannel_logout_uri: trim_optional_string(payload.backchannel_logout_uri),
            backchannel_logout_session_required: payload.backchannel_logout_session_required,
            frontchannel_logout_uri: trim_optional_string(payload.frontchannel_logout_uri),
            frontchannel_logout_session_required: payload.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: trim_optional_string(payload.tls_client_auth_subject_dn),
            tls_client_auth_cert_sha256: trim_optional_string(payload.tls_client_auth_cert_sha256),
            tls_client_auth_san_dns: trim_string_vec(payload.tls_client_auth_san_dns),
            tls_client_auth_san_uri: trim_string_vec(payload.tls_client_auth_san_uri),
            tls_client_auth_san_ip: trim_string_vec(payload.tls_client_auth_san_ip),
            tls_client_auth_san_email: trim_string_vec(payload.tls_client_auth_san_email),
            jwks: payload.jwks,
            introspection_encrypted_response_alg: trim_optional_string(
                payload.introspection_encrypted_response_alg,
            ),
            introspection_encrypted_response_enc: trim_optional_string(
                payload.introspection_encrypted_response_enc,
            ),
            userinfo_signed_response_alg: trim_optional_string(
                payload.userinfo_signed_response_alg,
            ),
            userinfo_encrypted_response_alg: trim_optional_string(
                payload.userinfo_encrypted_response_alg,
            ),
            userinfo_encrypted_response_enc: trim_optional_string(
                payload.userinfo_encrypted_response_enc,
            ),
            authorization_signed_response_alg: trim_optional_string(
                payload.authorization_signed_response_alg,
            ),
            authorization_encrypted_response_alg: trim_optional_string(
                payload.authorization_encrypted_response_alg,
            ),
            authorization_encrypted_response_enc: trim_optional_string(
                payload.authorization_encrypted_response_enc,
            ),
        },
        issued_secret,
        client_secret_hash: secret_hash,
        registration_access_token_blake3: None,
    })
}

pub(crate) fn issue_client_secret(
    client_type: &str,
    token_endpoint_auth_method: &str,
    client_secret_pepper: &str,
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
    let secret_hash = hash_client_secret(&secret, client_secret_pepper);
    (Some(secret), Some(secret_hash))
}

pub(crate) async fn insert_prepared_client(
    pool: &nazo_postgres::DbPool,
    prepared: &PreparedClientRegistration,
) -> Result<ClientRow, nazo_identity::ports::RepositoryError> {
    let client = ClientRow {
        id: Uuid::now_v7(),
        tenant_id: prepared.tenant.tenant_id.as_uuid(),
        realm_id: prepared.tenant.realm_id.as_uuid(),
        organization_id: prepared.tenant.organization_id.as_uuid(),
        registration: prepared.registration.clone(),
        require_mtls_bound_tokens: false,
        is_active: true,
    };
    nazo_postgres::OAuthClientRepository::new(pool.clone())
        .insert(
            &client,
            prepared.client_secret_hash.as_deref(),
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await
}

/// 校验客户端注册请求的协议约束。
fn validate_client_payload(
    payload: &CreateClientRequest,
    response_signing_algorithms: &[&'static str],
) -> anyhow::Result<()> {
    validate_pkce_compatibility_policy(
        payload.allow_authorization_code_without_pkce,
        &payload.client_type,
        payload.require_dpop_bound_tokens,
    )?;
    validate_client_metadata(ClientMetadata {
        client_type: &payload.client_type,
        redirect_uris: &payload.redirect_uris,
        post_logout_redirect_uris: &payload.post_logout_redirect_uris,
        scopes: &payload.scopes,
        allowed_audiences: &payload.allowed_audiences,
        grant_types: &payload.grant_types,
        token_endpoint_auth_method: &payload.token_endpoint_auth_method,
        backchannel_logout_uri: payload.backchannel_logout_uri.as_deref(),
        frontchannel_logout_uri: payload.frontchannel_logout_uri.as_deref(),
        jwks: payload.jwks.as_ref(),
        allow_jwks_without_kid: payload.allow_jwks_without_kid,
        introspection_encrypted_response_alg: payload
            .introspection_encrypted_response_alg
            .as_deref(),
        introspection_encrypted_response_enc: payload
            .introspection_encrypted_response_enc
            .as_deref(),
        userinfo_signed_response_alg: payload.userinfo_signed_response_alg.as_deref(),
        userinfo_encrypted_response_alg: payload.userinfo_encrypted_response_alg.as_deref(),
        userinfo_encrypted_response_enc: payload.userinfo_encrypted_response_enc.as_deref(),
        authorization_signed_response_alg: payload.authorization_signed_response_alg.as_deref(),
        authorization_encrypted_response_alg: payload
            .authorization_encrypted_response_alg
            .as_deref(),
        authorization_encrypted_response_enc: payload
            .authorization_encrypted_response_enc
            .as_deref(),
        response_signing_algorithms,
        mtls_binding: Some(&ClientMtlsMetadata {
            tls_client_auth_subject_dn: payload.tls_client_auth_subject_dn.clone(),
            tls_client_auth_cert_sha256: payload.tls_client_auth_cert_sha256.clone(),
            tls_client_auth_san_dns: payload.tls_client_auth_san_dns.clone(),
            tls_client_auth_san_uri: payload.tls_client_auth_san_uri.clone(),
            tls_client_auth_san_ip: payload.tls_client_auth_san_ip.clone(),
            tls_client_auth_san_email: payload.tls_client_auth_san_email.clone(),
        }),
    })
}

pub(crate) fn validate_pkce_compatibility_policy(
    allow_authorization_code_without_pkce: bool,
    client_type: &str,
    require_dpop_bound_tokens: bool,
) -> anyhow::Result<()> {
    if !allow_authorization_code_without_pkce {
        return Ok(());
    }
    if client_type != "confidential" {
        anyhow::bail!("PKCE compatibility exceptions are limited to confidential clients");
    }
    if require_dpop_bound_tokens {
        anyhow::bail!("DPoP-bound clients must use PKCE");
    }
    Ok(())
}

fn default_backchannel_logout_session_required() -> bool {
    true
}

fn default_frontchannel_logout_session_required() -> bool {
    true
}

pub(crate) fn trim_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(crate) fn trim_string_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

pub(crate) fn redirect_uri_host(uri: &str) -> Option<String> {
    url::Url::parse(uri)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
}

pub(crate) fn all_same_host(uris: &[String]) -> Option<String> {
    let mut hosts = uris.iter().filter_map(|u| redirect_uri_host(u));
    let first = hosts.next()?;
    if hosts.all(|h| h == first) {
        Some(first)
    } else {
        None
    }
}

pub(crate) fn sector_identifier_host_for_redirects(
    uri: &str,
    redirect_uris: &[String],
    sector_uris: &[String],
) -> anyhow::Result<String> {
    for redirect_uri in redirect_uris {
        if !sector_uris.contains(redirect_uri) {
            anyhow::bail!(
                "redirect_uri {} 不在 sector_identifier_uri 返回列表中",
                redirect_uri
            );
        }
    }
    sector_identifier_hostname(uri)
        .map_err(|error| anyhow::anyhow!("sector_identifier_uri host 解析失败: {:?}", error))
}

async fn validate_pairwise_subject(
    subject_type: &str,
    sector_identifier_uri: Option<String>,
    redirect_uris: &[String],
    pairwise_subject_secret: Option<&str>,
    _issuer: &str,
) -> Result<(Option<String>, Option<String>), InsertClientError> {
    if subject_type != "pairwise" {
        return Ok((None, None));
    }
    if pairwise_subject_secret.is_none() {
        return Err(InsertClientError::InvalidRequest(
            "pairwise 主题类型需要配置 PAIRWISE_SUBJECT_SECRET".to_owned(),
        ));
    }
    let sector_identifier_host = match sector_identifier_uri {
        Some(ref uri) => {
            let uris = fetch_sector_identifier_uris(uri).await.map_err(|error| {
                InsertClientError::InvalidRequest(format!(
                    "sector_identifier_uri 获取失败: {:?}",
                    error
                ))
            })?;
            sector_identifier_host_for_redirects(uri, redirect_uris, &uris)
                .map_err(|error| InsertClientError::InvalidRequest(error.to_string()))?
        }
        None => all_same_host(redirect_uris).ok_or_else(|| {
            InsertClientError::InvalidRequest(
                "pairwise 主题需要 sector_identifier_uri 或所有 redirect_uri 使用同一 host"
                    .to_owned(),
            )
        })?,
    };
    Ok((sector_identifier_uri, Some(sector_identifier_host)))
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/admin/clients/tests/create.rs"]
mod tests;
