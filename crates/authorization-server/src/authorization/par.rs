//! Pushed authorization request orchestration.
use super::{
    AuthorizationApplication, AuthorizationRequestContext, jar::apply_request_object_with_context,
};
use crate::{
    contracts::{
        oauth_error::OAuthEndpointError,
        request_facts::{DpopErrorContext, DpopRequestFacts},
        token_client_auth::TokenClientAuthTransportFacts,
    },
    crypto::random_urlsafe_token,
    domain::{
        oauth::PushedAuthorizationRequest,
        openid4vc::client_attestation::Openid4vcClientAttestationValidator, rows::ClientRow,
    },
    token::client_auth::{
        ClientAuthRequestFacts, TokenManagementClientAuthError,
        authenticate_client_with_dependencies,
        consume_token_management_client_assertion_with_authorization_service,
    },
};
use chrono::{Duration, Utc};
use http::StatusCode;
use nazo_auth::{
    DpopError, ExpandedParAdmissionPolicy, ParAdmissionError, PresentedClientCredentials,
    RawParAdmissionPolicy, is_valid_dpop_jkt, unverified_client_assertion_client_id,
    validate_expanded_par_admission, validate_raw_par_admission,
};
use serde_json::{Value, json};
use std::collections::HashMap;
const PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// One request snapshot, retained across adapter certificate extraction points.
pub struct ParPreparation<'a> {
    context: AuthorizationRequestContext<'a>,
}
pub struct PreparedParParameters<'a> {
    context: AuthorizationRequestContext<'a>,
    params: HashMap<String, String>,
    client_id: String,
}
pub struct PreparedParClient<'a> {
    context: AuthorizationRequestContext<'a>,
    params: HashMap<String, String>,
    client_id: String,
    client: ClientRow,
    credentials: PresentedClientCredentials,
}
pub struct ParRequestFacts<'a> {
    pub client_auth: ClientAuthRequestFacts,
    pub dpop: DpopRequestFacts<'a>,
    pub mtls_thumbprint: Option<String>,
    pub attestation: Option<(&'a str, &'a str)>,
}
impl AuthorizationApplication {
    pub async fn begin_par(
        &self,
        source_ip: &str,
    ) -> Result<ParPreparation<'_>, OAuthEndpointError> {
        let context = self.context();
        enforce_par_rate_limit(&context, source_ip).await?;
        Ok(ParPreparation { context })
    }
}
async fn enforce_par_rate_limit(
    context: &AuthorizationRequestContext<'_>,
    subject: &str,
) -> Result<(), OAuthEndpointError> {
    let count = context
        .service
        .increment_rate(subject, context.config.rate_limit_window_seconds)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "PAR rate limit increment failed");
            OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            )
        })?;
    if count > context.config.token_management_max_requests {
        return Err(OAuthEndpointError::RateLimited {
            retry_after_seconds: context.config.rate_limit_window_seconds,
        });
    }
    Ok(())
}

impl<'a> ParPreparation<'a> {
    pub fn prepare_parameters(
        self,
        mut params: HashMap<String, String>,
        has_basic: bool,
        attestation_headers: Option<(&str, &str)>,
    ) -> Result<PreparedParParameters<'a>, OAuthEndpointError> {
        let context = &self.context;
        let has_assertion =
            params.contains_key("client_assertion_type") || params.contains_key("client_assertion");
        if has_basic && (params.contains_key("client_secret") || has_assertion)
            || has_assertion && params.contains_key("client_secret")
            || attestation_headers.is_some()
                && (has_basic || has_assertion || params.contains_key("client_secret"))
        {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR 请求不能同时使用多种客户端认证方式.",
            ));
        }
        if !super::accepts_module(context, nazo_runtime_modules::ModuleId::RequestObjects)
            && params.contains_key("request")
        {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PAR request object 未启用.",
            ));
        }
        if !super::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::AuthorizationDetails,
        ) && params.contains_key("authorization_details")
        {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization_details 未启用.",
            ));
        }

        if !params.contains_key("client_id")
            && let Some(request_object) = params.get("request")
            && let Some(client_id) = super::jar::unverified_request_object_client_id(
                context.request_object_keys,
                request_object,
            )
        {
            params.insert("client_id".to_owned(), client_id);
        }
        if !params.contains_key("client_id")
        && let Some((attestation, _)) = attestation_headers
        && let Some(client_id) =
            crate::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator::unverified_client_id(attestation)
    {
        params.insert("client_id".to_owned(), client_id);
    }
        if !params.contains_key("client_id")
            && let Some(client_id) = params
                .get("client_assertion")
                .and_then(|assertion| unverified_client_assertion_client_id(assertion))
        {
            // This value is only a lookup hint. Client authentication below verifies
            // the assertion signature and binds its issuer/subject to the client.
            params.insert("client_id".to_owned(), client_id);
        }
        let Some(client_id) = params.get("client_id").cloned() else {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 client_id.",
            ));
        };
        Ok(PreparedParParameters {
            context: self.context,
            params,
            client_id,
        })
    }
}
impl<'a> PreparedParParameters<'a> {
    pub fn parameters(&self) -> &HashMap<String, String> {
        &self.params
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub async fn prepare_client(
        self,
        transport: &TokenClientAuthTransportFacts,
        mtls_present: bool,
        attestation_present: bool,
    ) -> Result<PreparedParClient<'a>, OAuthEndpointError> {
        let Self {
            context,
            params,
            client_id,
        } = self;
        let has_basic = transport.basic_challenge();
        let assertion_client_id = transport
            .client_assertion()
            .filter(|_| {
                transport.client_assertion_type()
                    == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            })
            .and_then(unverified_client_assertion_client_id);
        let mut credentials = transport
            .presented_credentials(assertion_client_id, mtls_present.then(|| client_id.clone()));
        if attestation_present {
            credentials = nazo_auth::PresentedClientCredentials {
                client_id: Some(client_id.clone()),
                client_secret: None,
                client_assertion: None,
                method: "attest_jwt_client_auth".to_owned(),
            };
        }
        if has_basic && credentials.method != "client_secret_basic" {
            return Err(OAuthEndpointError::json(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            ));
        }
        let client = match context.service.client_by_id(&client_id).await {
            Ok(Some(client)) if client.is_active => client,
            Ok(_) => {
                crate::token::client_auth::perform_dummy_client_secret_verification(
                    &credentials,
                    &context.config.client_secret_pepper,
                );
                return Err(OAuthEndpointError::json(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端认证失败.",
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "failed to query PAR client");
                return Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "客户端查询失败.",
                ));
            }
        };
        Ok(PreparedParClient {
            context,
            params,
            client_id,
            client,
            credentials,
        })
    }
}
impl PreparedParClient<'_> {
    pub async fn par(
        self,
        facts: ParRequestFacts<'_>,
        validator: Option<&Openid4vcClientAttestationValidator>,
    ) -> Result<Value, OAuthEndpointError> {
        let Self {
            context,
            mut params,
            client_id,
            mut client,
            credentials,
        } = self;
        let context = &context;
        let attestation_headers = facts.attestation;
        let client_policy = client.security_policy.clone();
        let fapi2_security = context.config.requires_fapi2_security(&client_policy);
        let par_ttl_seconds = if fapi2_security {
            context.config.par_ttl_seconds.min(599)
        } else {
            context.config.par_ttl_seconds
        };
        let auth_request = facts.client_auth;
        let client_assertion = if let Some((attestation, proof)) = attestation_headers {
            if client.token_endpoint_auth_method != "attest_jwt_client_auth" {
                return Err(OAuthEndpointError::json(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation is not registered for this client.",
                ));
            }
            let Some(validator) = validator else {
                return Err(OAuthEndpointError::json(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation is not configured.",
                ));
            };
            let validated = match validator
                .validate_for_client(
                    attestation,
                    proof,
                    &context.config.issuer,
                    Utc::now().timestamp(),
                )
                .await
            {
                Ok(validated) if validated.client_id == client.client_id => validated,
                _ => {
                    return Err(OAuthEndpointError::json(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client_attestation",
                        "Client attestation validation failed.",
                    ));
                }
            };
            let replay_key = format!("client-attestation:{}", validated.client_id);
            match context
                .service
                .consume_private_key_jwt(
                    &replay_key,
                    &validated.replay_id,
                    validated.replay_ttl_seconds,
                )
                .await
            {
                Ok(true) => None,
                Ok(false) => {
                    return Err(OAuthEndpointError::json(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client_attestation",
                        "Client attestation proof was replayed.",
                    ));
                }
                Err(_) => {
                    return Err(OAuthEndpointError::json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "Client attestation replay state is unavailable.",
                    ));
                }
            }
        } else {
            match authenticate_client_with_dependencies(
                context.service,
                crate::token::client_auth::ClientAuthConfig::new(
                    &context.config.issuer,
                    &context.config.client_secret_pepper,
                    context.remote_client_documents,
                    context.security_audit,
                ),
                &auth_request,
                &mut client,
                &credentials,
                nazo_auth::ClientAuthenticationContext::AllowPublicNone,
            )
            .await
            {
                Ok(assertion) => assertion,
                Err(error) => return Err(token_management_auth_error(error)),
            }
        };
        params.remove("client_secret");
        params.remove("client_assertion_type");
        params.remove("client_assertion");
        if let Err(error) = validate_raw_par_admission(
            &params,
            RawParAdmissionPolicy {
                client_is_confidential: client.client_type == "confidential",
                client_authentication_method: &client.token_endpoint_auth_method,
                require_dpop_bound_tokens: client.require_dpop_bound_tokens,
                require_mtls_bound_tokens: client.require_mtls_bound_tokens,
                require_request_object: client.require_par_request_object
                    || context
                        .config
                        .requires_signed_authorization_request(&client_policy),
                fapi2_security,
            },
        ) {
            return Err(par_admission_error(error));
        }
        apply_request_object_with_context(context, &mut params, &mut client).await?;
        if !super::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::AuthorizationDetails,
        ) && params.contains_key("authorization_details")
        {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization_details 未启用.",
            ));
        }
        params.remove("request");
        if let Err(error) = validate_expanded_par_admission(
            &params,
            ExpandedParAdmissionPolicy {
                client_type: &client.client_type,
                redirect_uris: &client.redirect_uris,
                allowed_audiences: &client.allowed_audiences,
                pkce_required: !client_policy.allow_confidential_oidc_without_pkce
                    || fapi2_security
                    || client.require_dpop_bound_tokens
                    || client.require_mtls_bound_tokens
                    || params.contains_key("dpop_jkt"),
                fapi2_requires_explicit_redirect_uri: fapi2_security,
            },
        ) {
            return Err(par_admission_error(error));
        }
        let request_dpop_jkt = match params.get("dpop_jkt") {
            Some(value) if is_valid_dpop_jkt(value) => Some(value.clone()),
            Some(_) => {
                return Err(OAuthEndpointError::json(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "dpop_jkt 无效.",
                ));
            }
            None => None,
        };
        let header_dpop_jkt = match crate::security::dpop::validate_dpop_proof(
            context.service,
            context.security_audit,
            &context.config.issuer,
            &context.config.mtls_endpoint_base_url,
            context.config.dpop_nonce_policy,
            facts.dpop,
            None,
            None,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                return Err(OAuthEndpointError::Dpop {
                    error,
                    context: DpopErrorContext::TokenEndpoint,
                });
            }
        };
        if let (Some(request_dpop_jkt), Some(header_dpop_jkt)) =
            (request_dpop_jkt.as_deref(), header_dpop_jkt.as_deref())
            && request_dpop_jkt != header_dpop_jkt
        {
            return Err(OAuthEndpointError::Dpop {
                error: DpopError::BindingMismatch,
                context: DpopErrorContext::TokenEndpoint,
            });
        }
        if let Err(error) = consume_token_management_client_assertion_with_authorization_service(
            context.service,
            &client,
            client_assertion.as_ref(),
            context.security_audit,
        )
        .await
        {
            return Err(token_management_auth_error(error));
        }
        let dpop_jkt = request_dpop_jkt.or(header_dpop_jkt);
        let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
            facts.mtls_thumbprint
        } else {
            None
        };

        let now = Utc::now();
        let request_token = random_urlsafe_token();
        let request_uri = format!("{PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX}{request_token}");
        let payload = PushedAuthorizationRequest {
            client_id,
            params,
            dpop_jkt,
            mtls_x5t_s256,
            issued_at: now,
            expires_at: now + Duration::seconds(par_ttl_seconds as i64),
        };
        if let Err(error) = context
            .service
            .store_par(&request_uri, &payload, par_ttl_seconds.max(1))
            .await
        {
            tracing::warn!(%error, "failed to persist PAR payload");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "PAR 写入失败.",
            ));
        }
        Ok(json!({
            "request_uri": request_uri,
            "expires_in": par_ttl_seconds
        }))
    }
}
fn par_admission_error(error: ParAdmissionError) -> OAuthEndpointError {
    let (status, description) = match error {
        ParAdmissionError::RequestUriNotAllowed => (
            StatusCode::BAD_REQUEST,
            "PAR request object 不能包含 request_uri.",
        ),
        ParAdmissionError::UnsupportedResponseType => (
            StatusCode::BAD_REQUEST,
            "PAR response_type is not supported.",
        ),
        ParAdmissionError::RequestObjectRequired => {
            (StatusCode::BAD_REQUEST, "PAR 请求缺少 request object.")
        }
        ParAdmissionError::ConfidentialClientRequired => (
            StatusCode::BAD_REQUEST,
            "FAPI2 profiles require confidential clients.",
        ),
        ParAdmissionError::StrongClientAuthenticationRequired => (
            StatusCode::UNAUTHORIZED,
            "FAPI2 profiles require private_key_jwt or mTLS client authentication.",
        ),
        ParAdmissionError::SenderConstraintRequired => (
            StatusCode::BAD_REQUEST,
            "FAPI2 profiles require sender-constrained access tokens.",
        ),
        ParAdmissionError::PkceRequired => (StatusCode::BAD_REQUEST, "PAR requests require PKCE."),
        ParAdmissionError::InvalidPkce => (
            StatusCode::BAD_REQUEST,
            "PAR code_challenge must use a valid S256 value.",
        ),
        ParAdmissionError::ExplicitRedirectUriRequired => (
            StatusCode::BAD_REQUEST,
            "FAPI2 PAR 请求必须显式包含 redirect_uri.",
        ),
        ParAdmissionError::RedirectUriRequired => {
            (StatusCode::BAD_REQUEST, "PAR 请求缺少 redirect_uri.")
        }
        ParAdmissionError::RedirectUriNotRegistered => {
            (StatusCode::BAD_REQUEST, "PAR 请求 redirect_uri 未注册.")
        }
        ParAdmissionError::InvalidResource => (
            StatusCode::BAD_REQUEST,
            "resource must be an absolute URI without a fragment.",
        ),
        ParAdmissionError::ResourceNotAllowed => (
            StatusCode::BAD_REQUEST,
            "请求的 resource 不在客户端允许范围内.",
        ),
    };
    OAuthEndpointError::json(status, error.oauth_error(), description)
}

fn token_management_auth_error(error: TokenManagementClientAuthError) -> OAuthEndpointError {
    match error {
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            OAuthEndpointError::json(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            )
        }
        TokenManagementClientAuthError::StoreUnavailable => OAuthEndpointError::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
        ),
    }
}
pub(crate) fn is_pushed_authorization_request_uri(request_uri: &str) -> bool {
    request_uri.starts_with(PUSHED_AUTHORIZATION_REQUEST_URI_PREFIX)
}
