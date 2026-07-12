//! FAPI-style protected resource endpoint.
//! Enforces RFC 6750 access-token transport rules plus sender-constrained token binding.
use std::{future::Future, pin::Pin};

use crate::http::prelude::*;
use nazo_auth::Claims;
use nazo_http_signatures::{
    OriginalRequest, RequestInput, ResponseInput, ResponsePolicy, SignatureFields,
    VerificationPolicy, VerifiedInput, content_digest, content_digest_field_matches,
    parse_request_for_verification, prepare_response,
};

type FapiStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

trait FapiResourceStore: Send + Sync {
    fn revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
    ) -> FapiStoreFuture<'a, anyhow::Result<bool>>;

    fn client<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> FapiStoreFuture<'a, anyhow::Result<Option<ClientRow>>>;

    fn consume_replay<'a>(
        &'a self,
        fingerprint: &'a [u8; 32],
        max_age_seconds: i64,
    ) -> FapiStoreFuture<'a, ReplayConsumption>;

    #[cfg(test)]
    fn protected_work_reached(&self) {}
}

impl FapiResourceStore for AppState {
    fn revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
    ) -> FapiStoreFuture<'a, anyhow::Result<bool>> {
        Box::pin(async move {
            let mut conn = get_conn(&self.diesel_db).await?;
            let count = access_token_revocations::table
                .filter(access_token_revocations::tenant_id.eq(tenant_id))
                .filter(access_token_revocations::access_token_jti_blake3.eq(blake3_hex(jti)))
                .select(count_star())
                .first::<i64>(&mut conn)
                .await?;
            Ok(count > 0)
        })
    }

    fn client<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> FapiStoreFuture<'a, anyhow::Result<Option<ClientRow>>> {
        Box::pin(async move { find_client_in_tenant(&self.diesel_db, tenant_id, client_id).await })
    }

    fn consume_replay<'a>(
        &'a self,
        fingerprint: &'a [u8; 32],
        max_age_seconds: i64,
    ) -> FapiStoreFuture<'a, ReplayConsumption> {
        Box::pin(async move {
            consume_fapi_http_signature_replay(&self.valkey, fingerprint, max_age_seconds).await
        })
    }
}

#[cfg(test)]
#[derive(Clone)]
struct FapiResourceStoreOverride(std::sync::Arc<dyn FapiResourceStore>);

pub(crate) async fn fapi_resource(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    #[cfg(test)]
    {
        use actix_web::HttpMessage;
        let store_override = req.extensions().get::<FapiResourceStoreOverride>().cloned();
        if let Some(store) = store_override {
            return fapi_resource_with_store(&state, req, body, store.0.as_ref()).await;
        }
    }
    fapi_resource_with_store(&state, req, body, state.get_ref()).await
}

async fn fapi_resource_with_store(
    state: &Data<AppState>,
    req: HttpRequest,
    body: Bytes,
    store: &dyn FapiResourceStore,
) -> HttpResponse {
    if !state.settings.enable_fapi_http_signatures {
        return fapi_resource_inner(state, &req, &body, None, store).await;
    }

    let original = FapiOriginalRequest::capture(&state.settings.issuer, &req, &body);
    let response = fapi_resource_inner(state, &req, &body, Some(&original), store).await;
    sign_fapi_resource_response(state, &original, response).await
}

async fn fapi_resource_inner(
    state: &Data<AppState>,
    req: &HttpRequest,
    body: &Bytes,
    original: Option<&FapiOriginalRequest>,
    store: &dyn FapiResourceStore,
) -> HttpResponse {
    let http_signatures_enabled = original.is_some();
    let (scheme, token) = match resource_access_token(req, body, http_signatures_enabled) {
        ResourceAccessToken::Present(scheme, token) => (scheme, token),
        ResourceAccessToken::Missing => {
            return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "缺少访问令牌.");
        }
        ResourceAccessToken::InvalidRequest => {
            return oauth_bearer_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Only one access token transport method may be used.",
            );
        }
    };
    let Some(claims) = decode_access_claims(state, &token) else {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌无效或已过期.",
        );
    };
    if let Err(response) = validate_access_token_binding(state, req, &token, scheme, &claims).await
    {
        return response;
    }
    if !fapi_resource_audience_allowed(&state.settings, &claims.aud) {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌 audience 不适用于该资源.",
        );
    }
    let Some(tenant_id) = access_token_tenant_id(&claims) else {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌租户边界无效.",
        );
    };

    let revoked = match store.revoked(tenant_id, &claims.jti).await {
        Ok(revoked) => revoked,
        Err(error) => {
            tracing::warn!(%error, "failed to query FAPI resource token revocation state");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "resource 查询失败.",
            );
        }
    };
    if revoked || claims.exp <= Utc::now().timestamp() {
        return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "访问令牌已失效.");
    }

    if http_signatures_enabled {
        let client = match store.client(tenant_id, &claims.client_id).await {
            Ok(Some(client)) if client.is_active => client,
            Ok(_) => {
                return oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "访问令牌客户端无效.",
                );
            }
            Err(error) => {
                tracing::warn!(%error, "failed to load FAPI HTTP signature client");
                return oauth_bearer_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "resource 查询失败.",
                );
            }
        };
        let verified = match verify_fapi_resource_http_signature(
            &client,
            original.expect("enabled resource flow captures its original request"),
            FapiResourceSignaturePolicy {
                tenant_id,
                client_id: &claims.client_id,
                max_age_seconds: state.settings.fapi_http_signature_max_age_seconds,
            },
        ) {
            Ok(verified) => verified,
            Err(()) => {
                return oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "HTTP message signature is missing or invalid.",
                );
            }
        };
        match store
            .consume_replay(
                verified.replay_fingerprint(),
                state.settings.fapi_http_signature_max_age_seconds,
            )
            .await
        {
            ReplayConsumption::Accepted => {}
            ReplayConsumption::Replay => {
                return oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "HTTP message signature replay detected.",
                );
            }
            ReplayConsumption::DependencyFailure => {
                tracing::warn!("failed to consume FAPI HTTP signature replay marker");
                return oauth_bearer_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "resource 暂时不可用.",
                );
            }
        }
    }

    #[cfg(test)]
    store.protected_work_reached();
    let mut response = json_response_no_store(json!({
        "sub": claims.sub,
        "client_id": claims.client_id,
        "scope": claims.scope,
        "aud": claims.aud
    }));
    response.headers_mut().insert(
        "x-fapi-interaction-id".parse().unwrap(),
        fapi_interaction_id(req),
    );
    response
}

#[derive(Clone, Debug)]
enum CapturedHeader {
    Missing,
    Unique(String),
    Invalid,
}

impl CapturedHeader {
    fn capture(req: &HttpRequest, name: &str) -> Self {
        let mut values = req.headers().get_all(name);
        let Some(value) = values.next() else {
            return Self::Missing;
        };
        if values.next().is_some() {
            return Self::Invalid;
        }
        match value.to_str() {
            Ok(value) => Self::Unique(value.to_owned()),
            Err(_) => Self::Invalid,
        }
    }

    fn unique(&self) -> Result<Option<&str>, ()> {
        match self {
            Self::Missing => Ok(None),
            Self::Unique(value) => Ok(Some(value)),
            Self::Invalid => Err(()),
        }
    }
}

struct FapiOriginalRequest {
    method: String,
    target_uri: String,
    body: Bytes,
    authorization: CapturedHeader,
    dpop: CapturedHeader,
    content_digest: CapturedHeader,
    signature_input: CapturedHeader,
    signature: CapturedHeader,
    safe_headers: Vec<(String, String)>,
    captured_at: i64,
}

impl FapiOriginalRequest {
    fn capture(issuer: &str, req: &HttpRequest, body: &Bytes) -> Self {
        let target_uri = format!(
            "{}{}",
            issuer.trim_end_matches('/'),
            req.uri()
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or(req.path())
        );
        let safe_headers = req
            .headers()
            .keys()
            .filter_map(|name| {
                let name = name.as_str().to_ascii_lowercase();
                if matches!(name.as_str(), "signature" | "signature-input") {
                    return None;
                }
                let mut values = req.headers().get_all(name.as_str());
                let value = values.next()?;
                if values.next().is_some() {
                    return None;
                }
                let value = value.to_str().ok()?;
                if value.chars().any(char::is_control) {
                    return None;
                }
                Some((name, value.to_owned()))
            })
            .collect();
        Self {
            method: req.method().as_str().to_owned(),
            target_uri,
            body: body.clone(),
            authorization: CapturedHeader::capture(req, "authorization"),
            dpop: CapturedHeader::capture(req, "dpop"),
            content_digest: CapturedHeader::capture(req, "content-digest"),
            signature_input: CapturedHeader::capture(req, "signature-input"),
            signature: CapturedHeader::capture(req, "signature"),
            safe_headers,
            captured_at: Utc::now().timestamp(),
        }
    }

    fn signature_fields(&self) -> Result<SignatureFields, ()> {
        match (self.signature_input.unique()?, self.signature.unique()?) {
            (Some(signature_input), Some(signature)) => Ok(SignatureFields {
                signature_input: signature_input.to_owned(),
                signature: signature.to_owned(),
            }),
            _ => Err(()),
        }
    }

    fn verification_headers(&self) -> Result<Vec<(&str, &str)>, ()> {
        let mut headers = self
            .safe_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        for (name, captured) in [
            ("authorization", &self.authorization),
            ("dpop", &self.dpop),
            ("content-digest", &self.content_digest),
        ] {
            if headers.iter().any(|(captured, _)| *captured == name) {
                continue;
            }
            if let Some(value) = captured.unique()? {
                headers.push((name, value));
            }
        }
        Ok(headers)
    }

    fn parse(&self, max_age_seconds: i64) -> Result<VerifiedInput, ()> {
        let fields = self.signature_fields()?;
        let headers = self.verification_headers()?;
        parse_request_for_verification(
            RequestInput {
                method: &self.method,
                target_uri: &self.target_uri,
                headers: &headers,
                body: &self.body,
            },
            fields,
            VerificationPolicy {
                now: self.captured_at,
                max_age_seconds,
                future_skew_seconds: FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS,
            },
        )
        .map_err(|_| ())
    }

    fn valid_digest(&self) -> Option<&str> {
        let value = self.content_digest.unique().ok().flatten()?;
        (!self.body.is_empty() && content_digest_field_matches(value, &self.body))
            .then(|| value.trim_matches([' ', '\t']))
    }
}

struct FapiResourceSignaturePolicy<'a> {
    tenant_id: Uuid,
    client_id: &'a str,
    max_age_seconds: i64,
}

fn verify_fapi_resource_http_signature(
    client: &ClientRow,
    original: &FapiOriginalRequest,
    policy: FapiResourceSignaturePolicy<'_>,
) -> Result<VerifiedInput, ()> {
    let verified = original.parse(policy.max_age_seconds)?;
    verify_client_http_message(
        client,
        policy.tenant_id,
        policy.client_id,
        verified.keyid(),
        verified.algorithm(),
        verified.signature_base(),
        verified.signature(),
    )
    .map_err(|_| ())?;
    Ok(verified)
}

async fn sign_fapi_resource_response(
    state: &AppState,
    original: &FapiOriginalRequest,
    response: HttpResponse,
) -> HttpResponse {
    let status = response.status();
    let response_headers = response.headers().clone();
    let response_body = match actix_web::body::to_bytes(response.into_body()).await {
        Ok(body) => body,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let digest = (!response_body.is_empty()).then(|| content_digest(&response_body));
    let mut response_signature_headers = digest
        .as_deref()
        .map(|value| vec![("content-digest", value)])
        .unwrap_or_default();
    let mut covered_response_headers = Vec::new();
    for name in ["content-type", "x-fapi-interaction-id"] {
        if let Some(value) = response_headers
            .get(name)
            .and_then(|value| value.to_str().ok())
        {
            response_signature_headers.push((name, value));
            covered_response_headers.push(name);
        }
    }
    let request_digest = original.valid_digest();
    let mut request_headers = original
        .safe_headers
        .iter()
        .filter(|(name, _)| name != "content-digest")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    if let Some(digest) = request_digest {
        request_headers.push(("content-digest", digest));
    }
    let request_fields = original.signature_fields().ok();
    let original_body = request_digest
        .map(|_| original.body.as_ref())
        .unwrap_or(b"");
    let signing_lease = match state.keyset.prepare_http_signing() {
        Ok(lease) => lease,
        Err(_) => return HttpResponse::ServiceUnavailable().finish(),
    };
    let signing = match prepare_response(
        ResponseInput {
            status: status.as_u16(),
            headers: &response_signature_headers,
            body: &response_body,
        },
        OriginalRequest {
            input: RequestInput {
                method: &original.method,
                target_uri: &original.target_uri,
                headers: &request_headers,
                body: original_body,
            },
            signature_fields: request_fields.as_ref(),
        },
        ResponsePolicy {
            created: Utc::now().timestamp(),
            keyid: signing_lease.kid(),
            algorithm: signing_lease.algorithm(),
            covered_headers: &covered_response_headers,
            covered_request_headers: &[],
        },
    ) {
        Ok(signing) => signing,
        Err(_) => {
            tracing::warn!(
                category = "prepare_failure",
                "failed to prepare FAPI resource response signature"
            );
            return HttpResponse::ServiceUnavailable().finish();
        }
    };
    let signature = match signing_lease.sign(signing.signature_base()).await {
        Ok(signature) => signature,
        Err(_) => {
            tracing::warn!(
                category = "signer_failure",
                "failed to sign FAPI resource response"
            );
            return HttpResponse::ServiceUnavailable().finish();
        }
    };
    let fields = signing.finish(signature.as_bytes());
    let mut builder = HttpResponse::build(status);
    for (name, value) in &response_headers {
        if name != header::CONTENT_LENGTH
            && name.as_str() != "content-digest"
            && name.as_str() != "signature-input"
            && name.as_str() != "signature"
        {
            builder.append_header((name.clone(), value.clone()));
        }
    }
    if let Some(digest) = digest {
        builder.insert_header(("content-digest", digest));
    }
    builder.insert_header(("signature-input", fields.signature_input));
    builder.insert_header(("signature", fields.signature));
    builder.body(response_body)
}

fn fapi_interaction_id(req: &HttpRequest) -> actix_web::http::header::HeaderValue {
    req.headers()
        .get("x-fapi-interaction-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| actix_web::http::header::HeaderValue::from_str(value).ok())
        .unwrap_or_else(|| {
            actix_web::http::header::HeaderValue::from_str(&Uuid::now_v7().to_string())
                .expect("UUID is a valid HTTP header value")
        })
}

async fn validate_access_token_binding(
    state: &AppState,
    req: &HttpRequest,
    token: &str,
    scheme: AccessTokenAuthScheme,
    claims: &Claims,
) -> Result<(), HttpResponse> {
    match (scheme, claims.cnf.as_ref()) {
        (AccessTokenAuthScheme::DPoP, Some(cnf)) if cnf.jkt.is_some() => {
            validate_dpop_proof(state, req, Some(token), cnf.jkt.as_deref())
                .await
                .map_err(|error| dpop_error_response(error, DpopErrorContext::ProtectedResource))?;
        }
        (AccessTokenAuthScheme::DPoP, _) => {
            return Err(dpop_error_response(
                DpopError::TokenNotBound,
                DpopErrorContext::ProtectedResource,
            ));
        }
        (AccessTokenAuthScheme::Bearer, Some(cnf)) if cnf.x5t_s256.is_some() => {
            let expected = cnf.x5t_s256.as_deref().unwrap_or_default();
            let Some(actual) = request_mtls_thumbprint(req, &state.settings) else {
                return Err(oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "mTLS-bound access token requires a verified client certificate.",
                ));
            };
            if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
                return Err(oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "mTLS-bound access token certificate mismatch.",
                ));
            }
        }
        (AccessTokenAuthScheme::Bearer, Some(_)) => {
            return Err(dpop_error_response(
                DpopError::MissingProof,
                DpopErrorContext::ProtectedResource,
            ));
        }
        (AccessTokenAuthScheme::Bearer, None) => {}
    }
    Ok(())
}

fn fapi_resource_audience_allowed(settings: &Settings, audience: &Value) -> bool {
    token_audience_contains(audience, &settings.default_audience)
        || token_audience_contains(audience, &settings.protected_resource_identifier)
}

enum ResourceAccessToken {
    Present(AccessTokenAuthScheme, String),
    Missing,
    InvalidRequest,
}

fn resource_access_token(
    req: &HttpRequest,
    body: &Bytes,
    http_signatures_enabled: bool,
) -> ResourceAccessToken {
    let header_token = authorization_access_token(req.headers());
    let body_token = resource_form_body_access_token(req, body);

    if http_signatures_enabled && !matches!(&body_token, ResourceFormBodyAccessToken::Missing) {
        return ResourceAccessToken::InvalidRequest;
    }

    match (header_token, body_token) {
        (Some(_), ResourceFormBodyAccessToken::Present(_)) => ResourceAccessToken::InvalidRequest,
        (Some((scheme, token)), _) => ResourceAccessToken::Present(scheme, token),
        (None, ResourceFormBodyAccessToken::Present(token)) => {
            ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token)
        }
        (None, ResourceFormBodyAccessToken::Missing) => ResourceAccessToken::Missing,
        (None, ResourceFormBodyAccessToken::InvalidRequest) => ResourceAccessToken::InvalidRequest,
    }
}

enum ResourceFormBodyAccessToken {
    Present(String),
    Missing,
    InvalidRequest,
}

fn resource_form_body_access_token(req: &HttpRequest, body: &Bytes) -> ResourceFormBodyAccessToken {
    if req.method() != actix_web::http::Method::POST
        || body.is_empty()
        || !request_uses_form_urlencoded(req)
    {
        return ResourceFormBodyAccessToken::Missing;
    }
    let mut access_token = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        if key == "access_token" {
            if access_token.is_some() {
                return ResourceFormBodyAccessToken::InvalidRequest;
            }
            let token = value.into_owned();
            if token.trim().is_empty() {
                return ResourceFormBodyAccessToken::Missing;
            }
            access_token = Some(token);
        }
    }
    access_token
        .map(ResourceFormBodyAccessToken::Present)
        .unwrap_or(ResourceFormBodyAccessToken::Missing)
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/fapi_resource.rs"]
mod tests;
