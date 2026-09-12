//! JWT-Secured Authorization Request coordination.

use std::collections::HashMap;

use crate::contracts::oauth_error::OAuthEndpointError;
use chrono::Utc;
use nazo_auth::{
    AuthorizationRequestError, RequestObjectJtiPolicy, RequestObjectPolicy,
    RequestObjectVerificationInput, verify_request_object,
};

use super::AuthorizationRequestContext;
use crate::domain::rows::ClientRow;
use crate::policy::RequestObjectJtiPolicy as ServerRequestObjectJtiPolicy;

use crate::contracts::oauth_error::OAuthEndpointError as Error;
use crate::domain::client_policy::refresh_client_jwks;
use http::StatusCode;
pub(crate) use nazo_auth::{
    unverified_signed_request_object_client_id, unverified_signed_request_object_kid,
};

pub(crate) fn unverified_request_object_client_id(
    keys: &nazo_key_management::KeyManager,
    request_object: &str,
) -> Option<String> {
    if request_object.split('.').count() == 5 {
        let nested = keys.decrypt_request_object(request_object).ok()?;
        return unverified_signed_request_object_client_id(&nested);
    }
    unverified_signed_request_object_client_id(request_object)
}

pub(crate) async fn apply_request_object_with_context(
    context: &AuthorizationRequestContext<'_>,
    outer: &mut HashMap<String, String>,
    client: &mut ClientRow,
) -> Result<(), OAuthEndpointError> {
    let Some(request_object) = outer.get("request") else {
        return Ok(());
    };
    let decrypted;
    let request_object = if request_object.split('.').count() == 5 {
        if client.request_object_encryption_alg.as_deref() != Some("RSA-OAEP-256")
            || client.request_object_encryption_enc.as_deref() != Some("A256GCM")
        {
            return Err(request_object_verification_error(
                nazo_auth::RequestObjectVerificationError::InvalidAlgorithm,
            ));
        }
        decrypted = context
            .request_object_keys
            .decrypt_request_object(request_object)
            .map_err(|error| {
                tracing::warn!(%error, "encrypted request object rejected");
                request_object_verification_error(
                    nazo_auth::RequestObjectVerificationError::InvalidSignature,
                )
            })?;
        decrypted.as_str()
    } else {
        request_object.as_str()
    };
    if let Some(kid) = unverified_signed_request_object_kid(request_object)
        && let Err(error) =
            refresh_client_jwks(client, context.remote_client_documents, Some(&kid)).await
    {
        tracing::warn!(%error, "request object client jwks_uri could not be refreshed");
        return Err(Error::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "request object key source is unavailable.",
        ));
    }
    let verified = verify_request_object(RequestObjectVerificationInput {
        request_object,
        client,
        expected_signing_algorithm: client.request_object_signing_alg.as_deref(),
    })
    .map_err(request_object_verification_error)?;
    let normalized = context
        .service
        .admit_request_object_owned(
            outer,
            &verified.claims,
            RequestObjectPolicy {
                issuer: &context.config.issuer,
                client_id: &client.client_id,
                jti_policy: match context.config.request_object_jti_policy {
                    ServerRequestObjectJtiPolicy::Optional => RequestObjectJtiPolicy::Optional,
                    ServerRequestObjectJtiPolicy::RequiredForSignedJar => {
                        RequestObjectJtiPolicy::RequiredForSignedJar
                    }
                },
                require_integrity_protected_parameters:
                    signed_request_object_requires_integrity_protected_parameters(
                        client,
                        context
                            .config
                            .requires_signed_authorization_request(&client.security_policy),
                    ),
                now: Utc::now().timestamp(),
            },
        )
        .await
        .map_err(|error| {
            if let AuthorizationRequestError::Dependency(dependency) = error {
                tracing::warn!(?dependency, "failed to store request object jti");
            }
            request_object_policy_error(error)
        })?;
    *outer = normalized.parameters;
    Ok(())
}

fn signed_request_object_requires_integrity_protected_parameters(
    client: &ClientRow,
    signed_request_required: bool,
) -> bool {
    client.require_dpop_bound_tokens || client.require_par_request_object || signed_request_required
}

use nazo_auth::RequestObjectVerificationError;
#[must_use]
pub(crate) fn request_object_verification_error(
    error: RequestObjectVerificationError,
) -> OAuthEndpointError {
    let description = match error {
        RequestObjectVerificationError::InvalidCompact => "request object 无效.",
        RequestObjectVerificationError::InvalidHeader => "request object header 无效.",
        RequestObjectVerificationError::InvalidClaims => "request object claims 无效.",
        RequestObjectVerificationError::InvalidAlgorithm => "request object 签名算法无效.",
        RequestObjectVerificationError::MissingKeyId => "request object 缺少 kid.",
        RequestObjectVerificationError::InvalidKey => "request object 签名密钥无效.",
        RequestObjectVerificationError::InvalidSignature => "request object 验签失败.",
    };
    Error::json(
        StatusCode::BAD_REQUEST,
        "invalid_request_object",
        description,
    )
}

#[must_use]
pub(crate) fn request_object_policy_error(error: AuthorizationRequestError) -> OAuthEndpointError {
    let (status, description) = match error {
        AuthorizationRequestError::InvalidRequestObject
        | AuthorizationRequestError::RequestObjectClaims => {
            (StatusCode::BAD_REQUEST, "request object claims 无效.")
        }
        AuthorizationRequestError::RequestObjectContainsRequestUri => (
            StatusCode::BAD_REQUEST,
            "request object 不能包含 request_uri.",
        ),
        AuthorizationRequestError::RequestObjectParameterType => {
            (StatusCode::BAD_REQUEST, "request object 参数类型无效.")
        }
        AuthorizationRequestError::InvalidRequest
        | AuthorizationRequestError::OuterClientIdConflict => (
            StatusCode::BAD_REQUEST,
            "request object 与外层 client_id 冲突.",
        ),
        AuthorizationRequestError::SignedRequestObjectMissingRedirectUri => (
            StatusCode::BAD_REQUEST,
            "signed request object 缺少 redirect_uri.",
        ),
        AuthorizationRequestError::OuterAuthorizationParametersConflict => (
            StatusCode::BAD_REQUEST,
            "request object 与外层授权参数冲突.",
        ),
        AuthorizationRequestError::InvalidRequestObjectReplay => {
            (StatusCode::BAD_REQUEST, "request object jti 已使用.")
        }
        AuthorizationRequestError::Dependency(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "request object 防重放状态不可用.",
        ),
        AuthorizationRequestError::InvalidTarget
        | AuthorizationRequestError::UnsupportedResponseType
        | AuthorizationRequestError::UnauthorizedClient
        | AuthorizationRequestError::InvalidClient => {
            (StatusCode::BAD_REQUEST, "request object claims 无效.")
        }
    };
    Error::json(status, error.oauth_error(), description)
}

#[cfg(test)]
#[path = "../../tests/unit/authorization/jar.rs"]
mod tests;
