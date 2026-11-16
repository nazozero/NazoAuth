//! Current-user avatar HTTP transport.
use crate::endpoints::views::auth_me_json_with_count;
use crate::endpoints::{sessions::SessionProfileHandles, views::is_cross_site_fetch};
use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use futures_util::Stream;
use http::StatusCode;
use http::header;
use http::header::HeaderValue;

use crate::http::{bytes_response, csrf_error, json_response, oauth_error};
use serde::{Deserialize, Serialize};

pub const AVATAR_STORAGE_DISABLED_MESSAGE: &str =
    "Avatar storage is not configured for this tenant. Contact the system administrator.";

pub fn avatar_storage_disabled_response() -> HttpResponse {
    oauth_error(
        StatusCode::FORBIDDEN,
        "access_denied",
        AVATAR_STORAGE_DISABLED_MESSAGE,
    )
}

#[derive(Deserialize)]
pub struct AvatarUploadBeginRequest {
    pub content_length: usize,
}

#[derive(Serialize)]
pub struct AvatarUploadStartResponse {
    pub upload_id: String,
    pub expires_at: String,
    pub upload: AvatarUploadTargetResponse,
}

#[derive(Serialize)]
pub struct AvatarUploadTargetResponse {
    pub url: String,
    pub method: String,
    pub headers: std::collections::BTreeMap<String, String>,
}

pub async fn avatar_upload_capability(
    sessions: &SessionProfileHandles,
    avatars: &AvatarProfileService,
    req: &HttpRequest,
) -> HttpResponse {
    if let Err(response) = sessions.current_session_or_login_required(req).await {
        return response;
    }
    let upload_mode = match avatars {
        AvatarProfileService::Disabled => "disabled",
        AvatarProfileService::Local(_) => "multipart",
        AvatarProfileService::Direct(_) => "direct",
    };
    let mut response = json_response(serde_json::json!({ "upload_mode": upload_mode }));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn begin_direct_avatar_upload(
    sessions: &SessionProfileHandles,
    avatars: &AvatarProfileService,
    req: &HttpRequest,
    payload: AvatarUploadBeginRequest,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if avatars.is_disabled() {
        return avatar_storage_disabled_response();
    }
    match avatars
        .begin_direct_upload(&user, payload.content_length)
        .await
    {
        Ok(start) => json_response(AvatarUploadStartResponse {
            upload_id: start.upload_id,
            expires_at: start.expires_at.to_rfc3339(),
            upload: AvatarUploadTargetResponse {
                url: start.target.url,
                method: start.target.method,
                headers: start.target.headers,
            },
        }),
        Err(nazo_identity::DirectAvatarUploadError::InvalidContentLength) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Avatar file size must be greater than zero.",
        ),
        Err(nazo_identity::DirectAvatarUploadError::TooLarge) => oauth_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "Avatar file is too large.",
        ),
        Err(nazo_identity::DirectAvatarUploadError::Storage(
            nazo_identity::ports::AvatarStorageError::Unsupported,
        )) => oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "Direct avatar upload is not supported by the configured storage.",
        ),
        Err(error) => {
            tracing::warn!(?error, "failed to authorize direct avatar upload");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Failed to authorize avatar upload.",
            )
        }
    }
}

pub async fn complete_direct_avatar_upload(
    sessions: &SessionProfileHandles,
    avatars: &AvatarProfileService,
    req: &HttpRequest,
    upload_id: String,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(req, None) {
        return csrf_error();
    }
    if uuid::Uuid::parse_str(upload_id.as_str()).is_err() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Avatar upload ID is invalid.",
        );
    }
    let user = match sessions.current_user_or_login_required(req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if avatars.is_disabled() {
        return avatar_storage_disabled_response();
    }
    match avatars
        .complete_direct_upload(user, upload_id.as_str())
        .await
    {
        Ok(overview) => json_response(auth_me_json_with_count(
            &overview.account,
            overview.authorized_application_count,
        )),
        Err(nazo_identity::DirectAvatarUploadError::UnsupportedContent) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Avatar must be PNG, JPEG, or WebP.",
        ),
        Err(
            nazo_identity::DirectAvatarUploadError::Missing
            | nazo_identity::DirectAvatarUploadError::Expired,
        ) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Avatar upload has expired.",
        ),
        Err(nazo_identity::DirectAvatarUploadError::Busy) => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "Avatar upload is being completed.",
        ),
        Err(nazo_identity::DirectAvatarUploadError::ConcurrentChange) => oauth_error(
            StatusCode::CONFLICT,
            "invalid_request",
            "Avatar was updated by another request.",
        ),
        Err(nazo_identity::DirectAvatarUploadError::Storage(
            nazo_identity::ports::AvatarStorageError::Unsupported,
        )) => oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "Direct avatar upload is not supported by the configured storage.",
        ),
        Err(error) => {
            tracing::warn!(?error, "failed to finalize direct avatar upload");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Failed to save avatar.",
            )
        }
    }
}

pub async fn upload_avatar<S, E>(
    sessions: &SessionProfileHandles,
    avatars: &AvatarProfileService,
    req: &HttpRequest,
    body: S,
) -> HttpResponse
where
    S: Stream<Item = Result<bytes::Bytes, E>>,
{
    if !sessions.has_valid_csrf_token(req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if avatars.is_disabled() {
        return avatar_storage_disabled_response();
    }
    let bytes = match super::multipart::read_avatar(req, body, avatars.max_bytes()).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    match avatars.upload(&user, bytes).await {
        Ok(overview) => json_response(auth_me_json_with_count(
            &overview.account,
            overview.authorized_application_count,
        )),
        Err(nazo_identity::UploadAvatarError::TooLarge) => oauth_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "Avatar file is too large.",
        ),
        Err(nazo_identity::UploadAvatarError::UnsupportedContent) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Avatar must be PNG, JPEG, or WebP.",
        ),
        Err(nazo_identity::UploadAvatarError::Storage(
            nazo_identity::ports::AvatarStorageError::PreparationFailed(error),
        )) => {
            tracing::warn!(%error, "failed to prepare avatar storage");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to save avatar.",
            )
        }
        Err(nazo_identity::UploadAvatarError::Overview(error)) => {
            tracing::warn!(%error, "failed to build auth me response after avatar upload");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Failed to load current user profile.",
            )
        }
        Err(error) => {
            tracing::warn!(?error, "failed to save avatar");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Failed to save avatar.",
            )
        }
    }
}

pub async fn get_avatar(
    sessions: &SessionProfileHandles,
    avatars: &AvatarProfileService,
    req: &HttpRequest,
) -> HttpResponse {
    let user = match sessions.current_user_or_login_required(req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if is_cross_site_fetch(req.headers()) {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Cross-origin avatar requests are not allowed.",
        );
    }
    if avatars.is_disabled() {
        return avatar_storage_disabled_response();
    }
    let avatar = avatars.read(&user).await;
    let avatar = match avatar {
        Err(nazo_identity::ReadAvatarError::Storage(
            nazo_identity::ports::AvatarStorageError::Conflict
            | nazo_identity::ports::AvatarStorageError::InvalidState
            | nazo_identity::ports::AvatarStorageError::Missing,
        )) => {
            // A request may have loaded the account immediately before an upload/delete
            // commits. The storage mutation is serialized, so refresh the projection once
            // after it completes rather than exposing a transient mixed version.
            let refreshed = match sessions.current_user_or_login_required(req).await {
                Ok(user) => user,
                Err(response) => return response,
            };
            avatars.read(&refreshed).await
        }
        result => result,
    };
    match avatar {
        Ok(avatar) => {
            let mut response = bytes_response(avatar.bytes);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(avatar.content_type.as_str()),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store, no-cache, must-revalidate"),
            );
            response
                .headers_mut()
                .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            response.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'"),
            );
            response
        }
        Err(nazo_identity::ReadAvatarError::NotUploaded) => oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "No avatar is set for the current user.",
        ),
        Err(error) => {
            tracing::warn!(?error, "failed to read avatar");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Failed to read avatar.",
            )
        }
    }
}

pub async fn delete_avatar(
    sessions: &SessionProfileHandles,
    avatars: &AvatarProfileService,
    req: &HttpRequest,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if avatars.is_disabled() {
        return avatar_storage_disabled_response();
    }
    match avatars.delete(&user).await {
        Ok(overview) => json_response(auth_me_json_with_count(
            &overview.account,
            overview.authorized_application_count,
        )),
        Err(nazo_identity::DeleteAvatarError::Overview(error)) => {
            tracing::warn!(%error, "failed to build auth me response after avatar delete");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Failed to load current user profile.",
            )
        }
        Err(error) => {
            tracing::warn!(?error, "failed to delete avatar");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Failed to delete avatar.",
            )
        }
    }
}

pub type AvatarFuture<'a, T, E> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send + 'a>>;

pub trait LocalAvatarOperations: Send + Sync {
    fn max_bytes(&self) -> usize;
    fn upload<'a>(
        &'a self,
        account: &'a nazo_identity::PublicAccount,
        bytes: Vec<u8>,
    ) -> AvatarFuture<'a, nazo_identity::AccountOverview, nazo_identity::UploadAvatarError>;
    fn read<'a>(
        &'a self,
        account: &'a nazo_identity::PublicAccount,
    ) -> AvatarFuture<'a, nazo_identity::AvatarObject, nazo_identity::ReadAvatarError>;
    fn delete<'a>(
        &'a self,
        account: &'a nazo_identity::PublicAccount,
    ) -> AvatarFuture<'a, nazo_identity::AccountOverview, nazo_identity::DeleteAvatarError>;
}

impl<S: nazo_identity::ports::AvatarStoragePort> LocalAvatarOperations
    for nazo_identity::AvatarService<S>
{
    fn max_bytes(&self) -> usize {
        self.max_bytes()
    }
    fn upload<'a>(
        &'a self,
        account: &'a nazo_identity::PublicAccount,
        bytes: Vec<u8>,
    ) -> AvatarFuture<'a, nazo_identity::AccountOverview, nazo_identity::UploadAvatarError> {
        Box::pin(self.upload(account, bytes))
    }
    fn read<'a>(
        &'a self,
        account: &'a nazo_identity::PublicAccount,
    ) -> AvatarFuture<'a, nazo_identity::AvatarObject, nazo_identity::ReadAvatarError> {
        Box::pin(self.read(account))
    }
    fn delete<'a>(
        &'a self,
        account: &'a nazo_identity::PublicAccount,
    ) -> AvatarFuture<'a, nazo_identity::AccountOverview, nazo_identity::DeleteAvatarError> {
        Box::pin(self.delete(account))
    }
}

#[derive(Clone)]
pub enum AvatarProfileService {
    Disabled,
    Local(std::sync::Arc<dyn LocalAvatarOperations>),
    Direct(nazo_identity::AvatarDirectUploadService),
}

impl AvatarProfileService {
    pub fn local<S: nazo_identity::ports::AvatarStoragePort + 'static>(
        service: nazo_identity::AvatarService<S>,
    ) -> Self {
        Self::Local(std::sync::Arc::new(service))
    }

    pub fn max_bytes(&self) -> usize {
        match self {
            Self::Disabled => 0,
            Self::Local(service) => service.max_bytes(),
            Self::Direct(service) => service.max_bytes(),
        }
    }

    pub const fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }

    pub async fn upload(
        &self,
        account: &nazo_identity::PublicAccount,
        bytes: Vec<u8>,
    ) -> Result<nazo_identity::AccountOverview, nazo_identity::UploadAvatarError> {
        match self {
            Self::Local(service) => service.upload(account, bytes).await,
            Self::Disabled | Self::Direct(_) => Err(nazo_identity::UploadAvatarError::Storage(
                nazo_identity::ports::AvatarStorageError::Unsupported,
            )),
        }
    }

    pub async fn begin_direct_upload(
        &self,
        account: &nazo_identity::PublicAccount,
        content_length: usize,
    ) -> Result<nazo_identity::AvatarUploadStart, nazo_identity::DirectAvatarUploadError> {
        match self {
            Self::Disabled | Self::Local(_) => {
                Err(nazo_identity::DirectAvatarUploadError::Storage(
                    nazo_identity::ports::AvatarStorageError::Unsupported,
                ))
            }
            Self::Direct(service) => service.begin_upload(account, content_length).await,
        }
    }

    pub async fn complete_direct_upload(
        &self,
        account: nazo_identity::PublicAccount,
        upload_id: &str,
    ) -> Result<nazo_identity::AccountOverview, nazo_identity::DirectAvatarUploadError> {
        match self {
            Self::Disabled | Self::Local(_) => {
                Err(nazo_identity::DirectAvatarUploadError::Storage(
                    nazo_identity::ports::AvatarStorageError::Unsupported,
                ))
            }
            Self::Direct(service) => service.complete_upload(account, upload_id).await,
        }
    }

    pub async fn read(
        &self,
        account: &nazo_identity::PublicAccount,
    ) -> Result<nazo_identity::AvatarObject, nazo_identity::ReadAvatarError> {
        match self {
            Self::Disabled => Err(nazo_identity::ReadAvatarError::Storage(
                nazo_identity::ports::AvatarStorageError::Unsupported,
            )),
            Self::Local(service) => service.read(account).await,
            Self::Direct(service) => service.read(account).await,
        }
    }

    pub async fn delete(
        &self,
        account: &nazo_identity::PublicAccount,
    ) -> Result<nazo_identity::AccountOverview, nazo_identity::DeleteAvatarError> {
        match self {
            Self::Disabled => Err(nazo_identity::DeleteAvatarError::Storage(
                nazo_identity::ports::AvatarStorageError::Unsupported,
            )),
            Self::Local(service) => service.delete(account).await,
            Self::Direct(service) => service.delete(account).await,
        }
    }
}
