// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::profile::avatar::*;
#[path = "../../../unit/http/profile/avatar.rs"]
pub(crate) mod tests;

use crate::http::sessions::SessionProfileHandles;

use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json, Path},
};

pub(crate) async fn avatar_upload_capability(
    sessions: Data<SessionProfileHandles>,
    avatars: Data<nazoauth::test_support::endpoints::profile::avatar::AvatarProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::avatar::avatar_upload_capability(
            sessions.get_ref(),
            avatars.get_ref(),
            &request,
        )
        .await,
    )
}

pub(crate) async fn begin_direct_avatar_upload(
    sessions: Data<SessionProfileHandles>,
    avatars: Data<nazoauth::test_support::endpoints::profile::avatar::AvatarProfileService>,
    req: HttpRequest,
    Json(payload): Json<AvatarUploadBeginRequest>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::avatar::begin_direct_avatar_upload(
            sessions.get_ref(),
            avatars.get_ref(),
            &request,
            payload,
        )
        .await,
    )
}

pub(crate) async fn complete_direct_avatar_upload(
    sessions: Data<SessionProfileHandles>,
    avatars: Data<nazoauth::test_support::endpoints::profile::avatar::AvatarProfileService>,
    req: HttpRequest,
    upload_id: Path<String>,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::avatar::complete_direct_avatar_upload(
            sessions.get_ref(),
            avatars.get_ref(),
            &request,
            upload_id.into_inner(),
        )
        .await,
    )
}

pub(crate) async fn get_avatar(
    sessions: Data<SessionProfileHandles>,
    avatars: Data<nazoauth::test_support::endpoints::profile::avatar::AvatarProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::avatar::get_avatar(
            sessions.get_ref(),
            avatars.get_ref(),
            &request,
        )
        .await,
    )
}

pub(crate) async fn delete_avatar(
    sessions: Data<SessionProfileHandles>,
    avatars: Data<nazoauth::test_support::endpoints::profile::avatar::AvatarProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let request = crate::test_support::transport::request_head(&req);
    nazo_http_actix::forward_response(
        nazoauth::test_support::endpoints::profile::avatar::delete_avatar(
            sessions.get_ref(),
            avatars.get_ref(),
            &request,
        )
        .await,
    )
}
