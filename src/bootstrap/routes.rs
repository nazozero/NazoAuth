//! HTTP 路由表。
// 本文件只声明 URL 到 handler 的映射，不承载业务逻辑。

use actix_web::web;

use crate::http::*;

pub(crate) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health))
        .service(
            web::resource("/authorize")
                .route(web::get().to(authorize_get))
                .route(web::post().to(authorize_post)),
        )
        .route("/authorize/consent", web::get().to(authorize_consent))
        .route("/authorize/decision", web::post().to(authorize_decision))
        .route("/par", web::post().to(par))
        .route("/token", web::post().to(token))
        .service(
            web::resource("/logout")
                .route(web::get().to(oidc_logout))
                .route(web::post().to(oidc_logout)),
        )
        .route("/revoke", web::post().to(revoke))
        .route("/introspect", web::post().to(introspect))
        .service(
            web::resource("/fapi/resource")
                .route(web::get().to(fapi_resource))
                .route(web::post().to(fapi_resource)),
        )
        .route(
            "/.well-known/openid-configuration",
            web::get().to(discovery),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            web::get().to(oauth_authorization_server_metadata),
        )
        .route("/jwks.json", web::get().to(jwks))
        .service(
            web::resource("/userinfo")
                .route(web::get().to(userinfo))
                .route(web::post().to(userinfo)),
        )
        .route(
            "/scim/v2/ServiceProviderConfig",
            web::get().to(scim_service_provider_config),
        )
        .route("/scim/v2/Schemas", web::get().to(scim_schemas))
        .route("/scim/v2/ResourceTypes", web::get().to(scim_resource_types))
        .service(
            web::resource("/scim/v2/Users")
                .route(web::get().to(scim_list_users))
                .route(web::post().to(scim_create_user)),
        )
        .service(
            web::resource("/scim/v2/Users/{user_id}")
                .route(web::get().to(scim_get_user))
                .route(web::put().to(scim_replace_user))
                .route(web::patch().to(scim_patch_user))
                .route(web::delete().to(scim_delete_user)),
        )
        .service(
            web::scope("/auth")
                .route("/captcha-config", web::get().to(captcha_config))
                .route("/send-code", web::post().to(send_code))
                .route("/register", web::post().to(register))
                .route("/login", web::post().to(login))
                .route("/passkey/begin", web::post().to(passkey_login_begin))
                .route("/passkey/finish", web::post().to(passkey_login_finish))
                .route("/mfa/verify", web::post().to(mfa_verify))
                .route("/csrf", web::get().to(csrf))
                .route("/me", web::get().to(me))
                .route("/me", web::patch().to(update_me))
                .route("/me/passkeys", web::get().to(passkey_list))
                .route(
                    "/me/passkeys/registration/begin",
                    web::post().to(passkey_registration_begin),
                )
                .route(
                    "/me/passkeys/registration/finish",
                    web::post().to(passkey_registration_finish),
                )
                .route(
                    "/me/passkeys/{passkey_id}",
                    web::delete().to(passkey_delete),
                )
                .route("/me/mfa/totp/begin", web::post().to(mfa_totp_begin))
                .route("/me/mfa/totp/confirm", web::post().to(mfa_totp_confirm))
                .route(
                    "/me/mfa/backup-codes/regenerate",
                    web::post().to(mfa_backup_codes_regenerate),
                )
                .route("/me/mfa/disable", web::post().to(mfa_disable))
                .route("/me/avatar", web::post().to(upload_avatar))
                .route("/me/avatar", web::get().to(get_avatar))
                .route("/me/avatar", web::delete().to(delete_avatar))
                .route("/me/applications", web::get().to(my_applications))
                .route("/me/access-requests", web::get().to(my_access_requests))
                .route("/me/access-requests", web::post().to(create_access_request))
                .route("/me/access-delivery", web::get().to(access_delivery))
                .route("/logout", web::post().to(logout)),
        )
        .service(
            web::scope("/admin")
                .route("/users", web::get().to(admin_users))
                .route("/users/{user_id}", web::patch().to(admin_patch_user))
                .route("/clients", web::get().to(admin_clients))
                .route("/clients", web::post().to(admin_create_client))
                .route("/clients/{client_id}", web::get().to(admin_get_client))
                .route("/clients/{client_id}", web::patch().to(admin_patch_client))
                .route("/grants", web::get().to(admin_grants))
                .route("/grants/revoke", web::post().to(admin_revoke_grant))
                .route("/access-requests", web::get().to(admin_access_requests))
                .route(
                    "/access-requests/{request_id}/approve",
                    web::post().to(admin_approve_access_request),
                )
                .route(
                    "/access-requests/{request_id}/reject",
                    web::post().to(admin_reject_access_request),
                ),
        );
}
