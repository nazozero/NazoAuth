//! HTTP 路由表。
// 本文件只声明 URL 到 handler 的映射，不承载业务逻辑。

use actix_web::web;

use crate::http::*;
use crate::settings::Settings;

use super::cors;

pub(crate) fn configure(cfg: &mut web::ServiceConfig, settings: &Settings) {
    cfg.service(
        web::resource("/health")
            .wrap(cors::cors_well_known(settings))
            .route(web::get().to(health)),
    );
    // NO CORS: /authorize
    cfg.route("/authorize", web::get().to(authorize_get))
        .route(web::post().to(authorize_post))
        .route("/authorize/consent", web::get().to(authorize_consent))
        .route("/authorize/decision", web::post().to(authorize_decision))
        // NO CORS: /par
        .route("/par", web::post().to(par))
        // CORS: cors_browser_oauth — /token
        .service(
            web::resource("/token")
                .wrap(cors::cors_browser_oauth(settings))
                .route(web::post().to(token)),
        )
        // NO CORS: /logout (backchannel)
        .service(
            web::resource("/logout")
                .route(web::get().to(oidc_logout))
                .route(web::post().to(oidc_logout)),
        )
        // CORS: cors_browser_oauth — /revoke
        .service(
            web::resource("/revoke")
                .wrap(cors::cors_browser_oauth(settings))
                .route(web::post().to(revoke)),
        )
        // NO CORS: /introspect (backchannel)
        .route("/introspect", web::post().to(introspect))
        // NO CORS: /fapi/resource
        .service(
            web::resource("/fapi/resource")
                .route(web::get().to(fapi_resource))
                .route(web::post().to(fapi_resource)),
        )
        // CORS: cors_well_known — /.well-known/*
        .service(
            web::scope("/.well-known")
                .wrap(cors::cors_well_known(settings))
                .route("/openid-configuration", web::get().to(discovery))
                .route(
                    "/oauth-authorization-server",
                    web::get().to(oauth_authorization_server_metadata),
                ),
        )
        // CORS: cors_well_known — /jwks.json
        .service(
            web::resource("/jwks.json")
                .wrap(cors::cors_well_known(settings))
                .route(web::get().to(jwks)),
        )
        // CORS: cors_browser_oauth — /userinfo
        .service(
            web::resource("/userinfo")
                .wrap(cors::cors_browser_oauth(settings))
                .route(web::get().to(userinfo))
                .route(web::post().to(userinfo)),
        )
        // CORS: cors_scim — /scim/v2/*
        .service(
            web::scope("/scim/v2")
                .wrap(cors::cors_scim(settings))
                .route(
                    "/ServiceProviderConfig",
                    web::get().to(scim_service_provider_config),
                )
                .route("/Schemas", web::get().to(scim_schemas))
                .route("/ResourceTypes", web::get().to(scim_resource_types))
                .service(
                    web::resource("/Users")
                        .route(web::get().to(scim_list_users))
                        .route(web::post().to(scim_create_user)),
                )
                .service(
                    web::resource("/Users/{user_id}")
                        .route(web::get().to(scim_get_user))
                        .route(web::put().to(scim_replace_user))
                        .route(web::patch().to(scim_patch_user))
                        .route(web::delete().to(scim_delete_user)),
                ),
        )
        // /auth scope — NO CORS for UI routes, cors_auth_api for /auth/me
        .service(
            web::scope("/auth")
                .route("/captcha-config", web::get().to(captcha_config))
                .route("/send-code", web::post().to(send_code))
                .route("/register", web::post().to(register))
                .route("/login", web::post().to(login))
                .route(
                    "/federation/oidc/start",
                    web::get().to(federation_oidc_start),
                )
                .route(
                    "/federation/oidc/callback",
                    web::get().to(federation_oidc_callback),
                )
                .route("/federation/saml/acs", web::post().to(federation_saml_acs))
                .route("/passkey/begin", web::post().to(passkey_login_begin))
                .route("/passkey/finish", web::post().to(passkey_login_finish))
                .route("/mfa/verify", web::post().to(mfa_verify))
                .route("/csrf", web::get().to(csrf))
                // CORS: cors_auth_api — /auth/me/*
                .service(
                    web::scope("/me")
                        .wrap(cors::cors_auth_api(settings))
                        .route("", web::get().to(me))
                        .route("", web::patch().to(update_me))
                        .route("/passkeys", web::get().to(passkey_list))
                        .route(
                            "/passkeys/registration/begin",
                            web::post().to(passkey_registration_begin),
                        )
                        .route(
                            "/passkeys/registration/finish",
                            web::post().to(passkey_registration_finish),
                        )
                        .route("/passkeys/{passkey_id}", web::delete().to(passkey_delete))
                        .route("/mfa/totp/begin", web::post().to(mfa_totp_begin))
                        .route("/mfa/totp/confirm", web::post().to(mfa_totp_confirm))
                        .route(
                            "/mfa/backup-codes/regenerate",
                            web::post().to(mfa_backup_codes_regenerate),
                        )
                        .route("/mfa/disable", web::post().to(mfa_disable))
                        .route("/avatar", web::post().to(upload_avatar))
                        .route("/avatar", web::get().to(get_avatar))
                        .route("/avatar", web::delete().to(delete_avatar))
                        .route("/applications", web::get().to(my_applications))
                        .route("/access-requests", web::get().to(my_access_requests))
                        .route("/access-requests", web::post().to(create_access_request))
                        .route("/access-delivery", web::get().to(access_delivery)),
                )
                .route("/logout", web::post().to(logout)),
        )
        // CORS: cors_admin — /admin/*
        .service(
            web::scope("/admin")
                .wrap(cors::cors_admin(settings))
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
