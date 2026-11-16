//! Exhaustive endpoint dispatch over the single transport manifest.
use super::NazoAuth;
use crate::http::{self, Request, Response};
use crate::integration::{Endpoint, Route, RouteGuard, RouteMethod};
use ::http::StatusCode;
use bytes::Bytes;

macro_rules! extract {
    ($value:expr) => {
        match $value {
            Ok(value) => value,
            Err(response) => return response,
        }
    };
}
macro_rules! require {
    ($value:expr) => {
        match $value {
            Some(value) => value,
            None => return http::empty_response(StatusCode::NOT_FOUND),
        }
    };
}

impl NazoAuth {
    /// Serve an already decoded HTTP request. A single body chunk retains its
    /// allocation through parsing and byte-preserving response paths.
    pub fn handle(&self, request: Request) -> impl std::future::Future<Output = Response> {
        self.handle_stream(request.map(|body| {
            futures_util::stream::once(std::future::ready(Ok::<_, std::convert::Infallible>(body)))
        }))
    }

    /// Serve framework-provided body chunks without requiring a runtime or a
    /// Send stream. Content decoding follows the route's declared BodyMode;
    /// adapters report decoder limits as io::ErrorKind::FileTooLarge.
    pub fn handle_stream<S, E>(
        &self,
        request: ::http::Request<S>,
    ) -> impl std::future::Future<Output = Response>
    where
        S: futures_util::Stream<Item = Result<Bytes, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let (parts, stream) = request.into_parts();
        let mut request = Request::from_parts(parts, Bytes::new());
        // Capture the final request once instead of retaining a second input head.
        async move {
            let mut response = self.route(&mut request, stream).await;
            http::apply_security_headers(
                response.headers_mut(),
                request.uri().path() == "/check_session",
            );
            response
        }
    }

    async fn route<S, E>(&self, request: &mut Request, stream: S) -> Response
    where
        S: futures_util::Stream<Item = Result<Bytes, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        // Uri::clone shares the original bytes and lets Params borrow the raw
        // target while the body is installed in the same standard Request.
        let uri = request.uri().clone();
        let routing_path = crate::integration::routing_path(uri.path());
        let matched = crate::integration::match_path(&routing_path);
        let (cors, guard) = matched.as_ref().map_or_else(
            || crate::integration::unmatched_policy(&routing_path),
            |(route, _)| (route.cors, route.guard),
        );
        let enabled = self.guard_enabled(guard);
        if crate::integration::guard_precedes_cors(&routing_path) && !enabled {
            return http::empty_response(StatusCode::NOT_FOUND);
        }
        let origins = &self.settings.endpoint.cors_allowed_origins;
        if let Some(response) = http::cors_preflight(cors, request, origins) {
            return response;
        }
        let mut response = match matched.as_ref() {
            Some((route, params)) if enabled => {
                self.dispatch_stream(route, params, request, stream).await
            }
            _ => http::empty_response(StatusCode::NOT_FOUND),
        };
        http::apply_cors_headers(cors, request, origins, response.headers_mut());
        response
    }

    fn guard_enabled(&self, guard: RouteGuard) -> bool {
        match guard {
            RouteGuard::None => true,
            RouteGuard::ControlTenant => self.deployment.as_ref().is_some_and(|deployment| {
                deployment.capabilities.control_tenant == self.settings.tenant.context.tenant_id
            }),
            RouteGuard::Openid4vci => {
                self.settings.modules.register_openid4vci_routes
                    && self.core.credential_issuer_endpoint.is_some()
            }
            RouteGuard::Openid4vp => {
                self.settings.modules.register_openid4vp_routes
                    && self.core.presentation_endpoint.is_some()
            }
        }
    }

    async fn dispatch_stream<S, E>(
        &self,
        route: &Route,
        params: &matchit::Params<'_, '_>,
        request: &mut Request,
        stream: S,
    ) -> Response
    where
        S: futures_util::Stream<Item = Result<Bytes, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        // This resource's existing budget also applies to unsupported methods.
        if route.needs_nonce_admission() {
            extract!(
                Box::pin(crate::endpoints::rate_limit::enforce_auth_request_limit(
                    &self.identity.auth_request_limiter,
                    request,
                    &self.identity.client_ip_config,
                ))
                .await
            );
        }
        let method = extract!(route.resolve_method(request.method()));
        match method.endpoint {
            Endpoint::Discovery => {
                return http::discovery(self.core.metadata_handles.as_ref()).await;
            }
            Endpoint::OauthAuthorizationServerMetadata => {
                return http::oauth_authorization_server_metadata(
                    self.core.metadata_handles.as_ref(),
                )
                .await;
            }
            Endpoint::OauthProtectedResourceMetadata => {
                return http::oauth_protected_resource_metadata(
                    self.core.metadata_handles.as_ref(),
                )
                .await;
            }
            Endpoint::Jwks => return http::jwks(self.core.metadata_handles.as_ref()).await,
            _ => {}
        }

        self.mtls.prepare_request(request);
        let future: futures_util::future::LocalBoxFuture<'_, Response> = match method.endpoint {
            Endpoint::UploadAvatar => Box::pin(crate::endpoints::profile::avatar::upload_avatar(
                &self.identity.session_profiles,
                &self.identity.avatar_profiles,
                request,
                stream,
            )),
            Endpoint::BackchannelAuthentication => {
                Box::pin(crate::endpoints::token::ciba::backchannel_authentication(
                    &self.core.ciba_application,
                    &self.identity.client_ip_config,
                    request,
                    http::collect_route_body(method, stream),
                ))
            }
            Endpoint::DynamicClientRegistration => Box::pin(http::dynamic_client_registration(
                &self.core.dynamic_registration_handles,
                request,
                http::collect_route_body(method, stream),
            )),
            Endpoint::ClientConfigurationPut => Box::pin(http::client_configuration_put(
                &self.core.dynamic_registration_handles,
                request,
                extract!(http::parse_path(
                    params.get("client_id").expect("manifest capture")
                )),
                http::collect_route_body(method, stream),
            )),
            Endpoint::OidcLogout => Box::pin(http::oidc_logout(
                &self.identity.oidc_logout,
                request,
                http::collect_route_body(method, stream),
            )),
            _ => {
                if extract!(http::validate_route_body_head(request, method)) {
                    *request.body_mut() = extract!(http::collect_route_body(method, stream).await);
                }
                self.dispatch_endpoint(method, params, request)
            }
        };
        future.await
    }

    // Each selected endpoint owns its own async state. A request does not reserve
    // space for unrelated handlers, and body decoding stays at the transport boundary.
    fn dispatch_endpoint<'a>(
        &'a self,
        method: &RouteMethod,
        params: &'a matchit::Params<'_, '_>,
        request: &'a Request,
    ) -> futures_util::future::LocalBoxFuture<'a, Response> {
        match method.endpoint {
            Endpoint::Token => Box::pin(async move {
                crate::endpoints::token::dispatch::token_with_service(
                    self.core.token_endpoint_handles.as_ref(),
                    self.identity.client_ip_config.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::MdocCrl => Box::pin(async move {
                crate::well_known::mdoc_crl(
                    self.mdoc_crls.as_deref(),
                    &extract!(http::parse_path::<String>(
                        params.get("issuer_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::CredentialIssuerMetadata => Box::pin(async move {
                crate::openid4vc::credential_issuer_metadata(
                    require!(self.core.credential_issuer_endpoint.as_deref()),
                    request,
                )
                .await
            }),
            Endpoint::ControlDiscovery => Box::pin(async move {
                crate::control_discovery::control_discovery(
                    &require!(self.deployment.as_ref()).capabilities.identity,
                    extract!(http::parse_json_limit(request, 2048)),
                )
                .await
            }),
            Endpoint::AdminRuntimeModules => Box::pin(async move {
                http::admin_runtime_modules(
                    self.identity.runtime_module_admin_endpoint.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::AdminRuntimeModuleEvents => Box::pin(async move {
                http::admin_runtime_module_events(
                    self.identity.runtime_module_admin_endpoint.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AdminPatchRuntimeModule => Box::pin(async move {
                http::admin_patch_runtime_module(
                    self.identity.runtime_module_admin_endpoint.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("module_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminControllerSlotCommit => Box::pin(async move {
                crate::endpoints::admin::controller_registry::admin_controller_slot_commit(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    &require!(self.deployment.as_ref()).controller_registry,
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 8192)),
                )
                .await
            }),
            Endpoint::AdminControllerSlotRotate => Box::pin(async move {
                crate::endpoints::admin::controller_registry::admin_controller_slot_rotate(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    &require!(self.deployment.as_ref()).controller_registry,
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 8192)),
                )
                .await
            }),
            Endpoint::AdminControllerSlotRevoke => Box::pin(async move {
                crate::endpoints::admin::controller_registry::admin_controller_slot_revoke(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    &require!(self.deployment.as_ref()).controller_registry,
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 8192)),
                )
                .await
            }),
            Endpoint::AdminControllerApproval => Box::pin(async move {
                crate::endpoints::admin::controller_registry::admin_controller_approval(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    &require!(self.deployment.as_ref()).controller_registry,
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 8192)),
                )
                .await
            }),
            Endpoint::AdminRecoveryRoot => Box::pin(async move {
                crate::endpoints::admin::recovery_root::admin_recovery_root(
                    self.identity.admin_sessions.as_ref(),
                    &require!(self.deployment.as_ref()).recovery_root,
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AdminRecoveryRootApproval => Box::pin(async move {
                crate::endpoints::admin::recovery_root::admin_recovery_root_approval(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    &require!(self.deployment.as_ref()).recovery_root,
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 8192)),
                )
                .await
            }),
            Endpoint::AdminRecoveryRootRotate => Box::pin(async move {
                crate::endpoints::admin::recovery_root::admin_recovery_root_rotate(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    &require!(self.deployment.as_ref()).recovery_root,
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 8192)),
                )
                .await
            }),
            Endpoint::Ready => {
                Box::pin(async move { crate::well_known::ready(&self.readiness).await })
            }
            Endpoint::Live => Box::pin(async move { crate::well_known::live().await }),
            Endpoint::Startup => Box::pin(async move { crate::well_known::startup().await }),
            Endpoint::AuthorizeGet => Box::pin(async move {
                crate::endpoints::authorization::request::authorize_get(
                    self.identity.authorization_endpoint.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::AuthorizePost => Box::pin(async move {
                crate::endpoints::authorization::request::authorize_post(
                    self.identity.authorization_endpoint.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::AuthorizeClientPresentation => Box::pin(async move {
                crate::endpoints::authorization::presentation::authorize_client_presentation(
                    self.identity.authorization_endpoint.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::AuthorizeConsent => Box::pin(async move {
                crate::endpoints::authorization::consent::authorize_consent(
                    self.identity.authorization_endpoint.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AuthorizeDecision => Box::pin(async move {
                http::authorize_decision(
                    self.identity.authorization_decision_endpoint.as_ref(),
                    request,
                    extract!(http::parse_form(request)),
                )
                .await
            }),
            Endpoint::Par => Box::pin(async move {
                crate::endpoints::authorization::par::par(
                    self.identity.authorization_endpoint.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::CibaVerificationPage => Box::pin(async move {
                crate::endpoints::token::ciba::ciba_verification_page(
                    self.core.ciba_application.as_ref(),
                    extract!(http::parse_path(
                        params.get("auth_req_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::DeviceAuthorization => Box::pin(async move {
                crate::endpoints::token::device::device_authorization(
                    self.identity.device_decision_handles.as_ref(),
                    self.core.device_config.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::DeviceVerificationPage => Box::pin(async move {
                crate::endpoints::token::device::device_verification_page(
                    self.identity.device_decision_handles.as_ref(),
                    self.core.device_config.as_ref(),
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::DeviceVerification => Box::pin(async move {
                crate::endpoints::token::device::device_verification(
                    self.identity.device_decision_handles.as_ref(),
                    self.identity.session_profiles.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::DeviceDecision => Box::pin(async move {
                crate::endpoints::token::device::device_decision(
                    self.identity.device_decision_handles.as_ref(),
                    self.identity.session_profiles.as_ref(),
                    self.core.device_config.as_ref(),
                    request,
                    extract!(http::parse_form(request)),
                )
                .await
            }),
            Endpoint::CheckSessionIframe => Box::pin(async move {
                http::check_session_iframe(self.identity.session_management_endpoint.as_ref()).await
            }),
            Endpoint::CheckSessionStatus => Box::pin(async move {
                http::check_session_status(
                    self.identity.session_management_endpoint.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::Revoke => Box::pin(async move {
                http::revoke(
                    self.core.token_management_endpoint.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::Introspect => Box::pin(async move {
                http::introspect(
                    self.core.token_management_endpoint.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::FapiResource => Box::pin(async move {
                http::fapi_resource(
                    self.core.resource_server_http_data.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::Userinfo => Box::pin(async move {
                http::userinfo(
                    self.core.userinfo_endpoint.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::ScimServiceProviderConfig => Box::pin(async move {
                http::scim_service_provider_config(self.core.scim_endpoint.as_ref(), request).await
            }),
            Endpoint::ScimSchemas => Box::pin(async move {
                http::scim_schemas(self.core.scim_endpoint.as_ref(), request).await
            }),
            Endpoint::ScimResourceTypes => Box::pin(async move {
                http::scim_resource_types(self.core.scim_endpoint.as_ref(), request).await
            }),
            Endpoint::ScimPollSecurityEvents => Box::pin(async move {
                http::scim_poll_security_events(
                    self.core.scim_endpoint.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::ScimListUsers => Box::pin(async move {
                http::scim_list_users(self.core.scim_endpoint.as_ref(), request).await
            }),
            Endpoint::ScimCreateUser => Box::pin(async move {
                http::scim_create_user(
                    self.core.scim_endpoint.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::ScimGetUser => Box::pin(async move {
                http::scim_get_user(
                    self.core.scim_endpoint.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("user_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::ScimReplaceUser => Box::pin(async move {
                http::scim_replace_user(
                    self.core.scim_endpoint.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("user_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::ScimPatchUser => Box::pin(async move {
                http::scim_patch_user(
                    self.core.scim_endpoint.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("user_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::ScimDeleteUser => Box::pin(async move {
                http::scim_delete_user(
                    self.core.scim_endpoint.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("user_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::SendCode => Box::pin(async move {
                http::send_code(
                    self.identity.local_registration_endpoint.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::Register => Box::pin(async move {
                http::register(
                    self.identity.local_registration_endpoint.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::Login => Box::pin(async move {
                http::login(
                    self.identity.password_login_endpoint.as_ref(),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::FederationProviderList => Box::pin(async move {
                crate::endpoints::auth::federation::federation_provider_list(
                    self.identity.federation_http_config.as_ref(),
                )
                .await
            }),
            Endpoint::FederationSamlAcs => Box::pin(async move {
                crate::endpoints::auth::federation::federation_saml_acs(
                    self.identity.auth_request_limiter.as_ref(),
                    self.identity.client_ip_config.as_ref(),
                    self.identity.federation.as_ref(),
                    self.identity.federation_http_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::FederationProviderStart => Box::pin(async move {
                crate::endpoints::auth::federation::federation_provider_start(
                    self.identity.auth_request_limiter.as_ref(),
                    self.identity.client_ip_config.as_ref(),
                    self.identity.federation.as_ref(),
                    self.identity.federation_http_config.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("provider_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::FederationProviderCallback => Box::pin(async move {
                crate::endpoints::auth::federation::federation_provider_callback(
                    self.identity.auth_request_limiter.as_ref(),
                    self.identity.client_ip_config.as_ref(),
                    self.identity.federation.as_ref(),
                    self.identity.federation_http_config.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("provider_id").expect("manifest capture")
                    )),
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::PasskeyLoginBegin => Box::pin(async move {
                http::passkey_login_begin(
                    self.identity.passkey_login_endpoint.as_ref(),
                    request,
                    http::parse_json(request).map_err(|_| ()),
                )
                .await
            }),
            Endpoint::PasskeyLoginFinish => Box::pin(async move {
                http::passkey_login_finish(
                    self.identity.passkey_login_endpoint.as_ref(),
                    request,
                    http::parse_json(request).map_err(|_| ()),
                )
                .await
            }),
            Endpoint::MfaVerify => Box::pin(async move {
                http::mfa_verify(
                    self.identity.mfa_profiles.as_ref(),
                    request,
                    extract!(http::parse_mfa_json(request)),
                )
                .await
            }),
            Endpoint::MfaOptions => Box::pin(async move { http::mfa_options().await }),
            Endpoint::Csrf => Box::pin(async move {
                crate::endpoints::auth::csrf::csrf(
                    self.identity.session_profiles.as_ref(),
                    self.identity.csrf_http_config.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::ProfileMe => Box::pin(async move {
                http::profile_me(self.identity.profile_account_endpoint.as_ref(), request).await
            }),
            Endpoint::ProfileUpdate => Box::pin(async move {
                http::profile_update(
                    self.identity.profile_account_endpoint.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::PasskeyList => Box::pin(async move {
                http::passkey_list(self.identity.passkey_profile_endpoint.as_ref(), request).await
            }),
            Endpoint::PasskeyRegistrationBegin => Box::pin(async move {
                http::passkey_registration_begin(
                    self.identity.passkey_profile_endpoint.as_ref(),
                    request,
                    http::parse_json(request).map_err(|_| ()),
                )
                .await
            }),
            Endpoint::PasskeyRegistrationFinish => Box::pin(async move {
                http::passkey_registration_finish(
                    self.identity.passkey_profile_endpoint.as_ref(),
                    request,
                    http::parse_json(request).map_err(|_| ()),
                )
                .await
            }),
            Endpoint::PasskeyDelete => Box::pin(async move {
                http::passkey_delete(
                    self.identity.passkey_profile_endpoint.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("passkey_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::MfaTotpBegin => Box::pin(async move {
                http::mfa_totp_begin(self.identity.mfa_profiles.as_ref(), request).await
            }),
            Endpoint::MfaTotpConfirm => Box::pin(async move {
                http::mfa_totp_confirm(
                    self.identity.mfa_profiles.as_ref(),
                    request,
                    extract!(http::parse_mfa_json(request)),
                )
                .await
            }),
            Endpoint::MfaStepUp => Box::pin(async move {
                http::mfa_step_up(
                    self.identity.mfa_profiles.as_ref(),
                    request,
                    extract!(http::parse_mfa_json(request)),
                )
                .await
            }),
            Endpoint::MfaBackupCodesRegenerate => Box::pin(async move {
                http::mfa_backup_codes_regenerate(
                    self.identity.mfa_profiles.as_ref(),
                    request,
                    extract!(http::parse_mfa_json(request)),
                )
                .await
            }),
            Endpoint::MfaDisable => Box::pin(async move {
                http::mfa_disable(
                    self.identity.mfa_profiles.as_ref(),
                    request,
                    extract!(http::parse_mfa_json(request)),
                )
                .await
            }),
            Endpoint::GetAvatar => Box::pin(async move {
                crate::endpoints::profile::avatar::get_avatar(
                    self.identity.session_profiles.as_ref(),
                    self.identity.avatar_profiles.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::DeleteAvatar => Box::pin(async move {
                crate::endpoints::profile::avatar::delete_avatar(
                    self.identity.session_profiles.as_ref(),
                    self.identity.avatar_profiles.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::AvatarUploadCapability => Box::pin(async move {
                crate::endpoints::profile::avatar::avatar_upload_capability(
                    self.identity.session_profiles.as_ref(),
                    self.identity.avatar_profiles.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::BeginDirectAvatarUpload => Box::pin(async move {
                crate::endpoints::profile::avatar::begin_direct_avatar_upload(
                    self.identity.session_profiles.as_ref(),
                    self.identity.avatar_profiles.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::CompleteDirectAvatarUpload => Box::pin(async move {
                crate::endpoints::profile::avatar::complete_direct_avatar_upload(
                    self.identity.session_profiles.as_ref(),
                    self.identity.avatar_profiles.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("upload_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::ProfileApplications => Box::pin(async move {
                http::profile_applications(self.identity.profile_account_endpoint.as_ref(), request)
                    .await
            }),
            Endpoint::MyFederationLinks => Box::pin(async move {
                crate::endpoints::profile::federation_links::my_federation_links(
                    self.identity.session_profiles.as_ref(),
                    self.identity.profile_federation.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::UnlinkMyFederationLink => Box::pin(async move {
                crate::endpoints::profile::federation_links::unlink_my_federation_link(
                    self.identity.session_profiles.as_ref(),
                    self.identity.profile_federation.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("link_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::MyAccessRequests => Box::pin(async move {
                crate::endpoints::profile::access_requests::my_access_requests(
                    self.identity.session_profiles.as_ref(),
                    self.identity.profile_access_requests.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::CreateAccessRequest => Box::pin(async move {
                crate::endpoints::profile::access_requests::create_access_request(
                    self.identity.session_profiles.as_ref(),
                    self.identity.profile_access_requests.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::MyMtlsTrustRequests => Box::pin(async move {
                crate::endpoints::profile::mtls_trust::my_mtls_trust_requests(
                    self.identity.session_profiles.as_ref(),
                    self.identity.mtls_trust_anchors.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::CreateMtlsTrustRequest => Box::pin(async move {
                crate::endpoints::profile::mtls_trust::create_mtls_trust_request(
                    self.identity.session_profiles.as_ref(),
                    self.identity.mtls_trust_anchors.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AccessDelivery => Box::pin(async move {
                crate::endpoints::profile::delivery::access_delivery(
                    self.identity.session_profiles.as_ref(),
                    self.identity.profile_access_requests.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::CibaVerification => Box::pin(async move {
                crate::endpoints::token::ciba::ciba_verification(
                    self.core.ciba_application.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("auth_req_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::CibaDecision => Box::pin(async move {
                crate::endpoints::token::ciba::ciba_decision(
                    self.core.ciba_application.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("auth_req_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::ProfileLogout => Box::pin(async move {
                http::profile_logout(self.identity.profile_logout_endpoint.as_ref(), request).await
            }),
            Endpoint::ControllerSlots => Box::pin(async move {
                crate::endpoints::admin::controller_registry::controller_slots(
                    &require!(self.deployment.as_ref()).controller_registry,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AdminUsers => Box::pin(async move {
                crate::endpoints::admin::users::admin_users(
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_users.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AdminCreateUser => Box::pin(async move {
                crate::endpoints::admin::users::admin_create_user(
                    self.core.security_audit.as_ref(),
                    self.password_hasher.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_user_registration.as_ref(),
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminPatchUser => Box::pin(async move {
                crate::endpoints::admin::users::admin_patch_user(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_users.as_ref(),
                    self.identity.client_ip_config.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("user_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::SystemSetTenantAdmin => Box::pin(async move {
                crate::endpoints::admin::users::system_set_tenant_admin(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_users.as_ref(),
                    require!(self.deployment.as_ref())
                        .capabilities
                        .tenants
                        .as_ref(),
                    require!(self.deployment.as_ref())
                        .capabilities
                        .control_tenant,
                    self.identity.client_ip_config.as_ref(),
                    request,
                    (
                        extract!(http::parse_path(
                            params.get("tenant_id").expect("manifest capture")
                        )),
                        extract!(http::parse_path(
                            params.get("user_id").expect("manifest capture")
                        )),
                    ),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminClients => Box::pin(async move {
                crate::endpoints::admin::clients::list::admin_clients(
                    self.identity.admin_sessions.as_ref(),
                    self.core.admin_client_service.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AdminCreateClient => Box::pin(async move {
                crate::endpoints::admin::clients::create::admin_create_client(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.core.admin_client_service.as_ref(),
                    self.core.admin_client_config.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminClientTemplates => Box::pin(async move {
                crate::endpoints::admin::clients::templates::admin_client_templates(
                    self.identity.admin_sessions.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::AdminGetClient => Box::pin(async move {
                crate::endpoints::admin::clients::detail::admin_get_client(
                    self.identity.admin_sessions.as_ref(),
                    self.core.admin_client_service.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("client_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::AdminPatchClient => Box::pin(async move {
                crate::endpoints::admin::clients::update::admin_patch_client(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.core.admin_client_service.as_ref(),
                    self.core.admin_client_config.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("client_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminFederationProviders => Box::pin(async move {
                crate::endpoints::admin::federation::admin_federation_providers(
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_federation.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::AdminGrants => Box::pin(async move {
                crate::endpoints::admin::grants::admin_grants(
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_grants.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AdminRevokeGrant => Box::pin(async move {
                crate::endpoints::admin::grants::admin_revoke_grant(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_grants.as_ref(),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminAccessRequests => Box::pin(async move {
                crate::endpoints::admin::access_requests::admin_access_requests(
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_access_requests.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AdminMtlsTrustRequests => Box::pin(async move {
                crate::endpoints::admin::mtls_trust::admin_mtls_trust_requests(
                    self.identity.admin_sessions.as_ref(),
                    self.identity.mtls_trust_anchors.as_ref(),
                    request,
                    extract!(http::parse_query(request)),
                )
                .await
            }),
            Endpoint::AdminMtlsTrustBundle => Box::pin(async move {
                crate::endpoints::admin::mtls_trust::admin_mtls_trust_bundle(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.mtls_trust_anchors.as_ref(),
                    request,
                )
                .await
            }),
            Endpoint::AdminApproveMtlsTrustRequest => Box::pin(async move {
                crate::endpoints::admin::mtls_trust::admin_approve_mtls_trust_request(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.mtls_trust_anchors.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("request_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminRejectMtlsTrustRequest => Box::pin(async move {
                crate::endpoints::admin::mtls_trust::admin_reject_mtls_trust_request(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.mtls_trust_anchors.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("request_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminRevokeMtlsTrustAnchor => Box::pin(async move {
                crate::endpoints::admin::mtls_trust::admin_revoke_mtls_trust_anchor(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.mtls_trust_anchors.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("request_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminApproveAccessRequest => Box::pin(async move {
                crate::endpoints::admin::access_requests::admin_approve_access_request(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    (
                        self.identity.admin_access_requests.as_ref(),
                        self.identity.admin_access_delivery.as_ref(),
                        self.core.admin_client_service.as_ref(),
                        self.identity.admin_access_request_config.as_ref(),
                        self.identity.client_ip_config.as_ref(),
                    ),
                    request,
                    extract!(http::parse_path(
                        params.get("request_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminRejectAccessRequest => Box::pin(async move {
                crate::endpoints::admin::access_requests::admin_reject_access_request(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    self.identity.admin_access_requests.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("request_id").expect("manifest capture")
                    )),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminGetCredentialDataset => Box::pin(async move {
                crate::endpoints::admin::openid4vc::admin_get_credential_dataset(
                    self.identity.admin_sessions.as_ref(),
                    require!(self.core.credential_dataset_admin.as_deref()),
                    request,
                    (
                        extract!(http::parse_path(
                            params.get("subject_id").expect("manifest capture")
                        )),
                        extract!(http::parse_path(
                            params.get("configuration_id").expect("manifest capture")
                        )),
                    ),
                )
                .await
            }),
            Endpoint::AdminPutCredentialDataset => Box::pin(async move {
                crate::endpoints::admin::openid4vc::admin_put_credential_dataset(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    require!(self.core.credential_dataset_admin.as_deref()),
                    request,
                    (
                        extract!(http::parse_path(
                            params.get("subject_id").expect("manifest capture")
                        )),
                        extract!(http::parse_path(
                            params.get("configuration_id").expect("manifest capture")
                        )),
                    ),
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::AdminDeleteCredentialDataset => Box::pin(async move {
                crate::endpoints::admin::openid4vc::admin_delete_credential_dataset(
                    self.core.security_audit.as_ref(),
                    self.identity.admin_sessions.as_ref(),
                    require!(self.core.credential_dataset_admin.as_deref()),
                    request,
                    (
                        extract!(http::parse_path(
                            params.get("subject_id").expect("manifest capture")
                        )),
                        extract!(http::parse_path(
                            params.get("configuration_id").expect("manifest capture")
                        )),
                    ),
                )
                .await
            }),
            Endpoint::ControllerRecoveryChallenge => Box::pin(async move {
                crate::endpoints::admin::controller_recovery::controller_recovery_challenge(
                    &require!(self.deployment.as_ref()).recovery_root,
                    extract!(http::parse_json_limit(request, 8192)),
                )
                .await
            }),
            Endpoint::ControllerRecoveryCommit => Box::pin(async move {
                crate::endpoints::admin::controller_recovery::controller_recovery_commit(
                    &require!(self.deployment.as_ref()).recovery_root,
                    extract!(http::parse_json_limit(request, 8192)),
                )
                .await
            }),
            Endpoint::ClientConfigurationGet => Box::pin(async move {
                http::client_configuration_get(
                    self.core.dynamic_registration_handles.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("client_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::ClientConfigurationDelete => Box::pin(async move {
                http::client_configuration_delete(
                    self.core.dynamic_registration_handles.as_ref(),
                    request,
                    extract!(http::parse_path(
                        params.get("client_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::CreateCredentialOffer => Box::pin(async move {
                crate::openid4vc::create_credential_offer(
                    require!(self.core.credential_issuer_endpoint.as_deref()),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::CredentialOffer => Box::pin(async move {
                crate::openid4vc::credential_offer(
                    require!(self.core.credential_issuer_endpoint.as_deref()),
                    extract!(http::parse_path(
                        params.get("offer_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::CredentialNonce => Box::pin(async move {
                crate::openid4vc::credential_nonce(
                    require!(self.core.credential_issuer_endpoint.as_deref()),
                    request,
                )
                .await
            }),
            Endpoint::Credential => Box::pin(async move {
                crate::openid4vc::credential(
                    require!(self.core.credential_issuer_endpoint.as_deref()),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::DeferredCredential => Box::pin(async move {
                crate::openid4vc::deferred_credential(
                    require!(self.core.credential_issuer_endpoint.as_deref()),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::Notification => Box::pin(async move {
                crate::openid4vc::notification(
                    require!(self.core.credential_issuer_endpoint.as_deref()),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::PresentationComplete => Box::pin(async move {
                crate::openid4vc::presentation_complete(
                    require!(self.core.presentation_endpoint.as_deref()),
                    extract!(http::parse_path(
                        params.get("transaction_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::CreatePresentation => Box::pin(async move {
                crate::openid4vc::create_presentation(
                    require!(self.core.presentation_endpoint.as_deref()),
                    request,
                    extract!(http::parse_json_limit(request, 2097152)),
                )
                .await
            }),
            Endpoint::PresentationRequest => Box::pin(async move {
                crate::openid4vc::presentation_request(
                    require!(self.core.presentation_endpoint.as_deref()),
                    extract!(http::parse_path(
                        params.get("transaction_id").expect("manifest capture")
                    )),
                    http::parse_form(request).ok(),
                )
                .await
            }),
            Endpoint::PresentationResponse => Box::pin(async move {
                crate::openid4vc::presentation_response(
                    require!(self.core.presentation_endpoint.as_deref()),
                    extract!(http::parse_path(
                        params.get("transaction_id").expect("manifest capture")
                    )),
                    request,
                    request.body(),
                )
                .await
            }),
            Endpoint::PresentationResult => Box::pin(async move {
                crate::openid4vc::presentation_result(
                    require!(self.core.presentation_endpoint.as_deref()),
                    request,
                    extract!(http::parse_path(
                        params.get("transaction_id").expect("manifest capture")
                    )),
                )
                .await
            }),
            Endpoint::Discovery
            | Endpoint::OauthAuthorizationServerMetadata
            | Endpoint::OauthProtectedResourceMetadata
            | Endpoint::Jwks
            | Endpoint::UploadAvatar
            | Endpoint::DynamicClientRegistration
            | Endpoint::ClientConfigurationPut
            | Endpoint::BackchannelAuthentication
            | Endpoint::OidcLogout => {
                Box::pin(
                    async move { unreachable!("endpoint dispatched before buffered fallback") },
                )
            }
        }
    }
}
