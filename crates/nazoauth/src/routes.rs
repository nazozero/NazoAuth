//! The product's complete HTTP surface. Adapters consume this table without owning policy.
use std::{borrow::Cow, sync::OnceLock};

use http::{HeaderName, Method, StatusCode, header};

use crate::http::{CorsPolicy, Response, finish};

/// The body representation consumed by an endpoint, after transport decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyMode {
    /// The endpoint does not consume the request body.
    None,
    /// A framework-decoded byte body, with the existing 256 KiB bound.
    Bytes,
    Json {
        limit: usize,
    },
    Form,
    /// A bounded wire body; content encoding is not decoded by this endpoint.
    Raw {
        limit: usize,
    },
    /// Multipart fields are consumed incrementally; the avatar service owns its file bound.
    Multipart,
}

impl BodyMode {
    pub const fn limit(self) -> Option<usize> {
        match self {
            Self::None => Some(0),
            Self::Bytes => Some(256 * 1024),
            Self::Json { limit } | Self::Raw { limit } => Some(limit),
            Self::Form => Some(32 * 1024),
            Self::Multipart => None,
        }
    }

    pub const fn decode_content(self) -> bool {
        matches!(self, Self::Bytes | Self::Json { .. } | Self::Form)
    }
}

/// Conditions applied before method dispatch or consuming a request body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteGuard {
    None,
    ControlTenant,
    Openid4vci,
    Openid4vp,
}

/// A concrete application endpoint, exhaustively dispatched by NazoAuth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endpoint {
    AccessDelivery,
    AdminAccessRequests,
    AdminApproveAccessRequest,
    AdminApproveMtlsTrustRequest,
    AdminClientTemplates,
    AdminClients,
    #[cfg(feature = "deployment-control")]
    AdminControllerApproval,
    #[cfg(feature = "deployment-control")]
    AdminControllerSlotCommit,
    #[cfg(feature = "deployment-control")]
    AdminControllerSlotRevoke,
    #[cfg(feature = "deployment-control")]
    AdminControllerSlotRotate,
    AdminCreateClient,
    AdminCreateUser,
    AdminDeleteCredentialDataset,
    AdminFederationProviders,
    AdminGetClient,
    AdminGetCredentialDataset,
    AdminGrants,
    AdminMtlsTrustBundle,
    AdminMtlsTrustRequests,
    AdminPatchClient,
    AdminPatchRuntimeModule,
    AdminPatchUser,
    AdminPutCredentialDataset,
    #[cfg(feature = "deployment-control")]
    AdminRecoveryRoot,
    #[cfg(feature = "deployment-control")]
    AdminRecoveryRootApproval,
    #[cfg(feature = "deployment-control")]
    AdminRecoveryRootRotate,
    AdminRejectAccessRequest,
    AdminRejectMtlsTrustRequest,
    AdminRevokeGrant,
    AdminRevokeMtlsTrustAnchor,
    AdminRuntimeModuleEvents,
    AdminRuntimeModules,
    AdminUsers,
    AuthorizeClientPresentation,
    AuthorizeConsent,
    AuthorizeDecision,
    AuthorizeGet,
    AuthorizePost,
    AvatarUploadCapability,
    BackchannelAuthentication,
    BeginDirectAvatarUpload,
    CheckSessionIframe,
    CheckSessionStatus,
    CibaDecision,
    CibaVerification,
    CibaVerificationPage,
    ClientConfigurationDelete,
    ClientConfigurationGet,
    ClientConfigurationPut,
    CompleteDirectAvatarUpload,
    #[cfg(feature = "deployment-control")]
    ControlDiscovery,
    #[cfg(feature = "deployment-control")]
    ControllerRecoveryChallenge,
    #[cfg(feature = "deployment-control")]
    ControllerRecoveryCommit,
    #[cfg(feature = "deployment-control")]
    ControllerSlots,
    CreateAccessRequest,
    CreateCredentialOffer,
    CreateMtlsTrustRequest,
    CreatePresentation,
    Credential,
    CredentialIssuerMetadata,
    CredentialNonce,
    CredentialOffer,
    Csrf,
    DeferredCredential,
    DeleteAvatar,
    DeviceAuthorization,
    DeviceDecision,
    DeviceVerification,
    DeviceVerificationPage,
    Discovery,
    DynamicClientRegistration,
    FapiResource,
    FederationProviderCallback,
    FederationProviderList,
    FederationProviderStart,
    FederationSamlAcs,
    GetAvatar,
    Introspect,
    Jwks,
    Live,
    Login,
    MdocCrl,
    MfaBackupCodesRegenerate,
    MfaDisable,
    MfaOptions,
    MfaStepUp,
    MfaTotpBegin,
    MfaTotpConfirm,
    MfaVerify,
    MyAccessRequests,
    MyFederationLinks,
    MyMtlsTrustRequests,
    Notification,
    OauthAuthorizationServerMetadata,
    OauthProtectedResourceMetadata,
    OidcLogout,
    Par,
    PasskeyDelete,
    PasskeyList,
    PasskeyLoginBegin,
    PasskeyLoginFinish,
    PasskeyRegistrationBegin,
    PasskeyRegistrationFinish,
    PresentationComplete,
    PresentationRequest,
    PresentationResponse,
    PresentationResult,
    ProfileApplications,
    ProfileLogout,
    ProfileMe,
    ProfileUpdate,
    Ready,
    Register,
    Revoke,
    ScimCreateUser,
    ScimDeleteUser,
    ScimGetUser,
    ScimListUsers,
    ScimPatchUser,
    ScimPollSecurityEvents,
    ScimReplaceUser,
    ScimResourceTypes,
    ScimSchemas,
    ScimServiceProviderConfig,
    SendCode,
    Startup,
    #[cfg(feature = "deployment-control")]
    SystemSetTenantAdmin,
    Token,
    UnlinkMyFederationLink,
    UploadAvatar,
    Userinfo,
}

impl Endpoint {
    pub const fn available_in(self, profile: nazo_auth::DeploymentProfile) -> bool {
        use nazo_auth::DeploymentProfile;

        if matches!(profile, DeploymentProfile::Full) {
            return true;
        }
        if matches!(
            self,
            Self::OauthAuthorizationServerMetadata
                | Self::OauthProtectedResourceMetadata
                | Self::Jwks
                | Self::Ready
                | Self::Live
                | Self::Startup
                | Self::FapiResource
                | Self::Token
                | Self::Revoke
                | Self::Introspect
                | Self::DynamicClientRegistration
                | Self::ClientConfigurationGet
                | Self::ClientConfigurationPut
                | Self::ClientConfigurationDelete
        ) {
            return true;
        }
        matches!(profile, DeploymentProfile::PasskeyOnly)
            && matches!(
                self,
                Self::Discovery
                    | Self::CheckSessionIframe
                    | Self::CheckSessionStatus
                    | Self::DeviceAuthorization
                    | Self::DeviceDecision
                    | Self::DeviceVerification
                    | Self::DeviceVerificationPage
                    | Self::AuthorizeGet
                    | Self::AuthorizePost
                    | Self::AuthorizeConsent
                    | Self::AuthorizeDecision
                    | Self::AuthorizeClientPresentation
                    | Self::Userinfo
                    | Self::ProfileMe
                    | Self::ProfileUpdate
                    | Self::ProfileLogout
                    | Self::Csrf
                    | Self::PasskeyDelete
                    | Self::PasskeyList
                    | Self::PasskeyLoginBegin
                    | Self::PasskeyLoginFinish
                    | Self::PasskeyRegistrationBegin
                    | Self::PasskeyRegistrationFinish
                    | Self::MfaVerify
                    | Self::MfaOptions
                    | Self::MfaTotpBegin
                    | Self::MfaTotpConfirm
                    | Self::MfaStepUp
                    | Self::MfaBackupCodesRegenerate
                    | Self::MfaDisable
                    | Self::OidcLogout
                    | Self::Par
            )
    }
}

#[derive(Debug)]
pub struct RouteMethod {
    pub method: Method,
    pub endpoint: Endpoint,
    pub body: BodyMode,
}

#[derive(Debug)]
pub struct Route {
    pub path: &'static str,
    pub methods: &'static [RouteMethod],
    pub(crate) cors: CorsPolicy,
    pub(crate) guard: RouteGuard,
    allowed_methods: &'static str,
    needs_connection_facts: bool,
    request_headers: Option<&'static [HeaderName]>,
    nonce_admission: bool,
}

impl Route {
    pub fn available_in(&self, profile: nazo_auth::DeploymentProfile, method: &Method) -> bool {
        profile == nazo_auth::DeploymentProfile::Full
            || self.methods.iter().any(|entry| {
                (method == Method::OPTIONS || entry.method == *method)
                    && entry.endpoint.available_in(profile)
            })
    }

    const fn new(
        path: &'static str,
        methods: &'static [RouteMethod],
        cors: CorsPolicy,
        guard: RouteGuard,
        allowed_methods: &'static str,
    ) -> Self {
        const METADATA_HEADERS: &[HeaderName] = &[
            header::ORIGIN,
            header::ACCESS_CONTROL_REQUEST_METHOD,
            header::ACCESS_CONTROL_REQUEST_HEADERS,
        ];
        let mut needs_connection_facts = false;
        let mut request_headers = Some(METADATA_HEADERS);
        let mut nonce_admission = false;
        let mut index = 0;
        while index < methods.len() {
            match methods[index].endpoint {
                Endpoint::Discovery
                | Endpoint::OauthAuthorizationServerMetadata
                | Endpoint::OauthProtectedResourceMetadata
                | Endpoint::Jwks => {}
                endpoint => {
                    needs_connection_facts = true;
                    request_headers = None;
                    if matches!(endpoint, Endpoint::CredentialNonce) {
                        nonce_admission = true;
                    }
                }
            }
            index += 1;
        }
        Self {
            path,
            methods,
            cors,
            guard,
            allowed_methods,
            needs_connection_facts,
            request_headers,
            nonce_admission,
        }
    }

    pub(crate) fn resolve_method(&self, method: &Method) -> Result<&'static RouteMethod, Response> {
        if let Some(found) = self.methods.iter().find(|entry| entry.method == *method) {
            return Ok(found);
        }
        if self
            .methods
            .iter()
            .any(|entry| entry.endpoint == Endpoint::MfaOptions)
        {
            return Err(crate::http::mfa_method_not_allowed());
        }
        Err(finish(
            http::Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(header::ALLOW, self.allowed_methods),
            bytes::Bytes::new(),
        ))
    }

    /// Lets a transport choose its decoder before polling the payload. Rejections
    /// still belong to the facade, including capability checks and CORS.
    pub fn body(&self, method: &Method) -> BodyMode {
        self.methods
            .iter()
            .find(|entry| entry.method == *method)
            .map_or(BodyMode::None, |entry| entry.body)
    }

    /// Whether this resource consumes connection facts, including admission
    /// checks that run before method resolution.
    pub const fn needs_connection_facts(&self) -> bool {
        self.needs_connection_facts
    }

    /// Request headers consumed by this resource, including CORS and unsupported
    /// methods. `None` requires all headers; a list retains every repeated value.
    pub const fn request_headers(&self) -> Option<&'static [HeaderName]> {
        self.request_headers
    }

    pub(crate) const fn needs_nonce_admission(&self) -> bool {
        self.nonce_admission
    }
}

/// Captures borrow the URI path; unescaped parameters do not need an allocation.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct RouteMatch<'path> {
    pub route: &'static Route,
    pub method: &'static RouteMethod,
    pub params: matchit::Params<'static, 'path>,
}

pub fn routes() -> &'static [Route] {
    ROUTES
}

fn in_scope(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Policies belonging to a resource scope also govern its unknown paths.
pub(crate) fn unmatched_policy(path: &str) -> (CorsPolicy, RouteGuard) {
    if in_scope(path, "/admin/controller-registry") || in_scope(path, "/admin/tenants") {
        (CorsPolicy::Admin, RouteGuard::ControlTenant)
    } else if in_scope(path, "/admin/openid4vci") {
        (CorsPolicy::Admin, RouteGuard::Openid4vci)
    } else if in_scope(path, "/admin") {
        (CorsPolicy::Admin, RouteGuard::None)
    } else if in_scope(path, "/.well-known") {
        (CorsPolicy::WellKnown, RouteGuard::None)
    } else if in_scope(path, "/auth/me") {
        (CorsPolicy::AuthApi, RouteGuard::None)
    } else if in_scope(path, "/scim/v2") {
        (CorsPolicy::Scim, RouteGuard::None)
    } else if in_scope(path, "/openid4vci") {
        (CorsPolicy::None, RouteGuard::Openid4vci)
    } else if in_scope(path, "/openid4vp") {
        (CorsPolicy::None, RouteGuard::Openid4vp)
    } else if in_scope(path, "/controller-recovery") {
        (CorsPolicy::None, RouteGuard::ControlTenant)
    } else {
        (CorsPolicy::None, RouteGuard::None)
    }
}

/// These deployment controls reject before their local CORS middleware. Other
/// guards are inside a public scope whose CORS policy still owns the response.
pub(crate) fn guard_precedes_cors(path: &str) -> bool {
    path == "/.well-known/nazoauth-control" || in_scope(path, "/admin/controller-registry")
}

/// Normalize escapes for routing while retaining escaped separators, percent and
/// plus. The original URI remains authoritative for signed request targets.
/// Paths needing no change borrow the caller's buffer.
pub(crate) fn routing_path(path: &str) -> Cow<'_, str> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let Some(mut cursor) = path.find('%') else {
        return Cow::Borrowed(path);
    };
    let input = path.as_bytes();
    let mut output: Option<Vec<u8>> = None;
    let mut copied = 0;
    while cursor + 2 < input.len() {
        if input[cursor] == b'%'
            && let (Some(high), Some(low)) = (hex(input[cursor + 1]), hex(input[cursor + 2]))
        {
            let decoded = (high << 4) | low;
            if !matches!(decoded, b'%' | b'/' | b'+') {
                let output = output.get_or_insert_with(|| Vec::with_capacity(input.len()));
                output.extend_from_slice(&input[copied..cursor]);
                output.push(decoded);
                cursor += 3;
                copied = cursor;
                continue;
            }
        }
        cursor += 1;
    }
    let Some(mut output) = output else {
        return Cow::Borrowed(path);
    };
    output.extend_from_slice(&input[copied..]);
    Cow::Owned(
        String::from_utf8(output)
            .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()),
    )
}

/// A single radix-tree lookup. The facade can apply route guards and CORS before
/// resolving the method, without parsing or searching the path a second time.
/// Pass the result of [`routing_path`] to preserve escaped route semantics.
pub(crate) fn match_path(path: &str) -> Option<(&'static Route, matchit::Params<'static, '_>)> {
    static ROUTER: OnceLock<matchit::Router<&'static Route>> = OnceLock::new();
    let router = ROUTER.get_or_init(|| {
        let mut router = matchit::Router::new();
        for route in ROUTES {
            router
                .insert(route.path, route)
                .expect("canonical routes must be unambiguous");
        }
        router
    });
    let matched = router.at(path).ok()?;
    Some((*matched.value, matched.params))
}

/// Look up transport metadata from the original URI path using the facade's
/// normalization rules. This does not resolve the method or apply registration,
/// capability or CORS policy; those checks remain in the facade.
pub fn route_for_path(raw_path: &str) -> Option<&'static Route> {
    let path = routing_path(raw_path);
    match_path(&path).map(|(route, _)| route)
}

#[cfg(any(test, feature = "test-support"))]
pub fn resolve<'path>(method: &Method, path: &'path str) -> Result<RouteMatch<'path>, Response> {
    let (route, params) =
        match_path(path).ok_or_else(|| crate::http::empty_response(StatusCode::NOT_FOUND))?;
    let method = route.resolve_method(method)?;
    Ok(RouteMatch {
        route,
        method,
        params,
    })
}

macro_rules! route {
    ($path:literal, $cors:ident, $guard:ident, $first_method:ident => $first_endpoint:ident ($first_body:expr) $(, $method:ident => $endpoint:ident ($body:expr))* $(,)?) => {
        Route::new(
            $path,
            &[
                RouteMethod { method: Method::$first_method, endpoint: Endpoint::$first_endpoint, body: $first_body },
                $(RouteMethod { method: Method::$method, endpoint: Endpoint::$endpoint, body: $body },)*
            ],
            CorsPolicy::$cors,
            RouteGuard::$guard,
            concat!(stringify!($first_method), $(", ", stringify!($method),)*),
        )
    };
}

static ROUTES: &[Route] = &[
    route!("/.well-known/openid-configuration", WellKnown, None, GET => Discovery(BodyMode::None)),
    route!("/.well-known/oauth-authorization-server", WellKnown, None, GET => OauthAuthorizationServerMetadata(BodyMode::None)),
    route!("/.well-known/oauth-protected-resource", WellKnown, None, GET => OauthProtectedResourceMetadata(BodyMode::None)),
    route!("/.well-known/oauth-protected-resource/", WellKnown, None, GET => OauthProtectedResourceMetadata(BodyMode::None)),
    route!("/.well-known/oauth-protected-resource/{*tail}", WellKnown, None, GET => OauthProtectedResourceMetadata(BodyMode::None)),
    route!("/.well-known/mdoc/{issuer_id}.crl", WellKnown, None, GET => MdocCrl(BodyMode::None)),
    route!("/.well-known/openid-credential-issuer", WellKnown, Openid4vci, GET => CredentialIssuerMetadata(BodyMode::None)),
    #[cfg(feature = "deployment-control")]
    route!("/.well-known/nazoauth-control", WellKnown, ControlTenant, POST => ControlDiscovery(BodyMode::Json { limit: 2048 })),
    route!("/admin/runtime-modules", Admin, None, GET => AdminRuntimeModules(BodyMode::None)),
    route!("/admin/runtime-modules/events", Admin, None, GET => AdminRuntimeModuleEvents(BodyMode::None)),
    route!("/admin/runtime-modules/{module_id}", Admin, None, PATCH => AdminPatchRuntimeModule(BodyMode::Json { limit: 2097152 })),
    #[cfg(feature = "deployment-control")]
    route!("/admin/controller-registry/slots", Admin, ControlTenant, POST => AdminControllerSlotCommit(BodyMode::Json { limit: 8192 })),
    #[cfg(feature = "deployment-control")]
    route!("/admin/controller-registry/slots/rotate", Admin, ControlTenant, POST => AdminControllerSlotRotate(BodyMode::Json { limit: 8192 })),
    #[cfg(feature = "deployment-control")]
    route!("/admin/controller-registry/slots/revoke", Admin, ControlTenant, POST => AdminControllerSlotRevoke(BodyMode::Json { limit: 8192 })),
    #[cfg(feature = "deployment-control")]
    route!("/admin/controller-registry/approvals", Admin, ControlTenant, POST => AdminControllerApproval(BodyMode::Json { limit: 8192 })),
    #[cfg(feature = "deployment-control")]
    route!("/admin/controller-registry/recovery-root", Admin, ControlTenant, GET => AdminRecoveryRoot(BodyMode::None)),
    #[cfg(feature = "deployment-control")]
    route!("/admin/controller-registry/recovery-root/approvals", Admin, ControlTenant, POST => AdminRecoveryRootApproval(BodyMode::Json { limit: 8192 })),
    #[cfg(feature = "deployment-control")]
    route!("/admin/controller-registry/recovery-root/rotate", Admin, ControlTenant, POST => AdminRecoveryRootRotate(BodyMode::Json { limit: 8192 })),
    route!("/health", WellKnown, None, GET => Ready(BodyMode::None)),
    route!("/live", WellKnown, None, GET => Live(BodyMode::None)),
    route!("/startup", WellKnown, None, GET => Startup(BodyMode::None)),
    route!("/authorize", None, None, GET => AuthorizeGet(BodyMode::None), POST => AuthorizePost(BodyMode::Bytes)),
    route!("/authorize/client-presentation", None, None, GET => AuthorizeClientPresentation(BodyMode::None)),
    route!("/authorize/consent", None, None, GET => AuthorizeConsent(BodyMode::None)),
    route!("/authorize/decision", None, None, POST => AuthorizeDecision(BodyMode::Form)),
    route!("/par", None, None, POST => Par(BodyMode::Bytes)),
    route!("/bc-authorize", None, None, POST => BackchannelAuthentication(BodyMode::Raw { limit: 16384 })),
    route!("/ciba/{auth_req_id}", None, None, GET => CibaVerificationPage(BodyMode::None)),
    route!("/device_authorization", None, None, POST => DeviceAuthorization(BodyMode::Bytes)),
    route!("/device", None, None, GET => DeviceVerificationPage(BodyMode::None)),
    route!("/device/verification", None, None, GET => DeviceVerification(BodyMode::None)),
    route!("/device/decision", None, None, POST => DeviceDecision(BodyMode::Form)),
    route!("/token", BrowserTokenManagement, None, POST => Token(BodyMode::Bytes)),
    route!("/logout", None, None, GET => OidcLogout(BodyMode::None), POST => OidcLogout(BodyMode::Raw { limit: 16384 })),
    route!("/check_session", None, None, GET => CheckSessionIframe(BodyMode::None)),
    route!("/check_session/status", None, None, GET => CheckSessionStatus(BodyMode::None)),
    route!("/revoke", BrowserTokenManagement, None, POST => Revoke(BodyMode::Bytes)),
    route!("/introspect", None, None, POST => Introspect(BodyMode::Bytes)),
    route!("/fapi/resource", None, None, GET => FapiResource(BodyMode::Bytes), POST => FapiResource(BodyMode::Bytes)),
    route!("/jwks.json", WellKnown, None, GET => Jwks(BodyMode::None)),
    route!("/userinfo", BrowserUserinfo, None, GET => Userinfo(BodyMode::Bytes), POST => Userinfo(BodyMode::Bytes)),
    route!("/scim/v2/ServiceProviderConfig", Scim, None, GET => ScimServiceProviderConfig(BodyMode::None)),
    route!("/scim/v2/Schemas", Scim, None, GET => ScimSchemas(BodyMode::None)),
    route!("/scim/v2/ResourceTypes", Scim, None, GET => ScimResourceTypes(BodyMode::None)),
    route!("/scim/v2/SecurityEvents", Scim, None, POST => ScimPollSecurityEvents(BodyMode::Json { limit: 2097152 })),
    route!("/scim/v2/Users", Scim, None, GET => ScimListUsers(BodyMode::None), POST => ScimCreateUser(BodyMode::Json { limit: 2097152 })),
    route!("/scim/v2/Users/{user_id}", Scim, None, GET => ScimGetUser(BodyMode::None), PUT => ScimReplaceUser(BodyMode::Json { limit: 2097152 }), PATCH => ScimPatchUser(BodyMode::Json { limit: 2097152 }), DELETE => ScimDeleteUser(BodyMode::None)),
    route!("/auth/send-code", None, None, POST => SendCode(BodyMode::Json { limit: 2097152 })),
    route!("/auth/register", None, None, POST => Register(BodyMode::Json { limit: 2097152 })),
    route!("/auth/login", None, None, POST => Login(BodyMode::Bytes)),
    route!("/auth/federation/providers", None, None, GET => FederationProviderList(BodyMode::None)),
    route!("/auth/federation/saml/acs", None, None, POST => FederationSamlAcs(BodyMode::Json { limit: 2097152 })),
    route!("/auth/federation/{provider_id}/start", None, None, GET => FederationProviderStart(BodyMode::None)),
    route!("/auth/federation/{provider_id}/callback", None, None, GET => FederationProviderCallback(BodyMode::None)),
    route!("/auth/passkey/begin", None, None, POST => PasskeyLoginBegin(BodyMode::Json { limit: 2097152 })),
    route!("/auth/passkey/finish", None, None, POST => PasskeyLoginFinish(BodyMode::Json { limit: 2097152 })),
    route!("/auth/mfa/verify", None, None, POST => MfaVerify(BodyMode::Json { limit: 2097152 }), OPTIONS => MfaOptions(BodyMode::None)),
    route!("/auth/csrf", None, None, GET => Csrf(BodyMode::None)),
    route!("/auth/me", AuthApi, None, GET => ProfileMe(BodyMode::None), PATCH => ProfileUpdate(BodyMode::Json { limit: 2097152 })),
    route!("/auth/me/passkeys", AuthApi, None, GET => PasskeyList(BodyMode::None)),
    route!("/auth/me/passkeys/registration/begin", AuthApi, None, POST => PasskeyRegistrationBegin(BodyMode::Json { limit: 2097152 })),
    route!("/auth/me/passkeys/registration/finish", AuthApi, None, POST => PasskeyRegistrationFinish(BodyMode::Json { limit: 2097152 })),
    route!("/auth/me/passkeys/{passkey_id}", AuthApi, None, DELETE => PasskeyDelete(BodyMode::None)),
    route!("/auth/me/mfa/totp/begin", AuthApi, None, POST => MfaTotpBegin(BodyMode::None), OPTIONS => MfaOptions(BodyMode::None)),
    route!("/auth/me/mfa/totp/confirm", AuthApi, None, POST => MfaTotpConfirm(BodyMode::Json { limit: 2097152 }), OPTIONS => MfaOptions(BodyMode::None)),
    route!("/auth/me/mfa/step-up", AuthApi, None, POST => MfaStepUp(BodyMode::Json { limit: 2097152 }), OPTIONS => MfaOptions(BodyMode::None)),
    route!("/auth/me/mfa/backup-codes/regenerate", AuthApi, None, POST => MfaBackupCodesRegenerate(BodyMode::Json { limit: 2097152 }), OPTIONS => MfaOptions(BodyMode::None)),
    route!("/auth/me/mfa/disable", AuthApi, None, POST => MfaDisable(BodyMode::Json { limit: 2097152 }), OPTIONS => MfaOptions(BodyMode::None)),
    route!("/auth/me/avatar", AuthApi, None, POST => UploadAvatar(BodyMode::Multipart), GET => GetAvatar(BodyMode::None), DELETE => DeleteAvatar(BodyMode::None)),
    route!("/auth/me/avatar/uploads", AuthApi, None, GET => AvatarUploadCapability(BodyMode::None), POST => BeginDirectAvatarUpload(BodyMode::Json { limit: 2097152 })),
    route!("/auth/me/avatar/uploads/{upload_id}/complete", AuthApi, None, POST => CompleteDirectAvatarUpload(BodyMode::None)),
    route!("/auth/me/applications", AuthApi, None, GET => ProfileApplications(BodyMode::None)),
    route!("/auth/me/federation/links", AuthApi, None, GET => MyFederationLinks(BodyMode::None)),
    route!("/auth/me/federation/links/{link_id}", AuthApi, None, DELETE => UnlinkMyFederationLink(BodyMode::None)),
    route!("/auth/me/access-requests", AuthApi, None, GET => MyAccessRequests(BodyMode::None), POST => CreateAccessRequest(BodyMode::Json { limit: 2097152 })),
    route!("/auth/me/mtls-trust-requests", AuthApi, None, GET => MyMtlsTrustRequests(BodyMode::None), POST => CreateMtlsTrustRequest(BodyMode::Json { limit: 2097152 })),
    route!("/auth/me/access-delivery", AuthApi, None, POST => AccessDelivery(BodyMode::Json { limit: 2097152 })),
    route!("/auth/ciba/{auth_req_id}", None, None, GET => CibaVerification(BodyMode::None), POST => CibaDecision(BodyMode::Json { limit: 2097152 })),
    route!("/auth/logout", None, None, POST => ProfileLogout(BodyMode::None)),
    #[cfg(feature = "deployment-control")]
    route!("/controller-registry/slots", None, ControlTenant, GET => ControllerSlots(BodyMode::None)),
    route!("/admin/users", Admin, None, GET => AdminUsers(BodyMode::None), POST => AdminCreateUser(BodyMode::Json { limit: 2097152 })),
    route!("/admin/users/{user_id}", Admin, None, PATCH => AdminPatchUser(BodyMode::Json { limit: 2097152 })),
    #[cfg(feature = "deployment-control")]
    route!("/admin/tenants/{tenant_id}/users/{user_id}/admin", Admin, ControlTenant, PATCH => SystemSetTenantAdmin(BodyMode::Json { limit: 2097152 })),
    route!("/admin/clients", Admin, None, GET => AdminClients(BodyMode::None), POST => AdminCreateClient(BodyMode::Json { limit: 2097152 })),
    route!("/admin/clients/templates", Admin, None, GET => AdminClientTemplates(BodyMode::None)),
    route!("/admin/clients/{client_id}", Admin, None, GET => AdminGetClient(BodyMode::None), PATCH => AdminPatchClient(BodyMode::Json { limit: 2097152 })),
    route!("/admin/federation/providers", Admin, None, GET => AdminFederationProviders(BodyMode::None)),
    route!("/admin/grants", Admin, None, GET => AdminGrants(BodyMode::None)),
    route!("/admin/grants/revoke", Admin, None, POST => AdminRevokeGrant(BodyMode::Json { limit: 2097152 })),
    route!("/admin/access-requests", Admin, None, GET => AdminAccessRequests(BodyMode::None)),
    route!("/admin/mtls-trust-requests", Admin, None, GET => AdminMtlsTrustRequests(BodyMode::None)),
    route!("/admin/mtls-trust-anchors.pem", Admin, None, GET => AdminMtlsTrustBundle(BodyMode::None)),
    route!("/admin/mtls-trust-requests/{request_id}/approve", Admin, None, POST => AdminApproveMtlsTrustRequest(BodyMode::Json { limit: 2097152 })),
    route!("/admin/mtls-trust-requests/{request_id}/reject", Admin, None, POST => AdminRejectMtlsTrustRequest(BodyMode::Json { limit: 2097152 })),
    route!("/admin/mtls-trust-requests/{request_id}/revoke", Admin, None, POST => AdminRevokeMtlsTrustAnchor(BodyMode::Json { limit: 2097152 })),
    route!("/admin/access-requests/{request_id}/approve", Admin, None, POST => AdminApproveAccessRequest(BodyMode::Json { limit: 2097152 })),
    route!("/admin/access-requests/{request_id}/reject", Admin, None, POST => AdminRejectAccessRequest(BodyMode::Json { limit: 2097152 })),
    route!("/admin/openid4vci/credential-datasets/{subject_id}/{configuration_id}", Admin, Openid4vci, GET => AdminGetCredentialDataset(BodyMode::None), PUT => AdminPutCredentialDataset(BodyMode::Json { limit: 2097152 }), DELETE => AdminDeleteCredentialDataset(BodyMode::None)),
    #[cfg(feature = "deployment-control")]
    route!("/controller-recovery/challenges", None, ControlTenant, POST => ControllerRecoveryChallenge(BodyMode::Json { limit: 8192 })),
    #[cfg(feature = "deployment-control")]
    route!("/controller-recovery/recover", None, ControlTenant, POST => ControllerRecoveryCommit(BodyMode::Json { limit: 8192 })),
    route!("/register", None, None, POST => DynamicClientRegistration(BodyMode::Json { limit: 2097152 })),
    route!("/register/{client_id}", None, None, GET => ClientConfigurationGet(BodyMode::None), PUT => ClientConfigurationPut(BodyMode::Json { limit: 2097152 }), DELETE => ClientConfigurationDelete(BodyMode::None)),
    route!("/openid4vci/offers", None, Openid4vci, POST => CreateCredentialOffer(BodyMode::Json { limit: 2097152 })),
    route!("/openid4vci/offers/{offer_id}", None, Openid4vci, GET => CredentialOffer(BodyMode::None)),
    route!("/openid4vci/nonce", None, Openid4vci, POST => CredentialNonce(BodyMode::None)),
    route!("/openid4vci/credential", None, Openid4vci, POST => Credential(BodyMode::Bytes)),
    route!("/openid4vci/deferred_credential", None, Openid4vci, POST => DeferredCredential(BodyMode::Bytes)),
    route!("/openid4vci/notification", None, Openid4vci, POST => Notification(BodyMode::Json { limit: 2097152 })),
    route!("/openid4vp/complete/{transaction_id}", None, Openid4vp, GET => PresentationComplete(BodyMode::None)),
    route!("/openid4vp/presentations", None, Openid4vp, POST => CreatePresentation(BodyMode::Json { limit: 2097152 })),
    route!("/openid4vp/request/{transaction_id}", None, Openid4vp, GET => PresentationRequest(BodyMode::Form), POST => PresentationRequest(BodyMode::Form)),
    route!("/openid4vp/response/{transaction_id}", None, Openid4vp, POST => PresentationResponse(BodyMode::Bytes)),
    route!("/openid4vp/result/{transaction_id}", None, Openid4vp, GET => PresentationResult(BodyMode::None)),
];

#[cfg(test)]
#[path = "../tests/unit/routes.rs"]
mod tests;
