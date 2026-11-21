//! Typed product configuration. The host loads process/environment configuration separately.

pub use crate::endpoints::mtls::MtlsCertificateSourceMode;
pub use crate::http::{ClientIpHeaderMode, ClientIpParseError, IpCidr, parse_trusted_proxy_cidrs};
use nazo_auth::DpopNoncePolicy;
pub use nazo_oauth_server::policy::{
    AuthorizationServerProfile, CibaSecurityProfile, Openid4vcRevocationPolicy,
    RequestObjectJtiPolicy,
};
use std::collections::BTreeMap;
pub mod federation;
pub use federation::*;
mod validation;

pub use validation::{
    MAX_ACCESS_TOKEN_TTL_SECONDS, MAX_ID_TOKEN_TTL_SECONDS, validate_token_lifetimes,
};

#[derive(Clone)]
pub struct Configuration {
    pub tenant: TenantSettings,
    pub endpoint: EndpointSettings,
    pub protocol: ProtocolSettings,
    pub session: SessionSettings,
    pub storage: StorageSettings,
    pub identity: IdentitySettings,
    pub modules: ModuleSettings,
    pub device: DeviceGrantSettings,
    pub ciba: CibaSettings,
    pub openid4vc: Openid4vcSettings,
}

#[derive(Clone)]
pub struct TenantSettings {
    pub context: nazo_identity::TenantContext,
}

#[derive(Clone)]
pub struct ProtocolSettings {
    /// Whether the host exposes end-user authorization and identity endpoints.
    pub user_authorization_supported: bool,
    /// Whether the host supplies durable backchannel logout delivery.
    pub backchannel_logout_supported: bool,
    pub default_audience: String,
    pub protected_resource_identifier: String,
    pub additional_scopes_supported: Vec<String>,
    pub authorization_server_profile: AuthorizationServerProfile,
    pub ciba_security_profile: CibaSecurityProfile,
    pub dpop_nonce_policy: DpopNoncePolicy,
    pub fapi_resource_dpop_nonce_policy: DpopNoncePolicy,
    pub request_object_jti_policy: RequestObjectJtiPolicy,
    pub auth_code_ttl_seconds: u64,
    pub access_token_ttl_seconds: i64,
    pub id_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub client_secret_pepper: String,
    pub pairwise_subject_secret: Option<String>,
    pub par_ttl_seconds: u64,
    pub require_pushed_authorization_requests: bool,
    pub fapi_http_signature_max_age_seconds: i64,
}

#[derive(Clone)]
pub struct SessionSettings {
    pub session_cookie_name: String,
    pub csrf_cookie_name: String,
    pub cookie_secure: bool,
    pub session_ttl_seconds: u64,
    pub pending_mfa_session_ttl_seconds: u64,
}

#[derive(Clone)]
pub struct DeviceGrantSettings {
    pub device_authorization_ttl_seconds: u64,
    pub device_authorization_poll_interval_seconds: u64,
}

#[derive(Clone)]
pub struct Openid4vcSettings {
    pub data_encryption_key: Option<[u8; 32]>,
    pub client_attestation_jwks: Option<serde_json::Value>,
    pub key_attestation_jwks: Option<serde_json::Value>,
    pub client_attestation_issuer: Option<String>,
    pub credential_configurations: BTreeMap<String, nazo_openid4vci::CredentialConfiguration>,
    pub deferred_credential_configurations: std::collections::BTreeSet<String>,
    pub issuer_management_token: Option<String>,
    pub wallet_authorization_origins: Vec<String>,
    pub verifier_management_token: Option<String>,
    pub transaction_ttl_seconds: u64,
    pub revocation_policy: Openid4vcRevocationPolicy,
}

#[derive(Clone)]
pub struct EndpointSettings {
    pub issuer: String,
    pub mtls_endpoint_base_url: String,
    pub frontend_base_url: String,
    pub cors_allowed_origins: Vec<String>,
    pub trusted_proxy_cidrs: Vec<IpCidr>,
    pub client_ip_header_mode: ClientIpHeaderMode,
    pub mtls_certificate_source: MtlsCertificateSourceMode,
}

#[derive(Clone)]
pub struct StorageSettings {
    pub avatar_max_bytes: usize,
    pub client_delivery_ttl_seconds: u64,
    pub scim_event_retention_seconds: u64,
}

#[derive(Clone)]
pub struct IdentitySettings {
    pub rate_limit: RateLimitSettings,
    pub email: EmailSettings,
    pub email_code_dev_response_enabled: bool,
    pub passkey: PasskeySettings,
    pub federation: FederationSettings,
}

#[derive(Clone)]
pub struct EmailSettings {
    pub delivery_enabled: bool,
    pub send_peer_cooldown_seconds: u64,
    pub send_cooldown_seconds: u64,
    pub code_ttl_seconds: u64,
}

#[derive(Clone, Default)]
pub struct ModuleSettings {
    pub dynamic_client_registration_capabilities: nazo_auth::DynamicRegistrationCapabilities,
    pub enable_openid4vci_issuer: bool,
    pub enable_openid4vp_verifier: bool,
    pub register_openid4vci_routes: bool,
    pub register_openid4vp_routes: bool,
    pub dynamic_client_registration_initial_access_token: Option<String>,
}

#[derive(Clone)]
pub struct CibaSettings {
    pub ciba_auth_req_id_ttl_seconds: u64,
    pub ciba_poll_interval_seconds: u64,
}

#[derive(Clone)]
pub struct RateLimitSettings {
    pub window_seconds: u64,
    pub auth_max_requests: u64,
    pub token_max_requests: u64,
    pub token_management_max_requests: u64,
    pub scim_denial_max_requests: u64,
    pub login_failure_window_seconds: u64,
    pub login_failure_ip_email_max_attempts: u64,
    pub mfa_failure_window_seconds: u64,
    pub mfa_failure_max_attempts: u64,
}

#[derive(Clone)]
pub struct PasskeySettings {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub require_user_verification: bool,
    pub require_user_handle: bool,
}

impl Configuration {
    /// Construct the product defaults for one tenant. Secrets are supplied by the host.
    pub fn new(
        tenant: nazo_identity::TenantContext,
        issuer: impl Into<String>,
        client_secret_pepper: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let issuer = issuer.into();
        let url = nazo_auth::validate_issuer_url(&issuer)?;
        let secure = url.scheme() == "https";
        let origin = url.origin().ascii_serialization();
        let rp_id = url
            .host_str()
            .expect("validated issuer has a host")
            .to_owned();
        let client_secret_pepper = client_secret_pepper.into();
        Ok(Self {
            tenant: TenantSettings { context: tenant },
            endpoint: EndpointSettings {
                mtls_endpoint_base_url: issuer.clone(),
                frontend_base_url: format!("{}/ui/", issuer.trim_end_matches('/')),
                cors_allowed_origins: vec![origin.clone()],
                trusted_proxy_cidrs: Vec::new(),
                client_ip_header_mode: ClientIpHeaderMode::None,
                mtls_certificate_source: MtlsCertificateSourceMode::Disabled,
                issuer: issuer.clone(),
            },
            protocol: ProtocolSettings {
                user_authorization_supported: true,
                backchannel_logout_supported: true,
                default_audience: "resource://default".into(),
                protected_resource_identifier: format!(
                    "{}/fapi/resource",
                    issuer.trim_end_matches('/')
                ),
                additional_scopes_supported: Vec::new(),
                authorization_server_profile: AuthorizationServerProfile::Oauth2Baseline,
                ciba_security_profile: CibaSecurityProfile::FapiCibaId1,
                dpop_nonce_policy: DpopNoncePolicy::Required,
                fapi_resource_dpop_nonce_policy: DpopNoncePolicy::Optional,
                request_object_jti_policy: RequestObjectJtiPolicy::Optional,
                auth_code_ttl_seconds: 60,
                access_token_ttl_seconds: 300,
                id_token_ttl_seconds: 600,
                refresh_token_ttl_seconds: 2_592_000,
                client_secret_pepper,
                pairwise_subject_secret: None,
                par_ttl_seconds: 90,
                require_pushed_authorization_requests: false,
                fapi_http_signature_max_age_seconds: 60,
            },
            session: SessionSettings {
                session_cookie_name: if secure {
                    "__Host-nazo_oauth_session"
                } else {
                    "nazo_oauth_session"
                }
                .into(),
                csrf_cookie_name: if secure {
                    "__Host-nazo_oauth_csrf"
                } else {
                    "nazo_oauth_csrf"
                }
                .into(),
                cookie_secure: secure,
                session_ttl_seconds: 28_800,
                pending_mfa_session_ttl_seconds: 600,
            },
            storage: StorageSettings {
                avatar_max_bytes: 2_097_152,
                client_delivery_ttl_seconds: 86_400,
                scim_event_retention_seconds: 604_800,
            },
            identity: IdentitySettings {
                rate_limit: RateLimitSettings {
                    window_seconds: 60,
                    auth_max_requests: 100_000,
                    token_max_requests: 100_000,
                    token_management_max_requests: 100_000,
                    scim_denial_max_requests: 60,
                    login_failure_window_seconds: 900,
                    login_failure_ip_email_max_attempts: 5,
                    mfa_failure_window_seconds: 900,
                    mfa_failure_max_attempts: 5,
                },
                email: EmailSettings {
                    delivery_enabled: false,
                    send_peer_cooldown_seconds: 5,
                    send_cooldown_seconds: 60,
                    code_ttl_seconds: 900,
                },
                email_code_dev_response_enabled: false,
                passkey: PasskeySettings {
                    rp_id,
                    rp_name: "Nazo OAuth".into(),
                    origin,
                    require_user_verification: true,
                    require_user_handle: true,
                },
                federation: FederationSettings {
                    providers: FederationProviderRegistry::default(),
                    saml_gateway: None,
                },
            },
            modules: ModuleSettings::default(),
            device: DeviceGrantSettings {
                device_authorization_ttl_seconds: 600,
                device_authorization_poll_interval_seconds: 5,
            },
            ciba: CibaSettings {
                ciba_auth_req_id_ttl_seconds: 600,
                ciba_poll_interval_seconds: 5,
            },
            openid4vc: Openid4vcSettings {
                data_encryption_key: None,
                client_attestation_jwks: None,
                key_attestation_jwks: None,
                client_attestation_issuer: None,
                credential_configurations: BTreeMap::new(),
                deferred_credential_configurations: Default::default(),
                issuer_management_token: None,
                wallet_authorization_origins: Vec::new(),
                verifier_management_token: None,
                transaction_ttl_seconds: 300,
                revocation_policy: Openid4vcRevocationPolicy::Disabled,
            },
        })
    }
}
