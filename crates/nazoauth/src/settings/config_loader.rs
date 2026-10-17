use super::*;

struct TenantOverride {
    context: nazo_identity::TenantContext,
    issuer: String,
    issuer_url: url::Url,
}

impl TenantOverride {
    fn from_issuer(context: nazo_identity::TenantContext, issuer: &str) -> anyhow::Result<Self> {
        let issuer = issuer.trim().to_owned();
        let issuer_url = validate_issuer_url(&issuer)?;
        Ok(Self {
            context,
            issuer,
            issuer_url,
        })
    }

    fn from_directory(binding: &nazo_identity::TenantDirectoryBinding) -> anyhow::Result<Self> {
        let override_ = Self::from_issuer(binding.tenant, &binding.issuer)?;
        let host = nazo_identity::tenant_host_from_issuer(&override_.issuer_url)?;
        let external_host = canonical_tenant_host(&binding.external_host)?;
        if host != external_host {
            bail!(
                "tenant directory issuer host {host} does not match external_host {external_host}"
            );
        }
        Ok(override_)
    }
}

pub(crate) fn credential_configurations_from_config(
    config: &ConfigSource,
) -> anyhow::Result<BTreeMap<String, nazo_openid4vci::CredentialConfiguration>> {
    let configurations: BTreeMap<String, nazo_openid4vci::CredentialConfiguration> = config
        .optional_string("OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON")
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .unwrap_or_default();
    for configuration in configurations.values() {
        configuration.validate().map_err(anyhow::Error::from)?;
    }
    Ok(configurations)
}

pub(crate) fn mdoc_issuing_country_from_config(
    config: &ConfigSource,
    configurations: &BTreeMap<String, nazo_openid4vci::CredentialConfiguration>,
) -> anyhow::Result<Option<String>> {
    let mdoc_enabled = configurations.values().any(|configuration| {
        configuration.format == nazo_digital_credentials::CredentialFormat::MsoMdoc
    });
    if !mdoc_enabled {
        return Ok(None);
    }

    let Some(issuing_country) = config.optional_string("OPENID4VC_MDOC_ISSUING_COUNTRY") else {
        bail!(
            "OPENID4VC_MDOC_ISSUING_COUNTRY is required when an mso_mdoc credential configuration is enabled"
        );
    };
    if issuing_country.len() != 2
        || !issuing_country
            .bytes()
            .all(|character| character.is_ascii_uppercase())
    {
        bail!("OPENID4VC_MDOC_ISSUING_COUNTRY must be two uppercase ASCII letters");
    }
    Ok(Some(issuing_country))
}

fn derive_tenant_secret(
    root: &[u8],
    tenant_id: nazo_identity::TenantId,
    purpose: &'static [u8],
) -> [u8; 32] {
    nazo_operator_protocol::hkdf_sha256_v1(root, tenant_id.as_uuid().as_bytes(), purpose)
}

fn derive_tenant_management_token(
    root: String,
    tenant_id: nazo_identity::TenantId,
    purpose: &'static [u8],
) -> String {
    URL_SAFE_NO_PAD.encode(derive_tenant_secret(root.as_bytes(), tenant_id, purpose))
}

impl Settings {
    pub(crate) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        Self::from_config_for_tenant(config, None)
    }

    pub(crate) fn initial_tenant_directory_binding(
        config: &ConfigSource,
    ) -> anyhow::Result<nazo_identity::TenantDirectoryBinding> {
        let tenant = nazo_identity::TenantContext::default_system();
        let issuer = config
            .get("ISSUER")
            .or_else(|| config.get("PUBLIC_BASE_URL"))
            .unwrap_or("http://127.0.0.1:8000");
        let override_ = TenantOverride::from_issuer(tenant, issuer)?;
        let external_host =
            nazo_identity::tenant_host_from_issuer(&override_.issuer_url)?.to_owned();
        Ok(nazo_identity::TenantDirectoryBinding {
            tenant,
            runtime_revision: 1,
            issuer: override_.issuer,
            external_host,
        })
    }

    /// Builds one tenant snapshot from the authoritative runtime directory.
    /// All non-routing policy remains in the process configuration; the
    /// directory only selects the tenant boundary and public issuer.
    pub(crate) fn from_directory_binding(
        config: &ConfigSource,
        binding: &nazo_identity::TenantDirectoryBinding,
    ) -> anyhow::Result<Self> {
        Self::from_config_for_tenant(config, Some(TenantOverride::from_directory(binding)?))
    }

    fn from_config_for_tenant(
        config: &ConfigSource,
        tenant_override: Option<TenantOverride>,
    ) -> anyhow::Result<Self> {
        let tenant_specific = tenant_override.is_some();
        let (public_base_url, public_origin, issuer, issuer_url, context) = match tenant_override {
            Some(tenant) => (
                tenant.issuer.clone(),
                tenant.issuer_url.origin().ascii_serialization(),
                tenant.issuer,
                tenant.issuer_url,
                tenant.context,
            ),
            None => {
                let public_base_url = config.string("PUBLIC_BASE_URL", "http://127.0.0.1:8000");
                let public_url = validate_issuer_url(&public_base_url)?;
                let public_origin = public_url.origin().ascii_serialization();
                let issuer = config.string("ISSUER", &public_base_url);
                let issuer_url = if issuer == public_base_url {
                    public_url
                } else {
                    validate_issuer_url(&issuer)?
                };
                (
                    public_base_url,
                    public_origin,
                    issuer,
                    issuer_url,
                    nazo_identity::TenantContext::default_system(),
                )
            }
        };
        // Issuer admission permits HTTP only for loopback hosts.
        let issuer_is_loopback_http = issuer_url.scheme() == "http";
        let transport_mode = TransportMode::from_config(
            config.get("TRANSPORT_MODE"),
            &issuer,
            issuer_is_loopback_http,
        );
        let tenant = TenantSettings { context };
        let (mtls_endpoint_base_url, mtls_endpoint_is_https) = if tenant_specific
            && matches!(&transport_mode, Ok(TransportMode::DirectTls))
            && let Some(configured_mtls) = config.optional_string("MTLS_ENDPOINT_BASE_URL")
        {
            let configured_mtls = validate_issuer_url(&configured_mtls)?;
            if configured_mtls.scheme() != "https" {
                bail!("direct-tls transport requires an HTTPS MTLS_ENDPOINT_BASE_URL");
            }
            let mut tenant_mtls = issuer_url.clone();
            // The directory owns the tenant host; the deployment owns its
            // externally published mTLS listener port. Using the tenant's
            // ordinary HTTPS port would advertise a listener that never
            // requests a client certificate.
            tenant_mtls
                .set_port(configured_mtls.port())
                .map_err(|()| anyhow::anyhow!("invalid tenant mTLS endpoint port"))?;
            (
                tenant_mtls.to_string().trim_end_matches('/').to_owned(),
                tenant_mtls.scheme() == "https",
            )
        } else if tenant_specific {
            (issuer.clone(), issuer_url.scheme() == "https")
        } else if let Some(configured_mtls) = config.optional_string("MTLS_ENDPOINT_BASE_URL") {
            let is_https = validate_issuer_url(&configured_mtls)?.scheme() == "https";
            (configured_mtls, is_https)
        } else {
            (issuer.clone(), issuer_url.scheme() == "https")
        };
        let frontend_base_url =
            if !tenant_specific && let Some(frontend) = config.get("FRONTEND_BASE_URL") {
                validate_frontend_base_url(frontend)?;
                frontend.to_owned()
            } else {
                format!("{}/ui/", public_base_url.trim_end_matches('/'))
            };
        let mut cors_allowed_origins = Vec::new();
        if !tenant_specific && let Some(origins) = config.get("CORS_ALLOWED_ORIGINS") {
            for origin in origins
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
            {
                validate_cors_origin(origin)?;
                cors_allowed_origins.push(origin.to_owned());
            }
        }
        if cors_allowed_origins.is_empty() {
            cors_allowed_origins.push(public_origin);
        }
        let default_cookie_secure = issuer.starts_with("https://");
        let cookie_secure = config.bool("COOKIE_SECURE", default_cookie_secure)?;
        if !cookie_secure && !issuer_is_loopback_http {
            bail!("COOKIE_SECURE=false 只允许用于 loopback HTTP 本地开发 issuer");
        }
        let session_cookie_name = config
            .optional_string("SESSION_COOKIE_NAME")
            .unwrap_or_else(|| {
                if cookie_secure {
                    "__Host-nazo_oauth_session".to_owned()
                } else {
                    "nazo_oauth_session".to_owned()
                }
            });
        let csrf_cookie_name = config
            .optional_string("CSRF_COOKIE_NAME")
            .unwrap_or_else(|| {
                if cookie_secure {
                    "__Host-nazo_oauth_csrf".to_owned()
                } else {
                    "nazo_oauth_csrf".to_owned()
                }
            });
        if !cookie_secure
            && (session_cookie_name.starts_with("__Host-")
                || csrf_cookie_name.starts_with("__Host-"))
        {
            bail!("__Host- cookie names require COOKIE_SECURE=true");
        }
        let subject_type = profile::subject_type_from_config(config)?;
        let pairwise_subject_secret = config.optional_string("PAIRWISE_SUBJECT_SECRET");
        if subject_type == SubjectType::Pairwise && pairwise_subject_secret.is_none() {
            bail!("PAIRWISE_SUBJECT_SECRET is required when SUBJECT_TYPE=pairwise");
        }
        if let Some(secret) = &pairwise_subject_secret
            && secret.len() < 32
        {
            bail!("pairwise_subject_secret must be at least 32 bytes");
        }
        let client_secret_pepper = match config.optional_string("CLIENT_SECRET_PEPPER") {
            Some(secret) if secret.len() >= 32 => secret,
            Some(_) => bail!("CLIENT_SECRET_PEPPER must be at least 32 bytes"),
            None if issuer_is_loopback_http => LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER.to_owned(),
            None => bail!("CLIENT_SECRET_PEPPER is required for non-loopback issuers"),
        };
        let authorization_server_profile =
            profile::authorization_server_profile_from_config(config)?;
        let ciba_security_profile = profile::ciba_security_profile_from_config(config)?;
        let protected_resource_identifier =
            match config.optional_string("PROTECTED_RESOURCE_IDENTIFIER") {
                Some(value) => {
                    validate_protected_resource_identifier(&value)?;
                    value
                }
                None => default_protected_resource_identifier(&issuer),
            };
        // RFC 6749 section 3.3: ASCII space separates scope-token values.
        // This is public discovery policy, never a client authorization allowlist.
        let additional_scopes_supported = config
            .optional_string("ADDITIONAL_SCOPES_SUPPORTED")
            .unwrap_or_default()
            .split(' ')
            .filter(|scope| !scope.is_empty())
            .map(|scope| {
                if !scope.bytes().all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e)) {
                    bail!("ADDITIONAL_SCOPES_SUPPORTED must contain space-separated OAuth scope tokens");
                }
                Ok(scope.to_owned())
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let dpop_nonce_policy = profile::dpop_nonce_policy_from_config(config)?;
        let fapi_resource_dpop_nonce_policy =
            profile::fapi_resource_dpop_nonce_policy_from_config(config)?;
        let request_object_jti_policy = profile::request_object_jti_policy_from_config(config)?;
        let auth_code_ttl_seconds =
            positive_u64(config, "AUTH_CODE_TTL_SECONDS", 60, "AUTH_CODE_TTL_SECONDS")?;
        if authorization_server_profile.requires_fapi2_security() && auth_code_ttl_seconds > 60 {
            bail!("AUTH_CODE_TTL_SECONDS must be 60 or less for FAPI2 profiles");
        }
        let par_ttl_seconds = positive_u64(config, "PAR_TTL_SECONDS", 90, "PAR_TTL_SECONDS")?;
        if authorization_server_profile.requires_fapi2_security() && par_ttl_seconds >= 600 {
            bail!("PAR_TTL_SECONDS must be less than 600 for FAPI2 profiles");
        }
        let require_pushed_authorization_requests =
            config.bool("REQUIRE_PUSHED_AUTHORIZATION_REQUESTS", false)?;
        let device_authorization_ttl_seconds =
            config.parse("DEVICE_AUTHORIZATION_TTL_SECONDS", 600)?;
        if device_authorization_ttl_seconds == 0 {
            bail!("DEVICE_AUTHORIZATION_TTL_SECONDS must be positive");
        }
        let device_authorization_poll_interval_seconds =
            config.parse("DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS", 5)?;
        if device_authorization_poll_interval_seconds == 0 {
            bail!("DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS must be positive");
        }
        if device_authorization_poll_interval_seconds >= device_authorization_ttl_seconds {
            bail!(
                "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS must be less than DEVICE_AUTHORIZATION_TTL_SECONDS"
            );
        }
        let ciba_auth_req_id_ttl_seconds = config.parse("CIBA_AUTH_REQ_ID_TTL_SECONDS", 600)?;
        if ciba_auth_req_id_ttl_seconds == 0 {
            bail!("CIBA_AUTH_REQ_ID_TTL_SECONDS must be positive");
        }
        let ciba_poll_interval_seconds = config.parse("CIBA_POLL_INTERVAL_SECONDS", 5)?;
        if ciba_poll_interval_seconds == 0 {
            bail!("CIBA_POLL_INTERVAL_SECONDS must be positive");
        }
        if ciba_poll_interval_seconds >= ciba_auth_req_id_ttl_seconds {
            bail!("CIBA_POLL_INTERVAL_SECONDS must be less than CIBA_AUTH_REQ_ID_TTL_SECONDS");
        }
        let ciba_notification_private_origins = config
            .optional_string("CIBA_NOTIFICATION_PRIVATE_ORIGINS")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let enable_openid4vci_issuer = config.bool("ENABLE_OPENID4VCI_ISSUER", false)?;
        let enable_directory_openid4vci_issuer = config.bool(
            "ENABLE_DIRECTORY_OPENID4VCI_ISSUER",
            enable_openid4vci_issuer,
        )?;
        let enable_openid4vci_issuer = if tenant_specific {
            enable_directory_openid4vci_issuer
        } else {
            enable_openid4vci_issuer
        };
        let enable_openid4vp_verifier = config.bool("ENABLE_OPENID4VP_VERIFIER", false)?;
        let enable_directory_openid4vp_verifier = config.bool(
            "ENABLE_DIRECTORY_OPENID4VP_VERIFIER",
            enable_openid4vp_verifier,
        )?;
        let enable_openid4vp_verifier = if tenant_specific {
            enable_directory_openid4vp_verifier
        } else {
            enable_openid4vp_verifier
        };
        let register_openid4vci_routes =
            enable_openid4vci_issuer || enable_directory_openid4vci_issuer;
        let register_openid4vp_routes =
            enable_openid4vp_verifier || enable_directory_openid4vp_verifier;
        let openid4vc_enabled = enable_openid4vci_issuer || enable_openid4vp_verifier;
        let mut openid4vc_data_encryption_key = config
            .optional_string("OPENID4VC_DATA_ENCRYPTION_KEY")
            .map(|value| URL_SAFE_NO_PAD.decode(value).map_err(anyhow::Error::from))
            .transpose()?
            .map(|value| {
                <[u8; 32]>::try_from(value).map_err(|_| {
                    anyhow::anyhow!("OPENID4VC_DATA_ENCRYPTION_KEY must decode to exactly 32 bytes")
                })
            })
            .transpose()?;
        let openid4vc_client_attestation_jwks = parse_attestation_jwk_set(
            config,
            "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON",
            AttestationTrustPurpose::Client,
        )?;
        let openid4vc_key_attestation_jwks = parse_attestation_jwk_set(
            config,
            "OPENID4VC_KEY_ATTESTATION_JWKS_JSON",
            AttestationTrustPurpose::HolderKey,
        )?;
        let openid4vc_client_attestation_issuer =
            config.optional_string("OPENID4VC_CLIENT_ATTESTATION_ISSUER");
        let credential_configurations = credential_configurations_from_config(config)?;
        let deferred_credential_configurations = config
            .optional_string("OPENID4VCI_DEFERRED_CREDENTIAL_CONFIGURATIONS")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        let mut openid4vci_issuer_management_token =
            config.optional_string("OPENID4VCI_ISSUER_MANAGEMENT_TOKEN");
        if openid4vci_issuer_management_token
            .as_ref()
            .is_some_and(|token| token.len() < 32)
        {
            bail!("OPENID4VCI_ISSUER_MANAGEMENT_TOKEN must be at least 32 bytes");
        }
        if !deferred_credential_configurations
            .iter()
            .all(|id| credential_configurations.contains_key(id))
        {
            bail!(
                "OPENID4VCI_DEFERRED_CREDENTIAL_CONFIGURATIONS must reference configured credentials"
            );
        }
        let wallet_authorization_origins = config
            .optional_string("OPENID4VP_WALLET_AUTHORIZATION_ORIGINS")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for origin in &wallet_authorization_origins {
            validate_cors_origin(origin)?;
        }
        let mut openid4vp_verifier_management_token =
            config.optional_string("OPENID4VP_VERIFIER_MANAGEMENT_TOKEN");
        if openid4vp_verifier_management_token
            .as_ref()
            .is_some_and(|token| token.len() < 32)
        {
            bail!("OPENID4VP_VERIFIER_MANAGEMENT_TOKEN must be at least 32 bytes");
        }
        if openid4vci_issuer_management_token == openid4vp_verifier_management_token
            && openid4vci_issuer_management_token.is_some()
        {
            bail!(
                "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN and OPENID4VP_VERIFIER_MANAGEMENT_TOKEN must differ"
            );
        }
        let openid4vc_revocation_policy = profile::openid4vc_revocation_policy_from_config(config)?;
        if enable_openid4vp_verifier
            && openid4vc_revocation_policy != Openid4vcRevocationPolicy::Required
        {
            bail!("ENABLE_OPENID4VP_VERIFIER=true requires OPENID4VC_REVOCATION_POLICY=required");
        }
        if openid4vc_enabled && openid4vc_data_encryption_key.is_none() {
            bail!("OpenID4VC modules require a data encryption root");
        }
        if enable_openid4vci_issuer && credential_configurations.is_empty() {
            bail!(
                "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON is required when the VCI issuer is enabled"
            );
        }
        if enable_openid4vci_issuer && openid4vci_issuer_management_token.is_none() {
            bail!("OPENID4VCI_ISSUER_MANAGEMENT_TOKEN is required when the VCI issuer is enabled");
        }
        // Static attestation trust may be empty.
        // Ordinary tenant resources can bind client-scoped trust policies at runtime;
        // unbound clients never inherit another client's policy.
        if openid4vc_client_attestation_issuer.is_some()
            && openid4vc_client_attestation_jwks.is_none()
        {
            bail!(
                "OPENID4VC_CLIENT_ATTESTATION_ISSUER requires OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON"
            );
        }
        if enable_openid4vp_verifier && wallet_authorization_origins.is_empty() && !tenant_specific
        {
            bail!(
                "OPENID4VP_WALLET_AUTHORIZATION_ORIGINS is required when the VP verifier is enabled"
            );
        }
        if enable_openid4vp_verifier && openid4vp_verifier_management_token.is_none() {
            bail!(
                "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN is required when the VP verifier is enabled"
            );
        }
        let mut dynamic_client_registration_initial_access_token =
            config.optional_string("DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN");
        if tenant_specific {
            dynamic_client_registration_initial_access_token =
                dynamic_client_registration_initial_access_token.map(|root| {
                    derive_tenant_management_token(
                        root,
                        tenant.context.tenant_id,
                        b"nazoauth/dynamic-client-registration/initial-access/v1",
                    )
                });
        }
        let email_code_dev_response_enabled =
            config.bool("EMAIL_CODE_DEV_RESPONSE_ENABLED", false)?;
        if email_code_dev_response_enabled && (!cfg!(debug_assertions) || !issuer_is_loopback_http)
        {
            bail!(
                "EMAIL_CODE_DEV_RESPONSE_ENABLED=true requires a debug build and loopback HTTP issuer"
            );
        }
        let passkey = PasskeySettings::from_config(config, &issuer, &issuer_url)?;
        let email = EmailSettings::from_config(config, issuer_is_loopback_http)?;
        let federation = FederationSettings::from_config(config)?;
        let task_key_settings = key_settings_from_config(config)?;
        let fapi_http_signature_max_age_seconds =
            config.parse("FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS", 60)?;
        if !(1..=300).contains(&fapi_http_signature_max_age_seconds) {
            bail!("FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS must be between 1 and 300");
        }
        let data_dir = config.persistent_path("DATA_DIR", Some(DEFAULT_DATA_DIR))?;
        if tenant_specific && openid4vc_enabled {
            let tenant_id = tenant.context.tenant_id;
            openid4vc_data_encryption_key = openid4vc_data_encryption_key.map(|root| {
                derive_tenant_secret(&root, tenant_id, b"nazoauth/openid4vc/data-encryption/v1")
            });
            openid4vci_issuer_management_token = openid4vci_issuer_management_token.map(|root| {
                derive_tenant_management_token(
                    root,
                    tenant_id,
                    b"nazoauth/openid4vci/management/v1",
                )
            });
            openid4vp_verifier_management_token = openid4vp_verifier_management_token.map(|root| {
                derive_tenant_management_token(root, tenant_id, b"nazoauth/openid4vp/management/v1")
            });
        }
        let tenant_id = tenant.context.tenant_id.as_uuid().to_string();
        let avatar_storage_dir = match config.optional_string("AVATAR_STORAGE_DIR") {
            Some(_) => config
                .persistent_path("AVATAR_STORAGE_DIR", None)?
                .join(tenant_id),
            None => data_dir.join("tenants").join(tenant_id).join("avatars"),
        };
        let scim_event_retention_seconds = positive_u64(
            config,
            "SCIM_EVENT_RETENTION_SECONDS",
            604_800,
            "SCIM_EVENT_RETENTION_SECONDS",
        )?;
        if !(3_600..=2_592_000).contains(&scim_event_retention_seconds) {
            bail!("SCIM_EVENT_RETENTION_SECONDS must be between 3600 and 2592000");
        }

        let session_ttl_seconds =
            positive_u64(config, "SESSION_TTL_SECONDS", 28_800, "SESSION_TTL_SECONDS")?;
        let pending_mfa_session_ttl_seconds = positive_u64(
            config,
            "PENDING_MFA_SESSION_TTL_SECONDS",
            600,
            "PENDING_MFA_SESSION_TTL_SECONDS",
        )?;
        if pending_mfa_session_ttl_seconds >= session_ttl_seconds {
            bail!("PENDING_MFA_SESSION_TTL_SECONDS must be less than SESSION_TTL_SECONDS");
        }

        Ok(Self {
            tenant,
            endpoint: {
                let trusted_proxy_cidrs =
                    parse_trusted_proxy_cidrs(config.get("TRUSTED_PROXY_CIDRS"))?;
                let transport_mode = transport_mode?;
                let configured_mtls_source = config
                    .get("MTLS_CERTIFICATE_SOURCE")
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let mtls_certificate_source = match transport_mode {
                    TransportMode::LoopbackHttp => {
                        if !trusted_proxy_cidrs.is_empty() {
                            bail!("loopback-http transport must not configure TRUSTED_PROXY_CIDRS");
                        }
                        if configured_mtls_source.is_some() {
                            bail!(
                                "loopback-http transport must not configure MTLS_CERTIFICATE_SOURCE"
                            );
                        }
                        MtlsCertificateSourceMode::Disabled
                    }
                    TransportMode::DirectTls => {
                        if !mtls_endpoint_is_https {
                            bail!("direct-tls transport requires an HTTPS MTLS_ENDPOINT_BASE_URL");
                        }
                        if !trusted_proxy_cidrs.is_empty() {
                            bail!("direct-tls transport must not configure TRUSTED_PROXY_CIDRS");
                        }
                        if configured_mtls_source.is_some_and(|value| value != "direct-tls") {
                            bail!("direct-tls transport cannot use a proxy certificate source");
                        }
                        MtlsCertificateSourceMode::DirectTls
                    }
                    TransportMode::TrustedProxy => {
                        if trusted_proxy_cidrs.is_empty() {
                            bail!(
                                "trusted-proxy transport requires at least one TRUSTED_PROXY_CIDRS entry"
                            );
                        }
                        let Some(value) = configured_mtls_source else {
                            bail!(
                                "trusted-proxy transport requires an explicit MTLS_CERTIFICATE_SOURCE"
                            );
                        };
                        let source = MtlsCertificateSourceMode::from_config(Some(value))?;
                        if source == MtlsCertificateSourceMode::DirectTls {
                            bail!(
                                "trusted-proxy transport cannot use MTLS_CERTIFICATE_SOURCE=direct-tls"
                            );
                        }
                        source
                    }
                };
                EndpointSettings {
                    issuer,
                    mtls_endpoint_base_url,
                    frontend_base_url,
                    cors_allowed_origins,
                    trusted_proxy_cidrs,
                    client_ip_header_mode: ClientIpHeaderMode::parse(
                        config.get("CLIENT_IP_HEADER_MODE").unwrap_or("none"),
                    )?,
                    transport_mode,
                    mtls_certificate_source,
                }
            },
            protocol: ProtocolSettings {
                default_audience: config.string("DEFAULT_AUDIENCE", "resource://default"),
                protected_resource_identifier,
                additional_scopes_supported,
                authorization_server_profile,
                ciba_security_profile,
                dpop_nonce_policy,
                fapi_resource_dpop_nonce_policy,
                request_object_jti_policy,
                auth_code_ttl_seconds,
                access_token_ttl_seconds: super::bounded_access_token_ttl_seconds(config)?,
                id_token_ttl_seconds: super::bounded_id_token_ttl_seconds(config)?,
                refresh_token_ttl_seconds: positive_i64(
                    config,
                    "REFRESH_TOKEN_TTL_SECONDS",
                    2_592_000,
                    "REFRESH_TOKEN_TTL_SECONDS",
                )?,
                client_secret_pepper,
                pairwise_subject_secret,
                par_ttl_seconds,
                require_pushed_authorization_requests,
                fapi_http_signature_max_age_seconds,
            },
            session: SessionSettings {
                session_cookie_name,
                csrf_cookie_name,
                cookie_secure,
                session_ttl_seconds,
                pending_mfa_session_ttl_seconds,
            },
            storage: StorageSettings {
                avatar_max_bytes: config.parse("AVATAR_MAX_BYTES", 2_097_152)?,
                client_delivery_ttl_seconds: positive_u64(
                    config,
                    "CLIENT_DELIVERY_TTL_SECONDS",
                    86_400,
                    "CLIENT_DELIVERY_TTL_SECONDS",
                )?,
                data_dir,
                avatar_storage_dir,
                scim_event_retention_seconds,
            },
            identity: IdentityRuntimeSettings {
                rate_limit: RateLimitSettings::from_config(config)?,
                email,
                email_code_dev_response_enabled,
                passkey,
                federation,
            },
            keys: KeyManagementSettings {
                signing_external_command: parse_signing_external_command(
                    config.optional_string("SIGNING_EXTERNAL_COMMAND"),
                ),
                signing_external_timeout_ms: config.parse("SIGNING_EXTERNAL_TIMEOUT_MS", 2_000)?,
                signing_key_rotation_interval_seconds: task_key_settings
                    .rotation_interval
                    .num_seconds(),
                signing_key_prepublish_seconds: task_key_settings.prepublish_window.num_seconds(),
            },
            modules: ModuleSettings {
                enable_openid4vci_issuer,
                enable_openid4vp_verifier,
                register_openid4vci_routes,
                register_openid4vp_routes,
                dynamic_client_registration_initial_access_token,
                remote_client_document_private_origins: config
                    .optional_string("REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS")
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                backchannel_logout_private_origins: config
                    .optional_string("BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS")
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            },
            device: DeviceGrantSettings {
                device_authorization_ttl_seconds,
                device_authorization_poll_interval_seconds,
            },
            ciba: CibaSettings {
                ciba_auth_req_id_ttl_seconds,
                ciba_poll_interval_seconds,
                ciba_notification_private_origins,
            },
            openid4vc: Openid4vcSettings {
                data_encryption_key: openid4vc_data_encryption_key,
                client_attestation_jwks: openid4vc_client_attestation_jwks,
                key_attestation_jwks: openid4vc_key_attestation_jwks,
                client_attestation_issuer: openid4vc_client_attestation_issuer,
                credential_configurations,
                deferred_credential_configurations,
                issuer_management_token: openid4vci_issuer_management_token,
                wallet_authorization_origins,
                verifier_management_token: openid4vp_verifier_management_token,
                transaction_ttl_seconds: positive_u64(
                    config,
                    "OPENID4VC_TRANSACTION_TTL_SECONDS",
                    300,
                    "OPENID4VC_TRANSACTION_TTL_SECONDS",
                )?,
                revocation_policy: openid4vc_revocation_policy,
            },
        })
    }
}
