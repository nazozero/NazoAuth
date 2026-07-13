use crate::settings::{DpopNoncePolicy, Settings};
use crate::support::client_ip::IpCidr;

#[derive(Clone)]
pub(crate) struct ResourceServerConfig {
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) default_audience: String,
    pub(crate) protected_resource_identifier: String,
    pub(crate) dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) fapi_http_signature_max_age_seconds: i64,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
}

impl From<&Settings> for ResourceServerConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let protocol = &settings.protocol;
        Self {
            issuer: endpoint.issuer.clone(),
            mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.clone(),
            default_audience: protocol.default_audience.to_owned(),
            protected_resource_identifier: protocol.protected_resource_identifier.to_owned(),
            dpop_nonce_policy: protocol.dpop_nonce_policy,
            fapi_http_signature_max_age_seconds: protocol.fapi_http_signature_max_age_seconds,
            trusted_proxy_cidrs: endpoint.trusted_proxy_cidrs.to_vec(),
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ResourceServerHandles {
    pub(crate) config: ResourceServerConfig,
    pub(crate) keyset: nazo_key_management::KeyManager,
    pub(crate) tokens: nazo_postgres::TokenRepository,
    pub(crate) clients: nazo_postgres::OAuthClientRepository,
    pub(crate) replay: nazo_valkey::ReplayStore,
    #[cfg(test)]
    pub(crate) http_message_signatures_enabled: bool,
}

#[cfg(test)]
impl ResourceServerHandles {
    pub(crate) fn accepts_http_message_signatures(&self) -> bool {
        self.http_message_signatures_enabled
    }
}

#[cfg(not(test))]
mod production {
    use std::sync::Arc;

    use actix_web::HttpRequest;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::Algorithm;
    use nazo_http_actix::{
        FapiAuthorizationError, FapiFuture, FapiHttpMessageSignatures, FapiMtlsThumbprintResolver,
        FapiResourceAuthorizer, FapiResponseSignature, FapiSignatureOperationError,
        FapiSignatureVerificationError,
    };
    use nazo_http_signatures::VerifiedInput;
    use nazo_key_management::HttpSigningLease;
    use nazo_resource_server::{
        ConfirmationPolicy, DpopProofVerifier, DpopProofVerifierConfig,
        ProtectedResourceAuthorizationContext, ProtectedResourceAuthorizationRequest,
        ProtectedResourceAuthorizationResult, ProtectedResourceAuthorizationService,
        ResourceServerVerifier, ResourceServerVerifierConfig,
    };
    use nazo_runtime_modules::ModuleId;
    use serde::Deserialize;

    use crate::{
        runtime_modules::ServerRuntimeModuleRegistry,
        settings::DpopNoncePolicy,
        support::{
            fapi_http_signatures::verify_client_http_message,
            mtls::request_mtls_thumbprint_from_trusted_proxy, security::random_urlsafe_token,
        },
    };

    use super::ResourceServerConfig;

    const DPOP_NONCE_TTL_SECONDS: u64 = 300;

    #[derive(Clone)]
    pub(crate) struct ServerFapiResourceAuthorizer {
        config: ResourceServerConfig,
        keyset: nazo_key_management::KeyManager,
        tokens: nazo_postgres::TokenRepository,
        replay: nazo_valkey::ReplayStore,
    }

    impl ServerFapiResourceAuthorizer {
        pub(crate) fn new(
            config: ResourceServerConfig,
            keyset: nazo_key_management::KeyManager,
            tokens: nazo_postgres::TokenRepository,
            replay: nazo_valkey::ReplayStore,
        ) -> Self {
            Self {
                config,
                keyset,
                tokens,
                replay,
            }
        }

        fn service(
            &self,
        ) -> Result<
            ProtectedResourceAuthorizationService<
                nazo_postgres::TokenRepository,
                nazo_valkey::ReplayStore,
            >,
            FapiAuthorizationError,
        > {
            let verifier = ResourceServerVerifier::new(ResourceServerVerifierConfig {
                issuer: self.config.issuer.clone(),
                audiences: vec![
                    self.config.default_audience.clone(),
                    self.config.protected_resource_identifier.clone(),
                ],
                jwks: self.keyset.snapshot().jwks(),
                required_scopes: Vec::new(),
                confirmation: ConfirmationPolicy::Optional,
                allowed_algs: vec![
                    Algorithm::EdDSA,
                    Algorithm::RS256,
                    Algorithm::ES256,
                    Algorithm::PS256,
                ],
                clock_skew_seconds: 0,
            })
            .map_err(|error| {
                FapiAuthorizationError::Protocol(
                    nazo_resource_server::ProtectedResourceAuthorizationError::InvalidToken(error),
                )
            })?;
            Ok(ProtectedResourceAuthorizationService::new(
                verifier,
                DpopProofVerifier::new(DpopProofVerifierConfig {
                    allowed_algs: vec![Algorithm::EdDSA, Algorithm::ES256],
                    clock_skew_seconds: 30,
                    max_age_seconds: 300,
                    required_nonce: None,
                }),
                self.tokens.clone(),
                self.replay.clone(),
            ))
        }

        async fn validate_nonce(&self, proof: Option<&str>) -> Result<(), FapiAuthorizationError> {
            let nonce = proof.and_then(dpop_nonce);
            let Some(nonce) = nonce else {
                if self.config.dpop_nonce_policy == DpopNoncePolicy::Required {
                    return Err(self.issue_nonce().await?);
                }
                return Ok(());
            };
            match self.replay.consume_dpop_nonce(&nonce).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(self.issue_nonce().await?),
                Err(_) => Err(FapiAuthorizationError::DpopNonceUnavailable),
            }
        }

        async fn issue_nonce(&self) -> Result<FapiAuthorizationError, FapiAuthorizationError> {
            let nonce = random_urlsafe_token();
            self.replay
                .issue_dpop_nonce(&nonce, DPOP_NONCE_TTL_SECONDS)
                .await
                .map_err(|_| FapiAuthorizationError::DpopNonceUnavailable)?;
            Ok(FapiAuthorizationError::UseDpopNonce(nonce))
        }
    }

    impl FapiResourceAuthorizer for ServerFapiResourceAuthorizer {
        fn authorize<'a>(
            &'a self,
            request: ProtectedResourceAuthorizationRequest<'a>,
            context: ProtectedResourceAuthorizationContext<'a>,
        ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>>
        {
            Box::pin(async move {
                let service = self.service()?;
                let result = service
                    .authorize(request, context)
                    .await
                    .map_err(FapiAuthorizationError::Protocol)?;
                if request.scheme == nazo_resource_server::AccessTokenScheme::Dpop {
                    self.validate_nonce(request.dpop_proof).await?;
                }
                Ok(result)
            })
        }
    }

    #[derive(Clone)]
    pub(crate) struct ServerFapiMtlsResolver {
        trusted_proxy_cidrs: Arc<[crate::support::client_ip::IpCidr]>,
    }

    impl ServerFapiMtlsResolver {
        pub(crate) fn new(trusted_proxy_cidrs: Vec<crate::support::client_ip::IpCidr>) -> Self {
            Self {
                trusted_proxy_cidrs: trusted_proxy_cidrs.into(),
            }
        }
    }

    impl FapiMtlsThumbprintResolver for ServerFapiMtlsResolver {
        fn resolve(&self, request: &HttpRequest) -> Option<String> {
            request_mtls_thumbprint_from_trusted_proxy(request, &self.trusted_proxy_cidrs)
        }
    }

    #[derive(Clone)]
    pub(crate) struct ServerFapiHttpMessageSignatures {
        clients: nazo_postgres::OAuthClientRepository,
        replay: nazo_valkey::ReplayStore,
        keyset: nazo_key_management::KeyManager,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
        max_age_seconds: i64,
    }

    impl ServerFapiHttpMessageSignatures {
        pub(crate) fn new(
            clients: nazo_postgres::OAuthClientRepository,
            replay: nazo_valkey::ReplayStore,
            keyset: nazo_key_management::KeyManager,
            runtime_modules: Arc<ServerRuntimeModuleRegistry>,
            max_age_seconds: i64,
        ) -> Self {
            Self {
                clients,
                replay,
                keyset,
                runtime_modules,
                max_age_seconds,
            }
        }
    }

    impl FapiHttpMessageSignatures for ServerFapiHttpMessageSignatures {
        fn enabled(&self) -> bool {
            nazo_auth::module_admissible(
                &self.runtime_modules.snapshot(),
                ModuleId::HttpMessageSignatures,
                nazo_auth::CapabilityAdmission::NewRequest,
            )
        }

        fn verify_and_consume<'a>(
            &'a self,
            tenant_id: &'a str,
            client_id: &'a str,
            input: &'a VerifiedInput,
        ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
            Box::pin(async move {
                let tenant_id = uuid::Uuid::parse_str(tenant_id)
                    .map_err(|_| FapiSignatureVerificationError::Invalid)?;
                let client = self
                    .clients
                    .by_client_id(tenant_id, client_id)
                    .await
                    .map_err(|_| FapiSignatureVerificationError::LookupUnavailable)?
                    .filter(|client| client.is_active)
                    .ok_or(FapiSignatureVerificationError::Invalid)?;
                verify_client_http_message(
                    &client,
                    tenant_id,
                    client_id,
                    input.keyid(),
                    input.algorithm(),
                    input.signature_base(),
                    input.signature(),
                )
                .map_err(|_| FapiSignatureVerificationError::Invalid)?;
                match self
                    .replay
                    .consume_fapi_http_signature(input.replay_fingerprint(), self.max_age_seconds)
                    .await
                {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(FapiSignatureVerificationError::Replay),
                    Err(_) => Err(FapiSignatureVerificationError::ReplayUnavailable),
                }
            })
        }

        fn response_signature(
            &self,
        ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
            self.keyset
                .prepare_http_signing()
                .map(|lease| Arc::new(ServerResponseSignature(lease)) as Arc<_>)
                .map_err(|_| FapiSignatureOperationError::Unavailable)
        }
    }

    struct ServerResponseSignature(HttpSigningLease);

    impl FapiResponseSignature for ServerResponseSignature {
        fn kid(&self) -> &str {
            self.0.kid()
        }

        fn algorithm(&self) -> &str {
            self.0.algorithm()
        }

        fn sign<'a>(
            &'a self,
            signature_base: &'a [u8],
        ) -> FapiFuture<'a, Result<Vec<u8>, FapiSignatureOperationError>> {
            Box::pin(async move {
                self.0
                    .sign(signature_base)
                    .await
                    .map(|signature| signature.as_bytes().to_vec())
                    .map_err(|_| FapiSignatureOperationError::Unavailable)
            })
        }
    }

    #[derive(Deserialize)]
    struct DpopNonceClaims {
        nonce: Option<String>,
    }

    fn dpop_nonce(proof: &str) -> Option<String> {
        let payload = proof.split('.').nth(1)?;
        let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
        serde_json::from_slice::<DpopNonceClaims>(&payload)
            .ok()?
            .nonce
            .filter(|nonce| !nonce.is_empty())
    }
}

#[cfg(not(test))]
pub(crate) use production::{
    ServerFapiHttpMessageSignatures, ServerFapiMtlsResolver, ServerFapiResourceAuthorizer,
};
