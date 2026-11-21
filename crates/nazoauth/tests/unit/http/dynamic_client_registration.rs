use bytes::Bytes;
use http::{StatusCode, header};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use nazo_auth::{
    AdminClientCryptoPort, ClientSecretDigesterPort, DynamicRegistrationSecretPort, OAuthClient,
    PreparedClientRegistration, SectorIdentifierFuture, SectorIdentifierResolverPort,
    ValidatedClientRegistration,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::auth::{bearer_token, parse_bearer};
use super::*;
use nazo_identity::TenantContext;
use nazo_oauth_server::contracts::dynamic_client_registration::{
    DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard,
    DynamicRegistrationSecurityServices, RemoteJwksFuture, RemoteJwksResolverPort,
};
use nazo_oauth_server::domain::dynamic_registration::{
    DynamicRegistrationApplication, DynamicRegistrationConfig,
};

const RP_METADATA_CHOICE_FIELDS: &[&str] = &[
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "id_token_encryption_alg_values_supported",
    "id_token_encryption_enc_values_supported",
    "userinfo_signing_alg_values_supported",
    "userinfo_encryption_alg_values_supported",
    "userinfo_encryption_enc_values_supported",
    "request_object_signing_alg_values_supported",
    "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc_values_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "backchannel_authentication_request_signing_alg_values_supported",
    "authorization_signing_alg_values_supported",
    "authorization_encryption_alg_values_supported",
    "authorization_encryption_enc_values_supported",
    "introspection_signing_alg_values_supported",
    "introspection_encryption_alg_values_supported",
    "introspection_encryption_enc_values_supported",
];

#[derive(Clone)]
struct FakeStore {
    client: Arc<Mutex<Option<OAuthClient>>>,
}

impl FakeStore {
    fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(Some(client()))),
        }
    }
}

impl DynamicRegistrationClientStore for FakeStore {
    fn insert<'a>(
        &'a self,
        prepared: PreparedClientRegistration,
        _source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        let inserted = OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: prepared.tenant.tenant_id.as_uuid(),
            realm_id: prepared.tenant.realm_id.as_uuid(),
            organization_id: prepared.tenant.organization_id.as_uuid(),
            registration: prepared.registration,
            require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
            is_active: true,
        };
        *self.client.lock().expect("client lock") = Some(inserted.clone());
        Box::pin(async move { Ok(inserted) })
    }

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        _token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<nazo_auth::RegistrationClientSnapshot>> {
        let found = self
            .client
            .lock()
            .expect("client lock")
            .clone()
            .filter(|client| client.tenant_id == tenant_id && client.client_id == client_id);
        Box::pin(async move {
            Ok(found.map(|client| nazo_auth::RegistrationClientSnapshot {
                client,
                has_client_secret: true,
                secret_salt: Some("salt".to_owned()),
            }))
        })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        let matches = candidate_digest == "digest:current-secret:pepper:salt"
            && self
                .client
                .lock()
                .expect("client lock")
                .as_ref()
                .is_some_and(|client| client.tenant_id == tenant_id && client.id == client_id);
        Box::pin(async move { Ok(matches) })
    }

    fn rotate_credentials<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_id: Uuid,
        _client_secret_hash: Option<&'a str>,
        _expected_registration_access_token_hash: &'a str,
        _new_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        let client = self.client.lock().expect("client lock").clone();
        Box::pin(async move { client.ok_or(DynamicRegistrationDependencyError::Unavailable) })
    }

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        _client_secret_hash: Option<&'a str>,
        _expected_registration_access_token_hash: &'a str,
        _new_registration_access_token_hash: Option<&'a str>,
        _source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient> {
        *self.client.lock().expect("client lock") = Some(client.clone());
        Box::pin(async move { Ok(client.clone()) })
    }

    fn deactivate<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_id: Uuid,
        _expected_registration_access_token_hash: &'a str,
        _source_ip_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        *self.client.lock().expect("client lock") = None;
        Box::pin(async { Ok(true) })
    }
}

#[test]
fn registration_access_token_lookup_fails_closed_across_tenants() {
    futures_executor::block_on(async {
        let store = FakeStore::new();
        let mut config = application_config();
        config.tenant = TenantContext {
            tenant_id: nazo_identity::TenantId::new(Uuid::from_u128(11)).unwrap(),
            realm_id: nazo_identity::RealmId::new(Uuid::from_u128(12)).unwrap(),
            organization_id: nazo_identity::OrganizationId::new(Uuid::from_u128(13)).unwrap(),
        };
        let endpoint = endpoint_with_config(
            config,
            store,
            FakeGuard {
                enabled: true,
                rate_limit: None,
            },
        );
        let response = endpoint
            .application
            .read("client-test", Some("registration-token"), "203.0.113.77")
            .await
            .expect_err("a token from the default tenant must not cross into another tenant");
        assert!(
            matches!(response, nazo_oauth_server::contracts::oauth_error::OAuthEndpointError::Bearer(fields) if fields.status.as_u16() == StatusCode::UNAUTHORIZED.as_u16())
        );
    });
}

#[derive(Clone, Copy)]
struct FakeSecurity;

impl SectorIdentifierResolverPort for FakeSecurity {
    fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl RemoteJwksResolverPort for FakeSecurity {
    fn resolve<'a>(
        &'a self,
        _uri: &'a str,
        _expected_kid: Option<&'a str>,
    ) -> RemoteJwksFuture<'a> {
        Box::pin(async { Ok(json!({"keys": []}).into()) })
    }
}

impl AdminClientCryptoPort for FakeSecurity {
    fn response_signing_algorithms(&self) -> Vec<String> {
        vec!["RS256".to_owned(), "PS256".to_owned()]
    }

    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        ("issued-secret".to_owned(), "stored-secret-hash".to_owned())
    }

    fn inspect_jwks(
        &self,
        _jwks: &Value,
        _certificate_auth: bool,
    ) -> Result<nazo_auth::ClientJwksCapabilities, String> {
        Ok(nazo_auth::ClientJwksCapabilities {
            signing_algorithms: nazo_auth::SUPPORTED_CLIENT_JWT_SIGNING_ALGS
                .iter()
                .copied()
                .collect(),
            encryption_key_counts: nazo_auth::SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS
                .iter()
                .map(|alg| (*alg, 1))
                .collect(),
            has_current_mtls_certificate: true,
        })
    }

    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        (!value.trim().is_empty() && value.contains('='))
            .then_some(())
            .ok_or_else(|| "invalid RFC 4514 DN".to_owned())
    }
}

impl DynamicRegistrationSecretPort for FakeSecurity {
    fn random_token(&self) -> String {
        "registration-token".to_owned()
    }

    fn token_hash(&self, token: &str) -> String {
        format!("token-hash:{token}")
    }

    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
        left == right
    }
}

impl ClientSecretDigesterPort for FakeSecurity {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
        format!("digest:{secret}:{pepper}:{salt}")
    }
}

#[derive(Clone)]
struct FakeGuard {
    enabled: bool,
    rate_limit: Option<DynamicRegistrationRateLimitError>,
}

impl DynamicRegistrationRequestGuard for FakeGuard {
    fn acquire_request(&self) -> Option<nazo_runtime_modules::RequestLease> {
        test_module_lease(self.enabled)
    }

    fn enforce_rate_limit<'a>(
        &'a self,
        _source_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
    {
        let result = self.rate_limit.map_or(Ok(()), Err);
        Box::pin(async move { result })
    }

    fn audit(&self, _event: &'static str, _client: &OAuthClient, _source_ip: &str) {}

    fn ensure_mutation_ready<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
    {
        Box::pin(async move { Ok(()) })
    }
}

fn endpoint(enabled: bool) -> DynamicRegistrationEndpoint {
    endpoint_with_store(enabled, FakeStore::new())
}

fn application_config() -> DynamicRegistrationConfig {
    DynamicRegistrationConfig {
        capabilities: Default::default(),
        require_fapi2: false,
        tenant: TenantContext::default_system(),
        issuer: "https://issuer.example".to_owned(),
        default_audience: "https://api.example".to_owned(),
        pairwise_subject_secret: None,
        client_secret_pepper: "pepper".to_owned(),
        initial_access_token: Some("initial-token".to_owned()),
        rate_limit_window_seconds: 60,
        rate_limit_max_requests: 100,
        id_token_signing_algs: vec!["RS256", "PS256"],
        response_signing_algs: vec!["RS256", "PS256"],
        request_object_encryption_algs: vec!["RSA-OAEP-256"],
        request_object_encryption_encs: vec!["A256GCM"],
    }
}

fn endpoint_with_store(enabled: bool, store: FakeStore) -> DynamicRegistrationEndpoint {
    endpoint_with_config(
        application_config(),
        store,
        FakeGuard {
            enabled,
            rate_limit: None,
        },
    )
}

fn endpoint_with_config(
    config: DynamicRegistrationConfig,
    store: FakeStore,
    guard: FakeGuard,
) -> DynamicRegistrationEndpoint {
    DynamicRegistrationEndpoint::new(
        Arc::new(DynamicRegistrationApplication::new(
            config,
            Arc::new(store),
            Arc::new(FakeSecurity),
            DynamicRegistrationSecurityServices::new(
                Arc::new(FakeSecurity),
                Arc::new(FakeSecurity),
                Arc::new(FakeSecurity),
                Arc::new(FakeSecurity),
            ),
            Arc::new(guard),
        )),
        ClientIpConfig::new(&[], ClientIpHeaderMode::None),
    )
}

#[test]
fn bearer_credentials_are_closed_to_exact_non_empty_scheme_and_expected_token() {
    futures_executor::block_on(async {
        for (header, expected, authorized) in [
            (Some("Bearer initial-token"), None, false),
            (None, Some("initial-token"), false),
            (Some("Bearer   "), Some("initial-token"), false),
            (Some("bearer initial-token"), Some("initial-token"), true),
            (
                Some("Bearer initial-token extra"),
                Some("initial-token"),
                false,
            ),
            (
                Some("  Bearer initial-token  "),
                Some("initial-token"),
                true,
            ),
        ] {
            let mut config = application_config();
            config.initial_access_token = expected.map(str::to_owned);
            let endpoint = endpoint_with_config(
                config,
                FakeStore::new(),
                FakeGuard {
                    enabled: true,
                    rate_limit: None,
                },
            );
            let payload = serde_json::from_value(
                json!({"redirect_uris": ["https://client.example/callback"]}),
            )
            .unwrap();
            let result = endpoint
                .application
                .create(payload, header.and_then(parse_bearer), "203.0.113.77")
                .await;
            assert_eq!(
                result.is_ok(),
                authorized,
                "header={header:?}, expected={expected:?}"
            );
        }

        let request = http::Request::builder()
            .header(header::AUTHORIZATION, "Bearer registration-token")
            .body(Bytes::new())
            .unwrap();
        assert_eq!(bearer_token(&request), Some("registration-token"));
    });
}

#[test]
fn untrusted_peer_cannot_spoof_forwarded_source_ip() {
    futures_executor::block_on(async {
        let config = ClientIpConfig::new(
            &[IpCidr::parse("192.0.2.0/24").expect("network")],
            ClientIpHeaderMode::XForwardedFor,
        );
        let request = http::Request::builder()
            .extension(crate::integration::ConnectionFacts {
                peer_addr: Some("198.51.100.10:443".parse().expect("peer")),
                ..Default::default()
            })
            .header("x-forwarded-for", "203.0.113.9")
            .body(Bytes::new())
            .unwrap();

        assert_eq!(client_ip_with_config(&request, &config), "198.51.100.10");
    });
}

#[test]
fn authenticated_host_source_is_independent_of_forwarding_headers_and_proxy_trust() {
    for mode in [
        ClientIpHeaderMode::None,
        ClientIpHeaderMode::Forwarded,
        ClientIpHeaderMode::XForwardedFor,
    ] {
        let config = ClientIpConfig::new(&[IpCidr::parse("192.0.2.0/24").unwrap()], mode);
        for peer in [None, Some("192.0.2.10:443".parse().unwrap())] {
            let request = http::Request::builder()
                .extension(crate::integration::ConnectionFacts {
                    peer_addr: peer,
                    authenticated_client_ip: Some("198.51.100.7".parse().unwrap()),
                    ..Default::default()
                })
                .header("forwarded", "for=203.0.113.9")
                .header("x-forwarded-for", "203.0.113.9")
                .header("x-real-ip", "203.0.113.9")
                .header("cf-connecting-ip", "203.0.113.9")
                .body(Bytes::new())
                .unwrap();
            assert_eq!(client_ip_with_config(&request, &config), "198.51.100.7");
            assert_eq!(
                request_from_trusted_proxy_cidrs(
                    &request,
                    &[IpCidr::parse("192.0.2.0/24").unwrap()],
                ),
                peer.is_some(),
                "source facts cannot establish proxy/certificate trust"
            );
        }
    }
}

#[test]
fn claimed_platform_source_without_authenticated_facts_is_unknown() {
    let config = ClientIpConfig::new(&[], ClientIpHeaderMode::None);
    let request = http::Request::builder()
        .header("cf-connecting-ip", "203.0.113.9")
        .header("x-real-ip", "203.0.113.9")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(client_ip_with_config(&request, &config), "unknown");
}

#[test]
fn trusted_proxy_chain_selects_nearest_untrusted_hop() {
    futures_executor::block_on(async {
        let config = ClientIpConfig::new(
            &[IpCidr::parse("192.0.2.0/24").expect("network")],
            ClientIpHeaderMode::XForwardedFor,
        );
        let request = http::Request::builder()
            .extension(crate::integration::ConnectionFacts {
                peer_addr: Some("192.0.2.10:443".parse().expect("peer")),
                ..Default::default()
            })
            .header("x-forwarded-for", "203.0.113.9, 192.0.2.20")
            .body(Bytes::new())
            .unwrap();

        assert_eq!(client_ip_with_config(&request, &config), "203.0.113.9");
    });
}

#[test]
fn disabled_module_rejects_every_method_before_body_or_credentials() {
    futures_executor::block_on(async {
        let service = endpoint(false);
        for request in [
            http::Request::builder()
                .method("POST")
                .uri("/register")
                .body(Bytes::from("not-json"))
                .unwrap(),
            http::Request::builder()
                .uri("/register/client-test")
                .body(Bytes::new())
                .unwrap(),
            http::Request::builder()
                .method("PUT")
                .uri("/register/client-test")
                .body(Bytes::from("not-json"))
                .unwrap(),
            http::Request::builder()
                .method("DELETE")
                .uri("/register/client-test")
                .body(Bytes::new())
                .unwrap(),
        ] {
            let response = {
                let request = request;
                match request.method().as_str() {
                    "POST" => {
                        let mut request = request;
                        let body = std::mem::take(request.body_mut());
                        dynamic_client_registration(
                            &service,
                            &mut request,
                            std::future::ready(Ok(body)),
                        )
                        .await
                    }
                    "GET" => {
                        client_configuration_get(&service, &request, "client-test".into()).await
                    }
                    "PUT" => {
                        let mut request = request;
                        let body = std::mem::take(request.body_mut());
                        let path: String = "client-test".into();
                        client_configuration_put(
                            &service,
                            &mut request,
                            path,
                            std::future::ready(Ok(body)),
                        )
                        .await
                    }
                    "DELETE" => {
                        client_configuration_delete(&service, &request, "client-test".into()).await
                    }
                    _ => unreachable!(),
                }
            };
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    });
}

#[test]
fn registration_authentication_error_keeps_bearer_and_no_store_contract() {
    futures_executor::block_on(async {
        let service = endpoint(true);
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(serde_json::to_vec(&json!({})).unwrap()))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                dynamic_client_registration(&service, &mut request, std::future::ready(Ok(body)))
                    .await
            }
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&header::HeaderValue::from_static(
                "Bearer error=\"invalid_token\", error_description=\"Initial access token is missing or invalid.\""
            ))
        );
        let body: Value = serde_json::from_slice::<Value>(response.body()).unwrap();
        assert_eq!(body["error"], "invalid_token");
    });
}

#[test]
fn configured_initial_access_token_keeps_oauth_only_client_pkce_policy() {
    futures_executor::block_on(async {
        let store = FakeStore::new();
        let service = endpoint_with_store(true, store.clone());

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::AUTHORIZATION, "Bearer initial-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "grant_types": ["authorization_code"],
                        "redirect_uris": ["https://client.example/callback"],
                        "scope": "profile"
                    }))
                    .unwrap(),
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                dynamic_client_registration(&service, &mut request, std::future::ready(Ok(body)))
                    .await
            }
        };

        assert_eq!(response.status(), StatusCode::CREATED);
        let body: Value = serde_json::from_slice::<Value>(response.body()).unwrap();
        assert_eq!(body["client_secret"], "issued-secret");
        assert_eq!(body["client_secret_expires_at"], 0);
        assert!(body["client_id_issued_at"].is_i64());
        assert!(body.get("jwks").is_none());
        assert!(body.get("request_uris").is_none());
        let stored = store
            .client
            .lock()
            .expect("client lock")
            .clone()
            .expect("registered client");
        assert!(!stored.security_policy.allow_confidential_oidc_without_pkce);
    });
}

#[test]
fn configured_initial_access_token_registers_baseline_confidential_oidc_compatibility() {
    futures_executor::block_on(async {
        let store = FakeStore::new();
        let service = endpoint_with_store(true, store.clone());

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::AUTHORIZATION, "Bearer initial-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "grant_types": ["authorization_code"],
                        "redirect_uris": ["https://client.example/callback"],
                        "scope": "openid profile"
                    }))
                    .unwrap(),
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                dynamic_client_registration(&service, &mut request, std::future::ready(Ok(body)))
                    .await
            }
        };

        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(
            store
                .client
                .lock()
                .expect("client lock")
                .as_ref()
                .map(|client| &client.security_policy)
                .is_some_and(|policy| policy.allow_confidential_oidc_without_pkce)
        );
    });
}

#[test]
fn configured_initial_access_update_preserves_security_policy() {
    futures_executor::block_on(async {
        let store = FakeStore::new();
        let service = endpoint_with_store(true, store.clone());

        let created = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::AUTHORIZATION, "Bearer initial-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "grant_types": ["authorization_code"],
                        "redirect_uris": ["https://client.example/callback"],
                        "scope": "openid profile"
                    }))
                    .unwrap(),
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                dynamic_client_registration(&service, &mut request, std::future::ready(Ok(body)))
                    .await
            }
        };
        assert_eq!(created.status(), StatusCode::CREATED);
        let created: Value = serde_json::from_slice::<Value>(created.body()).unwrap();
        assert_eq!(created["backchannel_user_code_parameter"], false);
        let client_id = created["client_id"].as_str().expect("client id");
        assert!(
            store
                .client
                .lock()
                .expect("client lock")
                .as_ref()
                .map(|client| &client.security_policy)
                .is_some_and(|policy| policy.allow_confidential_oidc_without_pkce)
        );

        // An administrator can subsequently require PKCE. Client updates must
        // retain that decision instead of reapplying the registration default.
        store
            .client
            .lock()
            .expect("client lock")
            .as_mut()
            .expect("registered client")
            .security_policy
            .allow_confidential_oidc_without_pkce = false;

        let updated = {
            let request = http::Request::builder()
                .method("PUT")
                .uri(format!("/register/{client_id}"))
                .header(header::AUTHORIZATION, "Bearer registration-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "client_id": client_id,
                        "client_secret": "current-secret",
                        "scope": "openid",
                        "client_name": "Updated registered client",
                        "redirect_uris": ["https://client.example/callback"]
                    }))
                    .unwrap(),
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                let path: String = crate::http::parse_path(
                    request.uri().path().strip_prefix("/register/").unwrap(),
                )
                .unwrap();
                client_configuration_put(&service, &mut request, path, std::future::ready(Ok(body)))
                    .await
            }
        };
        assert_eq!(updated.status(), StatusCode::OK);
        assert!(
            store
                .client
                .lock()
                .expect("client lock")
                .as_ref()
                .map(|client| &client.security_policy)
                .is_some_and(|policy| !policy.allow_confidential_oidc_without_pkce)
        );
    });
}

#[test]
fn configured_public_client_keeps_strict_pkce_policy() {
    futures_executor::block_on(async {
        let store = FakeStore::new();
        let service = endpoint_with_store(true, store.clone());

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::AUTHORIZATION, "Bearer initial-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "token_endpoint_auth_method": "none",
                        "redirect_uris": ["https://client.example/callback"]
                    }))
                    .unwrap(),
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                dynamic_client_registration(&service, &mut request, std::future::ready(Ok(body)))
                    .await
            }
        };

        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(
            store
                .client
                .lock()
                .expect("client lock")
                .as_ref()
                .map(|client| &client.security_policy)
                .is_some_and(|policy| !policy.allow_confidential_oidc_without_pkce)
        );
    });
}

#[test]
fn unknown_initial_access_token_remains_invalid() {
    futures_executor::block_on(async {
        let service = endpoint(true);
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::AUTHORIZATION, "Bearer unknown-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(serde_json::to_vec(&json!({})).unwrap()))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                dynamic_client_registration(&service, &mut request, std::future::ready(Ok(body)))
                    .await
            }
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: Value = serde_json::from_slice::<Value>(response.body()).unwrap();
        assert_eq!(body["error"], "invalid_token");
    });
}

#[test]
fn registration_and_management_methods_keep_wire_contracts() {
    futures_executor::block_on(async {
        let endpoint = endpoint(true);
        let service = endpoint;
        let created = {
            let request = http::Request::builder().method("POST").uri("/register").header(header::AUTHORIZATION, "Bearer initial-token").header(header::CONTENT_TYPE, "application/json").body(Bytes::from(serde_json::to_vec(&json!({
                "client_name": "Registered Client",
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": [
                    "authorization_code",
                    "urn:openid:params:grant-type:ciba"
                ],
                "jwks_uri": "https://client.example/jwks.json",
                "request_uris": ["https://client.example/request.jwt"],
                "initiate_login_uri": "https://client.example/login/initiate",
                "logo_uri": "https://client.example/logo.svg",
                "policy_uri": "https://client.example/privacy",
                "tos_uri": "https://client.example/terms",
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["PS256", "RS256"],
                "id_token_encryption_alg_values_supported": ["RSA-OAEP-256"],
                "id_token_encryption_enc_values_supported": ["A256GCM"],
                "userinfo_signing_alg_values_supported": ["PS256"],
                "userinfo_encryption_alg_values_supported": ["ECDH-ES"],
                "userinfo_encryption_enc_values_supported": ["A256GCM"],
                "request_object_signing_alg_values_supported": ["PS256"],
                "request_object_encryption_alg_values_supported": ["RSA-OAEP-256"],
                "request_object_encryption_enc_values_supported": ["A256GCM"],
                "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["PS256"],
                "backchannel_authentication_request_signing_alg_values_supported": ["PS256"],
                "authorization_signing_alg_values_supported": ["PS256"],
                "authorization_encryption_alg_values_supported": ["ECDH-ES"],
                "authorization_encryption_enc_values_supported": ["A256GCM"],
                "introspection_signing_alg_values_supported": ["PS256"],
                "introspection_encryption_alg_values_supported": ["ECDH-ES"],
                "introspection_encryption_enc_values_supported": ["A256GCM"]
            })).unwrap())).unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                dynamic_client_registration(&service, &mut request, std::future::ready(Ok(body)))
                    .await
            }
        };
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(
            created.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
        let created: Value = serde_json::from_slice::<Value>(created.body()).unwrap();
        assert_eq!(created["backchannel_user_code_parameter"], false);
        let client_id = created["client_id"].as_str().expect("client id");
        assert_eq!(created["registration_access_token"], "registration-token");
        assert!(created.get("client_secret").is_none());
        assert_eq!(created["jwks_uri"], "https://client.example/jwks.json");
        assert!(created.get("jwks").is_none());
        assert_eq!(
            created["request_uris"],
            json!(["https://client.example/request.jwt"])
        );
        assert_eq!(
            created["initiate_login_uri"],
            "https://client.example/login/initiate"
        );
        assert_eq!(created["logo_uri"], "https://client.example/logo.svg");
        assert_eq!(created["policy_uri"], "https://client.example/privacy");
        assert_eq!(created["tos_uri"], "https://client.example/terms");
        assert_eq!(created["subject_type"], "public");
        assert_eq!(created["id_token_signed_response_alg"], "PS256");
        assert_eq!(created["id_token_encrypted_response_alg"], "RSA-OAEP-256");
        assert_eq!(created["id_token_encrypted_response_enc"], "A256GCM");
        assert_eq!(created["userinfo_signed_response_alg"], "PS256");
        assert_eq!(created["userinfo_encrypted_response_alg"], "ECDH-ES");
        assert_eq!(created["userinfo_encrypted_response_enc"], "A256GCM");
        assert_eq!(created["request_object_signing_alg"], "PS256");
        assert_eq!(created["request_object_encryption_alg"], "RSA-OAEP-256");
        assert_eq!(created["request_object_encryption_enc"], "A256GCM");
        assert_eq!(created["token_endpoint_auth_method"], "private_key_jwt");
        assert_eq!(created["token_endpoint_auth_signing_alg"], "PS256");
        assert_eq!(
            created["backchannel_authentication_request_signing_alg"],
            "PS256"
        );
        assert_eq!(created["authorization_signed_response_alg"], "PS256");
        assert_eq!(created["authorization_encrypted_response_alg"], "ECDH-ES");
        assert_eq!(created["authorization_encrypted_response_enc"], "A256GCM");
        assert_eq!(created["introspection_signed_response_alg"], "PS256");
        assert_eq!(created["introspection_encrypted_response_alg"], "ECDH-ES");
        assert_eq!(created["introspection_encrypted_response_enc"], "A256GCM");
        for &choices in RP_METADATA_CHOICE_FIELDS {
            assert!(
                created.get(choices).is_none(),
                "{choices} must be input-only"
            );
        }
        assert!(created["client_id_issued_at"].is_i64());
        assert_eq!(
            created["registration_client_uri"],
            format!("https://issuer.example/register/{client_id}")
        );

        let read = {
            let request = http::Request::builder()
                .uri(format!("/register/{client_id}"))
                .header(header::AUTHORIZATION, "Bearer registration-token")
                .body(Bytes::new())
                .unwrap();
            client_configuration_get(
                &service,
                &request,
                crate::http::parse_path(request.uri().path().strip_prefix("/register/").unwrap())
                    .unwrap(),
            )
            .await
        };
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(
            read.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
        let read: Value = serde_json::from_slice::<Value>(read.body()).unwrap();
        assert_eq!(read["registration_access_token"], "registration-token");
        assert!(read.get("client_secret").is_none());
        assert!(read.get("client_secret_expires_at").is_none());
        assert!(read.get("client_id_issued_at").is_none());
        for selected in [
            "subject_type",
            "id_token_signed_response_alg",
            "id_token_encrypted_response_alg",
            "id_token_encrypted_response_enc",
            "userinfo_signed_response_alg",
            "userinfo_encrypted_response_alg",
            "userinfo_encrypted_response_enc",
            "request_object_signing_alg",
            "request_object_encryption_alg",
            "request_object_encryption_enc",
            "token_endpoint_auth_method",
            "token_endpoint_auth_signing_alg",
            "backchannel_authentication_request_signing_alg",
            "authorization_signed_response_alg",
            "authorization_encrypted_response_alg",
            "authorization_encrypted_response_enc",
            "introspection_signed_response_alg",
            "introspection_encrypted_response_alg",
            "introspection_encrypted_response_enc",
        ] {
            assert_eq!(
                read[selected], created[selected],
                "{selected} must round-trip"
            );
        }
        for &choices in RP_METADATA_CHOICE_FIELDS {
            assert!(
                read.get(choices).is_none(),
                "{choices} must remain input-only"
            );
        }

        let update = {
            let request = http::Request::builder()
                .method("PUT")
                .uri(format!("/register/{client_id}"))
                .header(header::AUTHORIZATION, "Bearer registration-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "client_id": client_id,
                        "client_secret": "current-secret",
                        "scope": "openid",
                        "client_name": "Updated Client",
                        "redirect_uris": ["https://client.example/callback"]
                    }))
                    .unwrap(),
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                let path: String = crate::http::parse_path(
                    request.uri().path().strip_prefix("/register/").unwrap(),
                )
                .unwrap();
                client_configuration_put(&service, &mut request, path, std::future::ready(Ok(body)))
                    .await
            }
        };
        assert_eq!(update.status(), StatusCode::OK);
        let updated: Value = serde_json::from_slice::<Value>(update.body()).unwrap();
        assert_eq!(updated["backchannel_user_code_parameter"], false);
        assert_eq!(updated["client_name"], "Updated Client");
        let updated_client_id = updated["client_id"].as_str().expect("updated client id");

        let deleted = {
            let request = http::Request::builder()
                .method("DELETE")
                .uri(format!("/register/{updated_client_id}"))
                .header(header::AUTHORIZATION, "Bearer registration-token")
                .body(Bytes::new())
                .unwrap();
            client_configuration_delete(
                &service,
                &request,
                crate::http::parse_path(request.uri().path().strip_prefix("/register/").unwrap())
                    .unwrap(),
            )
            .await
        };
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            deleted.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
    });
}

#[test]
fn client_configuration_update_preserves_server_managed_security_policy() {
    futures_executor::block_on(async {
        let store = FakeStore::new();
        {
            let mut guard = store.client.lock().expect("client lock");
            let current = guard.as_mut().expect("fixture client");
            current.security_policy.session_management = true;
        }
        let service = endpoint_with_store(true, store.clone());

        let response = {
            let request = http::Request::builder()
                .method("PUT")
                .uri("/register/client-test")
                .header(header::AUTHORIZATION, "Bearer registration-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "client_id": "client-test",
                        "client_secret": "current-secret",
                        "scope": "openid",
                        "client_name": "Updated Client",
                        "redirect_uris": ["https://client.example/callback"]
                    }))
                    .unwrap(),
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                let path: String = crate::http::parse_path(
                    request.uri().path().strip_prefix("/register/").unwrap(),
                )
                .unwrap();
                client_configuration_put(&service, &mut request, path, std::future::ready(Ok(body)))
                    .await
            }
        };

        assert_eq!(response.status(), StatusCode::OK);
        let stored = store
            .client
            .lock()
            .expect("client lock")
            .clone()
            .expect("updated client");
        assert!(stored.security_policy.session_management);
    });
}

#[test]
fn client_configuration_update_validates_current_server_managed_policy() {
    futures_executor::block_on(async {
        let store = FakeStore::new();
        store
            .client
            .lock()
            .expect("client lock")
            .as_mut()
            .expect("fixture client")
            .registration
            .security_policy
            .version = u16::MAX;
        let service = endpoint_with_store(true, store.clone());

        let response = {
            let request = http::Request::builder()
                .method("PUT")
                .uri("/register/client-test")
                .header(header::AUTHORIZATION, "Bearer registration-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "client_id": "client-test",
                        "client_secret": "current-secret",
                        "client_name": "Updated Client",
                        "redirect_uris": ["https://client.example/callback"]
                    }))
                    .unwrap(),
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                let path: String = crate::http::parse_path(
                    request.uri().path().strip_prefix("/register/").unwrap(),
                )
                .unwrap();
                client_configuration_put(&service, &mut request, path, std::future::ready(Ok(body)))
                    .await
            }
        };

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let stored = store
            .client
            .lock()
            .expect("client lock")
            .clone()
            .expect("unchanged client");
        assert_eq!(stored.client_name, "Client");
    });
}

#[test]
fn client_configuration_read_preserves_authenticated_registration_token() {
    futures_executor::block_on(async {
        let service = endpoint(true);
        let response = {
            let request = http::Request::builder()
                .uri("/register/client-test")
                .header(
                    header::AUTHORIZATION,
                    "Bearer authenticated-registration-token",
                )
                .body(Bytes::new())
                .unwrap();
            client_configuration_get(
                &service,
                &request,
                crate::http::parse_path(request.uri().path().strip_prefix("/register/").unwrap())
                    .unwrap(),
            )
            .await
        };

        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice::<Value>(response.body()).unwrap();
        assert_eq!(
            body["registration_access_token"],
            "authenticated-registration-token"
        );
    });
}

#[test]
fn rate_limit_error_keeps_oauth_code_and_retry_after() {
    futures_executor::block_on(async {
        let endpoint = endpoint_with_config(
            application_config(),
            FakeStore::new(),
            FakeGuard {
                enabled: true,
                rate_limit: Some(DynamicRegistrationRateLimitError::Limited {
                    retry_after_seconds: 30,
                }),
            },
        );
        let service = endpoint;
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/register")
                .header(header::AUTHORIZATION, "Bearer initial-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(serde_json::to_vec(&json!({})).unwrap()))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                dynamic_client_registration(&service, &mut request, std::future::ready(Ok(body)))
                    .await
            }
        };
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "30");
        let body: Value = serde_json::from_slice::<Value>(response.body()).unwrap();
        assert_eq!(body["error"], "temporarily_unavailable");
    });
}

fn client() -> OAuthClient {
    let tenant = TenantContext::default_system();
    OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: tenant.tenant_id.as_uuid(),
        realm_id: tenant.realm_id.as_uuid(),
        organization_id: tenant.organization_id.as_uuid(),
        registration: ValidatedClientRegistration {
            client_id: "client-test".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".to_owned()],
            allowed_audiences: vec!["https://api.example".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: "client_secret_basic".to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks_uri: None,
            jwks: None,
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: nazo_auth::ClientPresentationMetadata::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            security_policy: nazo_auth::ClientSecurityPolicy::default(),
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

fn test_module_lease(enabled: bool) -> Option<nazo_runtime_modules::RequestLease> {
    use nazo_runtime_modules::{
        ActiveModuleSnapshot, CapabilityAdmission, ModuleId, ModuleRevision, SnapshotStore,
    };
    SnapshotStore::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(1),
        accepting: if enabled {
            [ModuleId::DynamicClientRegistration].into()
        } else {
            Default::default()
        },
        draining: Default::default(),
    })
    .lease(
        ModuleId::DynamicClientRegistration,
        CapabilityAdmission::NewRequest,
    )
}

#[test]
fn closed_admission_and_invalid_json_headers_never_poll_the_request_body() {
    futures_executor::block_on(async {
        for enabled in [false, true] {
            let endpoint = endpoint(enabled);
            let mut request = http::Request::builder()
                .method("POST")
                .uri("/register")
                .body(Bytes::new())
                .unwrap();
            let body = async { panic!("DCR must reject before consuming the body") };
            let response = dynamic_client_registration(&endpoint, &mut request, body).await;
            assert_eq!(
                response.status(),
                if enabled {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::NOT_FOUND
                }
            );
        }
    });
}
