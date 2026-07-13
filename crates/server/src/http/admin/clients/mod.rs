//! 管理端 OAuth 客户端 transport adapter。
pub(crate) mod create;
pub(crate) mod detail;
pub(crate) mod list;
pub(crate) mod update;

use crate::settings::Settings;
use crate::support::{
    client_jwks_contains_signing_key, client_jwks_matching_encryption_key_count,
    fetch_sector_identifier_uris, hash_client_secret, random_urlsafe_token,
    validate_client_jwks_with_missing_kid_policy, validate_self_signed_mtls_jwks,
};
use nazo_auth::{
    AdminClientCryptoPort, AdminClientPolicy, SectorIdentifierFuture, SectorIdentifierResolverPort,
};
use serde_json::Value;

pub(crate) type ServerAdminClientService = nazo_auth::AdminClientService<
    nazo_postgres::OAuthClientRepository,
    ServerSectorIdentifierResolver,
    ServerAdminClientCrypto,
>;

#[derive(Clone)]
pub(crate) struct AdminClientConfig {
    client_ip: crate::support::client_ip::ClientIpConfig,
}

impl AdminClientConfig {
    pub(crate) fn from_settings(settings: &Settings) -> Self {
        Self {
            client_ip: crate::support::client_ip::ClientIpConfig::new(
                &settings.endpoint.trusted_proxy_cidrs,
                settings.endpoint.client_ip_header_mode,
            ),
        }
    }

    pub(crate) fn client_ip(&self) -> &crate::support::client_ip::ClientIpConfig {
        &self.client_ip
    }
}

pub(crate) fn admin_client_policy(settings: &Settings) -> AdminClientPolicy {
    AdminClientPolicy {
        tenant: nazo_identity::TenantContext::default_system(),
        pairwise_subject_secret: settings.protocol.pairwise_subject_secret.clone(),
        client_secret_pepper: settings.protocol.client_secret_pepper.clone(),
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ServerSectorIdentifierResolver;

impl SectorIdentifierResolverPort for ServerSectorIdentifierResolver {
    fn resolve<'a>(&'a self, uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async move {
            fetch_sector_identifier_uris(uri)
                .await
                .map_err(|error| format!("{error:?}"))
        })
    }
}

#[derive(Clone)]
pub(crate) struct ServerAdminClientCrypto {
    keyset: nazo_key_management::KeyManager,
}

impl ServerAdminClientCrypto {
    pub(crate) fn new(keyset: nazo_key_management::KeyManager) -> Self {
        Self { keyset }
    }
}

impl AdminClientCryptoPort for ServerAdminClientCrypto {
    fn response_signing_algorithms(&self) -> Vec<String> {
        self.keyset
            .snapshot()
            .response_signing_alg_values_supported()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn issue_client_secret(&self, pepper: &str) -> (String, String) {
        let secret = random_urlsafe_token();
        let digest = hash_client_secret(&secret, pepper);
        (secret, digest)
    }

    fn validate_jwks(&self, jwks: &Value, allow_missing_kid: bool) -> Result<(), String> {
        validate_client_jwks_with_missing_kid_policy(jwks, allow_missing_kid)
            .map_err(|error| error.to_string())
    }

    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
        client_jwks_matching_encryption_key_count(jwks, algorithm)
    }

    fn contains_signing_key(&self, jwks: &Value) -> bool {
        client_jwks_contains_signing_key(jwks)
    }

    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool {
        validate_self_signed_mtls_jwks(jwks)
    }
}

#[cfg(test)]
pub(crate) struct AdminClientTestDependencies {
    pub(crate) sessions: actix_web::web::Data<crate::support::sessions::AdminSessionHandles>,
    pub(crate) service: actix_web::web::Data<ServerAdminClientService>,
    pub(crate) config: actix_web::web::Data<AdminClientConfig>,
}

#[cfg(test)]
pub(crate) fn test_dependencies(
    state: &actix_web::web::Data<crate::domain::AppState>,
) -> AdminClientTestDependencies {
    let session = &state.settings.session;
    AdminClientTestDependencies {
        sessions: actix_web::web::Data::new(crate::support::sessions::AdminSessionHandles::new(
            nazo_valkey::SessionStore::new(&state.valkey_connection()),
            nazo_postgres::UserRepository::new(state.diesel_db.clone()),
            crate::support::sessions::SessionHttpConfig::new(
                &session.session_cookie_name,
                &session.csrf_cookie_name,
                session.cookie_secure,
            ),
        )),
        service: actix_web::web::Data::new(ServerAdminClientService::new(
            nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
            ServerSectorIdentifierResolver,
            ServerAdminClientCrypto::new(state.keyset.clone()),
            admin_client_policy(&state.settings),
        )),
        config: actix_web::web::Data::new(AdminClientConfig::from_settings(&state.settings)),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::ServerSectorIdentifierResolver;
    use crate::support::{
        client_jwks_contains_signing_key, client_jwks_matching_encryption_key_count,
        hash_client_secret, random_urlsafe_token, validate_client_jwks_with_missing_kid_policy,
        validate_self_signed_mtls_jwks,
    };
    use nazo_auth::AdminClientCryptoPort;
    use serde_json::Value;

    pub(crate) use nazo_auth::{
        AdminClientError as InsertClientError, CreateClientRequest, PreparedClientRegistration,
    };

    pub(crate) async fn prepare_client_insert_with_secret_pepper(
        payload: CreateClientRequest,
        pairwise_subject_secret: Option<&str>,
        client_secret_pepper: &str,
        _issuer: &str,
        response_signing_algorithms: &[&'static str],
    ) -> Result<PreparedClientRegistration, InsertClientError> {
        let crypto = TestAdminClientCrypto {
            response_signing_algorithms,
        };
        nazo_auth::prepare_client_registration(
            payload,
            &nazo_auth::AdminClientPolicy {
                tenant: nazo_identity::TenantContext::default_system(),
                pairwise_subject_secret: pairwise_subject_secret.map(ToOwned::to_owned),
                client_secret_pepper: client_secret_pepper.to_owned(),
            },
            &ServerSectorIdentifierResolver,
            &crypto,
        )
        .await
    }

    struct TestAdminClientCrypto<'a> {
        response_signing_algorithms: &'a [&'static str],
    }

    impl AdminClientCryptoPort for TestAdminClientCrypto<'_> {
        fn response_signing_algorithms(&self) -> Vec<String> {
            self.response_signing_algorithms
                .iter()
                .map(|algorithm| (*algorithm).to_owned())
                .collect()
        }

        fn issue_client_secret(&self, pepper: &str) -> (String, String) {
            let secret = random_urlsafe_token();
            let digest = hash_client_secret(&secret, pepper);
            (secret, digest)
        }

        fn validate_jwks(&self, jwks: &Value, allow_missing_kid: bool) -> Result<(), String> {
            validate_client_jwks_with_missing_kid_policy(jwks, allow_missing_kid)
                .map_err(|error| error.to_string())
        }

        fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
            client_jwks_matching_encryption_key_count(jwks, algorithm)
        }

        fn contains_signing_key(&self, jwks: &Value) -> bool {
            client_jwks_contains_signing_key(jwks)
        }

        fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool {
            validate_self_signed_mtls_jwks(jwks)
        }
    }

    pub(crate) async fn insert_prepared_client(
        repository: &nazo_postgres::OAuthClientRepository,
        prepared: &PreparedClientRegistration,
    ) -> Result<nazo_auth::OAuthClient, InsertClientError> {
        nazo_auth::insert_prepared_client(repository, prepared).await
    }

    pub(crate) async fn prepare_client_patch(
        current: &nazo_auth::OAuthClient,
        payload: nazo_auth::PatchClientRequest,
        pairwise_subject_secret: Option<&str>,
        _issuer: &str,
        response_signing_algorithms: &[&'static str],
    ) -> Result<nazo_auth::OAuthClient, InsertClientError> {
        let crypto = TestAdminClientCrypto {
            response_signing_algorithms,
        };
        nazo_auth::prepare_client_patch(
            current.clone(),
            payload,
            &nazo_auth::AdminClientPolicy {
                tenant: nazo_identity::TenantContext::default_system(),
                pairwise_subject_secret: pairwise_subject_secret.map(ToOwned::to_owned),
                client_secret_pepper: crate::support::LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER
                    .to_owned(),
            },
            &ServerSectorIdentifierResolver,
            &crypto,
        )
        .await
    }
}

#[cfg(test)]
mod boundary_tests {
    #[test]
    fn admin_client_handlers_use_focused_service() {
        for (name, source) in [
            ("create", include_str!("create.rs")),
            ("list", include_str!("list.rs")),
            ("detail", include_str!("detail.rs")),
            ("update", include_str!("update.rs")),
        ] {
            for forbidden in [
                "OAuthClientRepository",
                "nazo_postgres",
                "ClientRow",
                "KeyManager",
                "Data<AppState>",
            ] {
                assert!(!source.contains(forbidden), "{name} contains {forbidden}");
            }
        }
    }
}
