use super::{
    AdminClientConfig, ServerAdminClientCrypto, ServerAdminClientService, admin_client_policy,
};
use crate::settings::Settings;
use crate::test_support::hash_client_secret_fixture as hash_client_secret;
use nazo_auth::AdminClientCryptoPort;
use nazo_key_management::inspect_client_jwks;
use nazo_oauth_server::crypto::random_urlsafe_token;
use serde_json::Value;
use std::sync::Arc;

fn sector_identifier_resolver()
-> crate::adapters::remote_client_documents::RemoteClientDocumentResolver {
    crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
        .expect("empty sector-identifier policy should be valid")
}

pub(crate) use nazo_auth::{
    AdminClientError as InsertClientError, CreateClientRequest, PreparedClientRegistration,
};

pub(crate) fn admin_session_handles(
    database: nazo_postgres::DbPool,
    valkey: nazo_valkey::ValkeyConnection,
    settings: &Settings,
) -> actix_web::web::Data<crate::http::sessions::AdminSessionHandles> {
    let session = &settings.session;
    actix_web::web::Data::new(crate::http::sessions::AdminSessionHandles::new(
        std::sync::Arc::new(nazo_oauth_server::sessions::SessionResolver::new(
            Arc::new(nazo_valkey::SessionStore::new(&valkey)),
            Arc::new(nazo_postgres::UserRepository::new(database)),
            settings.tenant.context.tenant_id,
        )),
        crate::http::sessions::SessionHttpConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    ))
}

pub(crate) fn admin_client_service(
    database: nazo_postgres::DbPool,
    keyset: nazo_key_management::KeyManager,
    settings: &Settings,
) -> actix_web::web::Data<ServerAdminClientService> {
    actix_web::web::Data::new(ServerAdminClientService::new(
        std::sync::Arc::new(nazo_postgres::OAuthClientRepository::new(database))
            as std::sync::Arc<dyn nazo_auth::AdminClientRepositoryPort>,
        sector_identifier_resolver(),
        ServerAdminClientCrypto::new(keyset),
        admin_client_policy(settings),
    ))
}

pub(crate) fn admin_client_config(settings: &Settings) -> actix_web::web::Data<AdminClientConfig> {
    actix_web::web::Data::new(AdminClientConfig::from_settings(settings))
}

pub(crate) async fn prepare_client_insert_with_secret_pepper(
    payload: CreateClientRequest,
    pairwise_subject_secret: Option<&str>,
    client_secret_pepper: &str,
    _issuer: &str,
    tenant: nazo_identity::TenantContext,
    response_signing_algorithms: &[&'static str],
) -> Result<PreparedClientRegistration, InsertClientError> {
    let crypto = TestAdminClientCrypto {
        response_signing_algorithms,
    };
    let sector_identifiers = sector_identifier_resolver();
    nazo_auth::prepare_client_registration(
        payload,
        &nazo_auth::AdminClientPolicy {
            tenant,
            pairwise_subject_secret: pairwise_subject_secret.map(ToOwned::to_owned),
            client_secret_pepper: client_secret_pepper.to_owned(),
        },
        &sector_identifiers,
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

    fn inspect_jwks(
        &self,
        jwks: &Value,
        certificate_auth: bool,
    ) -> Result<nazo_auth::ClientJwksCapabilities, String> {
        inspect_client_jwks(jwks, certificate_auth)
    }

    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        nazo_key_management::validate_rfc4514_dn(value)
    }
}

pub(crate) async fn insert_prepared_client(
    repository: &nazo_postgres::OAuthClientRepository,
    prepared: &PreparedClientRegistration,
) -> anyhow::Result<nazo_auth::OAuthClient> {
    let prepared = prepared.clone().into_write();
    Ok(repository
        .insert(
            &prepared.client,
            prepared.client_secret_hash.as_deref(),
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await?)
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
    let sector_identifiers = sector_identifier_resolver();
    nazo_auth::prepare_client_patch(
        current.clone(),
        payload,
        &nazo_auth::AdminClientPolicy {
            tenant: nazo_identity::TenantContext::default_system(),
            pairwise_subject_secret: pairwise_subject_secret.map(ToOwned::to_owned),
            client_secret_pepper: crate::adapters::security::LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER
                .to_owned(),
        },
        &sector_identifiers,
        &crypto,
    )
    .await
}
