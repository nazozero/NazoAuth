use std::sync::{Arc, Mutex};

use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId};
use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::{
    AdminClientCryptoPort, AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort,
    SectorIdentifierFuture, SectorIdentifierResolverPort,
};

#[derive(Clone, Default)]
struct CapturingRepository(Arc<Mutex<Vec<(Uuid, i64, i64)>>>);

impl AdminClientRepositoryPort for CapturingRepository {
    fn page(
        &self,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        self.0.lock().unwrap().push((tenant_id, offset, limit));
        Box::pin(async { Ok((Vec::new(), 0)) })
    }

    fn by_client_id<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }

    fn insert<'a>(
        &'a self,
        _client: &'a OAuthClient,
        _client_secret_hash: Option<&'a str>,
        _registration_access_token_blake3: Option<&'a str>,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }

    fn update<'a>(
        &'a self,
        _expected: &'a OAuthClient,
        _client: &'a OAuthClient,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unexpected) })
    }
}

#[derive(Clone, Copy)]
struct NoopSectorIdentifierResolver;

impl SectorIdentifierResolverPort for NoopSectorIdentifierResolver {
    fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async { Err("unexpected sector identifier lookup".to_owned()) })
    }
}

#[derive(Clone, Copy)]
struct NoopCrypto;

impl AdminClientCryptoPort for NoopCrypto {
    fn response_signing_algorithms(&self) -> Vec<String> {
        Vec::new()
    }

    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        unreachable!("page and public registration do not issue client secrets")
    }

    fn validate_jwks(&self, _jwks: &Value) -> Result<(), String> {
        Err("unexpected JWKS validation".to_owned())
    }

    fn validate_rfc4514_dn(&self, _value: &str) -> Result<(), String> {
        Err("unexpected distinguished name validation".to_owned())
    }

    fn matching_encryption_key_count(&self, _jwks: &Value, _algorithm: &str) -> usize {
        0
    }

    fn contains_signing_key(&self, _jwks: &Value) -> bool {
        false
    }

    fn valid_self_signed_mtls_jwks(&self, _jwks: &Value) -> bool {
        false
    }
}

fn policy() -> AdminClientPolicy {
    AdminClientPolicy {
        tenant: TenantContext {
            tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
            realm_id: RealmId::new(Uuid::now_v7()).unwrap(),
            organization_id: OrganizationId::new(Uuid::now_v7()).unwrap(),
        },
        pairwise_subject_secret: None,
        client_secret_pepper: "test-only".to_owned(),
    }
}

fn registration(subject_type: Option<&str>) -> CreateClientRequest {
    serde_json::from_value(serde_json::json!({
        "client_name": "Subject contract",
        "client_type": "public",
        "redirect_uris": ["https://client.example/callback"],
        "scopes": ["openid"],
        "allowed_audiences": ["resource://default"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "none",
        "subject_type": subject_type,
        "jwks": null,
    }))
    .unwrap()
}

#[test]
fn page_forwards_the_policy_tenant_to_persistence() {
    let policy = policy();
    let tenant = policy.tenant;
    let repository = CapturingRepository::default();
    let observed = repository.0.clone();
    let service = AdminClientService::new(
        repository,
        NoopSectorIdentifierResolver,
        NoopCrypto,
        policy,
    );

    let (clients, total) = futures_executor::block_on(service.page(17, 23)).unwrap();
    assert!(clients.is_empty());
    assert_eq!(total, 0);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![(tenant.tenant_id.as_uuid(), 17, 23)]
    );
}

#[test]
fn registration_rejects_unknown_subject_types_before_persistence() {
    let service = AdminClientService::new(
        CapturingRepository::default(),
        NoopSectorIdentifierResolver,
        NoopCrypto,
        policy(),
    );
    for subject_type in ["", "PUBLIC", "user", "unsupported"] {
        let result = futures_executor::block_on(
            service.prepare_registration(registration(Some(subject_type))),
        );
        assert!(matches!(result, Err(AdminClientError::InvalidRequest(_))));
    }
    for subject_type in [None, Some("public")] {
        let prepared = futures_executor::block_on(
            service.prepare_registration(registration(subject_type)),
        )
        .unwrap();
        assert_eq!(prepared.registration.subject_type, "public");
    }
}

#[test]
fn client_patch_keeps_subject_type_validation_in_the_core() {
    let mut policy = policy();
    policy.pairwise_subject_secret = Some("test-only-pairwise-secret".to_owned());
    let prepared = futures_executor::block_on(
        super::super::registration::prepare_client_registration(
            registration(Some("pairwise")),
            &policy,
            &NoopSectorIdentifierResolver,
            &NoopCrypto,
        ),
    )
    .unwrap();
    let original = prepared.into_write().client;
    assert_eq!(original.sector_identifier_host.as_deref(), Some("client.example"));
    for subject_type in ["", "PUBLIC", "user", "unsupported"] {
        let result = futures_executor::block_on(super::super::patch::prepare_client_patch(
            original.clone(),
            PatchClientRequest {
                subject_type: Some(subject_type.to_owned()),
                ..PatchClientRequest::default()
            },
            &policy,
            &NoopSectorIdentifierResolver,
            &NoopCrypto,
        ));
        assert!(matches!(result, Err(AdminClientError::InvalidRequest(_))));
    }
    let retained = futures_executor::block_on(super::super::patch::prepare_client_patch(
        original.clone(),
        PatchClientRequest::default(),
        &policy,
        &NoopSectorIdentifierResolver,
        &NoopCrypto,
    ))
    .unwrap();
    assert_eq!(retained, original);
}
