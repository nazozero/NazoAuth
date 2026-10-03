use super::*;
use nazo_identity::ports::{
    DeliveryConsume, DeliveryPublish, DeliveryRecord, DeliveryStage, DeliveryStageResult,
    DeliveryStorePort, RepositoryError, RepositoryFuture,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Barrier;

struct PublishGate {
    entered: Barrier,
    release: Barrier,
}

struct ControlledDelivery {
    inner: Arc<dyn DeliveryStorePort>,
    gate: Option<Arc<PublishGate>>,
    unknown_after_publish: bool,
    fail_before_publish: bool,
    calls: AtomicUsize,
}

impl DeliveryStorePort for ControlledDelivery {
    fn stage<'a>(
        &'a self,
        user: nazo_identity::UserId,
        token: &'a str,
        stage: DeliveryStage,
    ) -> RepositoryFuture<'a, DeliveryStageResult> {
        self.inner.stage(user, token, stage)
    }
    fn publish<'a>(
        &'a self,
        user: nazo_identity::UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
        client: Uuid,
    ) -> RepositoryFuture<'a, DeliveryPublish> {
        Box::pin(async move {
            if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
                if let Some(gate) = self.gate.as_ref() {
                    gate.entered.wait().await;
                    gate.release.wait().await;
                }
                if self.fail_before_publish {
                    return Err(RepositoryError::Unavailable);
                }
                let result = self.inner.publish(user, token, expected, client).await?;
                if self.unknown_after_publish {
                    return Err(RepositoryError::Unavailable);
                }
                return Ok(result);
            }
            self.inner.publish(user, token, expected, client).await
        })
    }
    fn load<'a>(
        &'a self,
        user: nazo_identity::UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>> {
        DeliveryStorePort::load(self.inner.as_ref(), user, token)
    }
    fn load_many<'a>(
        &'a self,
        lookups: &'a [(nazo_identity::UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>> {
        self.inner.load_many(lookups)
    }
    fn retire<'a>(
        &'a self,
        user: nazo_identity::UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, bool> {
        self.inner.retire(user, token, expected)
    }
    fn consume<'a>(
        &'a self,
        user: nazo_identity::UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume> {
        self.inner.consume(user, token, expected)
    }
}

struct UnknownApproval {
    inner: Arc<dyn AdminAccessRequestStore>,
    commits: AtomicUsize,
}

impl AdminAccessRequestStore for UnknownApproval {
    fn approved_delivery_matches<'a>(
        &'a self,
        tenant: nazo_identity::TenantId,
        user: nazo_identity::UserId,
        request: Uuid,
        client: Uuid,
        public_id: &'a str,
        binding: Option<&'a str>,
    ) -> RepositoryFuture<'a, bool> {
        self.inner
            .approved_delivery_matches(tenant, user, request, client, public_id, binding)
    }
    fn page<'a>(
        &'a self,
        tenant: nazo_identity::TenantId,
        limit: i64,
        offset: i64,
        search: Option<&'a str>,
        status: Option<AccessRequestStatus>,
    ) -> RepositoryFuture<'a, nazo_identity::AccessRequestPage> {
        self.inner.page(tenant, limit, offset, search, status)
    }
    fn by_id(
        &self,
        tenant: nazo_identity::TenantId,
        id: Uuid,
    ) -> RepositoryFuture<'_, Option<nazo_identity::AccessRequest>> {
        self.inner.by_id(tenant, id)
    }
    fn approve<'a>(
        &'a self,
        tenant: nazo_identity::TenantContext,
        id: Uuid,
        actor: nazo_identity::UserId,
        prepared: &'a nazo_auth::PreparedClientRegistration,
    ) -> RepositoryFuture<'a, nazo_auth::ApprovedClient> {
        Box::pin(async move {
            let _committed = self.inner.approve(tenant, id, actor, prepared).await?;
            self.commits.fetch_add(1, Ordering::AcqRel);
            Err(RepositoryError::Unavailable)
        })
    }
    fn reject(
        &self,
        tenant: nazo_identity::TenantId,
        id: Uuid,
        actor: nazo_identity::UserId,
        note: String,
    ) -> RepositoryFuture<'_, ()> {
        self.inner.reject(tenant, id, actor, note)
    }
}

fn secret_registration() -> CreateClientRequest {
    let mut payload = create_client_request();
    payload.token_endpoint_auth_method = "client_secret_post".to_owned();
    payload.jwks = None;
    payload
}

async fn approve_with(
    fixture: &LiveAdminAccessRequestFixture,
    mut dependencies: TestAdminAccessRequestDependencies,
    sid: &str,
    id: Uuid,
    delivery: Option<Arc<dyn DeliveryStorePort>>,
    repository: Option<Arc<dyn AdminAccessRequestStore>>,
) -> HttpResponse {
    if let Some(store) = delivery {
        dependencies.delivery_store = Data::from(store);
    }
    if let Some(store) = repository {
        dependencies.repository = Data::from(store);
    }
    admin_approve_access_request(
        dependencies.admin_sessions,
        (
            dependencies.repository,
            dependencies.delivery_store,
            dependencies.client_service,
            dependencies.config,
            dependencies.client_ip_config,
        ),
        fixture.admin_post_request(
            sid,
            "delivery-race-csrf",
            "/admin/access-requests/request/approve",
        ),
        actix_web::web::Path::from(id),
        Json(secret_registration()),
    )
    .await
}

#[actix_web::test]
async fn recovery_claim_before_original_publish_resumes_discloses_secret_at_most_once() {
    let fixture = LiveAdminAccessRequestFixture::new()
        .await
        .expect("real PG/Valkey fixture required");
    let suffix = Uuid::now_v7().to_string();
    let admin = fixture
        .create_user(&format!("race-admin-{suffix}"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("race-user-{suffix}"), "user", 0)
        .await;
    let sid = format!("race-admin-{suffix}");
    let user_sid = format!("race-user-{suffix}");
    fixture.store_session(&admin, &sid).await;
    fixture.store_session(&applicant, &user_sid).await;
    let id = fixture
        .insert_access_request(&applicant, "RecoveryRace", AccessRequestStatus::Pending)
        .await;
    let gate = Arc::new(PublishGate {
        entered: Barrier::new(2),
        release: Barrier::new(2),
    });
    let dependencies = admin_access_request_dependencies(&fixture.state);
    let inner: Arc<dyn DeliveryStorePort> = Arc::new(nazo_valkey::DeliveryStore::new(
        &fixture.state.valkey_connection(),
    ));
    let store: Arc<dyn DeliveryStorePort> = Arc::new(ControlledDelivery {
        inner: Arc::new(nazo_valkey::DeliveryStore::new(
            &fixture.state.valkey_connection(),
        )),
        gate: Some(gate.clone()),
        unknown_after_publish: false,
        fail_before_publish: false,
        calls: AtomicUsize::new(0),
    });
    let original = approve_with(&fixture, dependencies, &sid, id, Some(store), None);
    let recovery_and_claim = async {
        gate.entered.wait().await;
        let token = access_delivery_token(
            &fixture.state.settings.protocol.client_secret_pepper,
            applicant.id,
            id,
        );
        let user = nazo_identity::UserId::new(applicant.id).unwrap();
        let staged = DeliveryStorePort::load(inner.as_ref(), user, &token)
            .await
            .unwrap()
            .unwrap();
        let recovered = invoke_admin_approve_access_request(
            fixture.state.clone(),
            fixture.admin_post_request(
                &sid,
                "delivery-race-csrf",
                "/admin/access-requests/request/approve",
            ),
            actix_web::web::Path::from(id),
            Json(secret_registration()),
        )
        .await;
        assert_eq!(recovered.status(), StatusCode::OK);
        let committed = DeliveryStorePort::load(inner.as_ref(), user, &token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(committed.expires_at, staged.expires_at);
        assert_eq!(committed.attempt_id, staged.attempt_id);
        let mut disclosures = 0;
        for _ in 0..2 {
            let response = profile_delivery_from_state(
                fixture.state.clone(),
                fixture.admin_post_request(
                    &user_sid,
                    "delivery-user-csrf",
                    "/profile/access-delivery",
                ),
                Json(crate::http::profile::delivery::AccessDeliveryRequest { request_id: id }),
            )
            .await;
            let (status, body) = json_body(response).await;
            if status == StatusCode::OK {
                assert!(body["client_secret"] == staged.value["client_secret"]);
                assert!(body.get("secret_binding").is_none());
                disclosures += 1;
            } else {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
        }
        assert_eq!(disclosures, 1);
        gate.release.wait().await;
        token
    };
    let (original, token) = tokio::join!(original, recovery_and_claim);
    assert_eq!(original.status(), StatusCode::SERVICE_UNAVAILABLE);
    let user = nazo_identity::UserId::new(applicant.id).unwrap();
    let store = Arc::new(nazo_valkey::DeliveryStore::new(
        &fixture.state.valkey_connection(),
    ));
    assert!(
        DeliveryStorePort::load(store.as_ref(), user, &token)
            .await
            .unwrap()
            .is_none(),
        "late publisher must not recreate consumed credentials"
    );
}

#[actix_web::test]
async fn unknown_approval_ack_retains_original_stage_and_recovers_without_secret_or_ttl_rotation() {
    let fixture = LiveAdminAccessRequestFixture::new()
        .await
        .expect("real PG/Valkey fixture required");
    let suffix = Uuid::now_v7().to_string();
    let admin = fixture
        .create_user(&format!("unknown-admin-{suffix}"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("unknown-user-{suffix}"), "user", 0)
        .await;
    let sid = format!("unknown-admin-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let id = fixture
        .insert_access_request(&applicant, "UnknownApproval", AccessRequestStatus::Pending)
        .await;
    let dependencies = admin_access_request_dependencies(&fixture.state);
    let repository = Arc::new(UnknownApproval {
        inner: Arc::new(AccessRequestRepository::new(
            fixture.state.diesel_db.clone(),
        )),
        commits: AtomicUsize::new(0),
    });
    let response = approve_with(
        &fixture,
        dependencies,
        &sid,
        id,
        None,
        Some(repository.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(AtomicUsize::load(&repository.commits, Ordering::Acquire), 1);
    let store = Arc::new(nazo_valkey::DeliveryStore::new(
        &fixture.state.valkey_connection(),
    ));
    let user = nazo_identity::UserId::new(applicant.id).unwrap();
    let token = access_delivery_token(
        &fixture.state.settings.protocol.client_secret_pepper,
        applicant.id,
        id,
    );
    let before = DeliveryStorePort::load(store.as_ref(), user, &token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.value["delivery_state"], "staged");
    let row = AccessRequestRepository::new(fixture.state.diesel_db.clone())
        .by_id(fixture.state.settings.tenant.context.tenant_id, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, AccessRequestStatus::Approved);
    let response = invoke_admin_approve_access_request(
        fixture.state.clone(),
        fixture.admin_post_request(
            &sid,
            "delivery-race-csrf",
            "/admin/access-requests/request/approve",
        ),
        actix_web::web::Path::from(id),
        Json(secret_registration()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let after = DeliveryStorePort::load(store.as_ref(), user, &token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.attempt_id, before.attempt_id);
    assert_eq!(after.expires_at, before.expires_at);
    assert!(after.secret_binding == before.secret_binding);
    assert!(after.value["client_secret"] == before.value["client_secret"]);
    assert_eq!(
        AtomicUsize::load(&repository.commits, Ordering::Acquire),
        1,
        "recovery must not approve or rotate again"
    );
}

#[actix_web::test]
async fn unknown_publish_ack_keeps_one_current_secret_and_never_recreates_after_claim() {
    let fixture = LiveAdminAccessRequestFixture::new()
        .await
        .expect("real PG/Valkey fixture required");
    let suffix = Uuid::now_v7().to_string();
    let admin = fixture
        .create_user(&format!("publish-admin-{suffix}"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("publish-user-{suffix}"), "user", 0)
        .await;
    let sid = format!("publish-admin-{suffix}");
    let user_sid = format!("publish-user-{suffix}");
    fixture.store_session(&admin, &sid).await;
    fixture.store_session(&applicant, &user_sid).await;
    let id = fixture
        .insert_access_request(&applicant, "UnknownPublish", AccessRequestStatus::Pending)
        .await;
    let store = Arc::new(ControlledDelivery {
        inner: Arc::new(nazo_valkey::DeliveryStore::new(
            &fixture.state.valkey_connection(),
        )),
        gate: None,
        unknown_after_publish: true,
        fail_before_publish: false,
        calls: AtomicUsize::new(0),
    });
    let response = approve_with(
        &fixture,
        admin_access_request_dependencies(&fixture.state),
        &sid,
        id,
        Some(store.clone()),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let token = access_delivery_token(
        &fixture.state.settings.protocol.client_secret_pepper,
        applicant.id,
        id,
    );
    let user = nazo_identity::UserId::new(applicant.id).unwrap();
    let before = DeliveryStorePort::load(store.as_ref(), user, &token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.value["delivery_state"], "committed");
    let mut disclosures = 0;
    for _ in 0..2 {
        let response = profile_delivery_from_state(
            fixture.state.clone(),
            fixture.admin_post_request(&user_sid, "delivery-user-csrf", "/profile/access-delivery"),
            Json(crate::http::profile::delivery::AccessDeliveryRequest { request_id: id }),
        )
        .await;
        let (status, body) = json_body(response).await;
        if status == StatusCode::OK {
            assert!(body["client_secret"] == before.value["client_secret"]);
            disclosures += 1;
        } else {
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }
    assert_eq!(disclosures, 1);
    let response = invoke_admin_approve_access_request(
        fixture.state.clone(),
        fixture.admin_post_request(
            &sid,
            "delivery-race-csrf",
            "/admin/access-requests/request/approve",
        ),
        actix_web::web::Path::from(id),
        Json(secret_registration()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        DeliveryStorePort::load(store.as_ref(), user, &token)
            .await
            .unwrap()
            .is_none()
    );
}

#[actix_web::test]
async fn verified_recovery_rejects_wrong_client_secret_and_rotated_generation_without_touching_stage()
 {
    let fixture = LiveAdminAccessRequestFixture::new()
        .await
        .expect("real PG/Valkey fixture required");
    let suffix = Uuid::now_v7().to_string();
    let admin = fixture
        .create_user(&format!("binding-admin-{suffix}"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("binding-user-{suffix}"), "user", 0)
        .await;
    let sid = format!("binding-admin-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let id = fixture
        .insert_access_request(&applicant, "BindingRecovery", AccessRequestStatus::Pending)
        .await;
    let store = Arc::new(ControlledDelivery {
        inner: Arc::new(nazo_valkey::DeliveryStore::new(
            &fixture.state.valkey_connection(),
        )),
        gate: None,
        unknown_after_publish: false,
        fail_before_publish: true,
        calls: AtomicUsize::new(0),
    });
    let response = approve_with(
        &fixture,
        admin_access_request_dependencies(&fixture.state),
        &sid,
        id,
        Some(store.clone()),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let user = nazo_identity::UserId::new(applicant.id).unwrap();
    let token = access_delivery_token(
        &fixture.state.settings.protocol.client_secret_pepper,
        applicant.id,
        id,
    );
    let original = DeliveryStorePort::load(store.as_ref(), user, &token)
        .await
        .unwrap()
        .unwrap();
    let repository = AccessRequestRepository::new(fixture.state.diesel_db.clone());
    let row = repository
        .by_id(fixture.state.settings.tenant.context.tenant_id, id)
        .await
        .unwrap()
        .unwrap();
    let config =
        AdminAccessRequestConfig::new(&fixture.state.settings.protocol.client_secret_pepper, 3600);
    for field in ["client_id", "client_secret"] {
        let current = DeliveryStorePort::load(store.as_ref(), user, &token)
            .await
            .unwrap()
            .unwrap();
        assert!(store.retire(user, &token, &current).await.unwrap());
        let mut value = original.value.clone();
        value[field] = json!("another-attempt");
        let bad = match store
            .stage(
                user,
                &token,
                DeliveryStage {
                    attempt_id: Uuid::now_v7(),
                    expires_at: original.expires_at,
                    secret_binding: original.secret_binding.clone(),
                    value,
                },
            )
            .await
            .unwrap()
        {
            DeliveryStageResult::Created(record) => record,
            _ => panic!("fresh bad-binding fixture should stage"),
        };
        assert!(
            !resume_staged_client_delivery(&repository, store.as_ref(), &config, &row)
                .await
                .unwrap()
        );
        assert_eq!(
            DeliveryStorePort::load(store.as_ref(), user, &token)
                .await
                .unwrap()
                .unwrap()
                .opaque_version,
            bad.opaque_version
        );
        assert_eq!(
            DeliveryStorePort::load(store.as_ref(), user, &token)
                .await
                .unwrap()
                .unwrap()
                .expires_at,
            original.expires_at
        );
    }
    let current = DeliveryStorePort::load(store.as_ref(), user, &token)
        .await
        .unwrap()
        .unwrap();
    assert!(store.retire(user, &token, &current).await.unwrap());
    let valid = match store
        .stage(
            user,
            &token,
            DeliveryStage {
                attempt_id: Uuid::now_v7(),
                expires_at: original.expires_at,
                secret_binding: original.secret_binding.clone(),
                value: original.value.clone(),
            },
        )
        .await
        .unwrap()
    {
        DeliveryStageResult::Created(record) => record,
        _ => panic!("valid generation fixture should stage"),
    };
    let mut connection = get_conn(&fixture.state.diesel_db).await.unwrap();
    sql_query("UPDATE oauth_clients SET client_secret_hash=$1 WHERE id=$2")
        .bind::<Text, _>("client-secret-v1:rotated-salt:rotated-digest")
        .bind::<SqlUuid, _>(row.approved_client_id.unwrap())
        .execute(&mut connection)
        .await
        .unwrap();
    assert!(
        !resume_staged_client_delivery(&repository, store.as_ref(), &config, &row)
            .await
            .unwrap()
    );
    assert_eq!(
        DeliveryStorePort::load(store.as_ref(), user, &token)
            .await
            .unwrap()
            .unwrap()
            .opaque_version,
        valid.opaque_version
    );
}
