use diesel::{
    sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_auth::{PreparedClientRegistration, ValidatedClientRegistration};
use nazo_identity::{
    AccessRequestStatus, NewAccessRequest, TenantContext, TenantId, UserId, ports::RepositoryError,
};
use nazo_postgres::{AccessRequestRepository, OAuthClientRepository, create_pool, get_conn};
use uuid::Uuid;

async fn fixture() -> Option<(nazo_postgres::DbPool, TenantContext, UserId)> {
    let database_url =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(database_url) => database_url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!("CI requires NAZO_TEST_DATABASE_URL or DATABASE_URL")
            }
            Err(_) => return None,
        };
    let pool = create_pool(database_url, 8).expect("test pool can be built");
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::now_v7()).unwrap();
    let token = Uuid::now_v7().simple().to_string();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
        .bind::<Text, _>(format!("access-{token}"))
        .bind::<Text, _>(format!("access-{token}@example.test"))
        .execute(&mut connection)
        .await
        .unwrap();
    Some((pool, tenant, user_id))
}

async fn cleanup(pool: &nazo_postgres::DbPool, user_id: UserId) {
    if let Ok(mut connection) = get_conn(pool).await {
        let _ = sql_query("DELETE FROM users WHERE id = $1")
            .bind::<SqlUuid, _>(user_id.as_uuid())
            .execute(&mut connection)
            .await;
    }
}

fn new_request(tenant: TenantContext, user_id: UserId, suffix: &str) -> NewAccessRequest {
    NewAccessRequest {
        tenant_id: tenant.tenant_id,
        user_id,
        site_name: format!("Access {suffix}"),
        site_url: format!("https://{suffix}.example.test"),
        request_description: "integration test".to_owned(),
    }
}

fn client(suffix: &str) -> ValidatedClientRegistration {
    ValidatedClientRegistration {
        client_id: format!("access-client-{suffix}"),
        client_name: format!("Access Client {suffix}"),
        client_type: "public".to_owned(),
        redirect_uris: vec!["https://client.example.test/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: Vec::new(),
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "none".to_owned(),
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
        backchannel_user_code_parameter: false,
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
    }
}

fn prepared_client(
    tenant: TenantContext,
    registration: ValidatedClientRegistration,
    require_mtls_bound_tokens: bool,
) -> PreparedClientRegistration {
    PreparedClientRegistration {
        tenant,
        registration,
        require_mtls_bound_tokens,
        issued_secret: None.into(),
        client_secret_hash: None,
        registration_access_token_blake3: None,
    }
}

#[tokio::test]
async fn create_list_cancel_and_detail_are_tenant_and_owner_scoped() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let created = repository
        .create(new_request(
            tenant,
            user_id,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(
        repository
            .list_for_user(tenant.tenant_id, user_id)
            .await
            .unwrap()
            .iter()
            .filter(|request| request.id == created.id)
            .count(),
        1
    );
    let other_tenant = TenantId::new(Uuid::now_v7()).unwrap();
    assert!(
        repository
            .by_id(other_tenant, created.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .list_for_user(other_tenant, user_id)
            .await
            .unwrap()
            .is_empty()
    );
    repository
        .cancel_pending(tenant.tenant_id, user_id, created.id)
        .await
        .unwrap();
    assert!(
        repository
            .by_id(tenant.tenant_id, created.id)
            .await
            .unwrap()
            .is_none()
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn create_rejects_user_from_a_different_tenant() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let other_tenant = TenantId::new(Uuid::now_v7()).unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind::<SqlUuid, _>(other_tenant.as_uuid())
        .bind::<Text, _>(format!("cross-tenant-{}", other_tenant.as_uuid().simple()))
        .bind::<Text, _>("Cross Tenant")
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let error = repository
        .create(NewAccessRequest {
            tenant_id: other_tenant,
            user_id,
            site_name: "Cross Tenant".to_owned(),
            site_url: "https://cross-tenant.example.test".to_owned(),
            request_description: "must be rejected".to_owned(),
        })
        .await
        .unwrap_err();

    assert_eq!(error, RepositoryError::NotFound);
    assert!(
        repository
            .list_for_user(other_tenant, user_id)
            .await
            .unwrap()
            .is_empty()
    );
    cleanup(&pool, user_id).await;
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(other_tenant.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    let _ = tenant;
}

#[tokio::test]
async fn concurrent_approval_has_one_cas_winner_and_rolls_back_losing_client() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let request = repository
        .create(new_request(
            tenant,
            user_id,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    let left_client = prepared_client(tenant, client(&Uuid::now_v7().simple().to_string()), false);
    let right_client = prepared_client(tenant, client(&Uuid::now_v7().simple().to_string()), false);
    let client_ids = [
        left_client.registration.client_id.clone(),
        right_client.registration.client_id.clone(),
    ];
    let (left, right) = tokio::join!(
        repository.approve(tenant, request.id, user_id, &left_client),
        repository.approve(tenant, request.id, user_id, &right_client)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(RepositoryError::AlreadyProcessed))
            || matches!(right, Err(RepositoryError::AlreadyProcessed))
    );
    let state = repository
        .by_id(tenant.tenant_id, request.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.status, AccessRequestStatus::Approved);
    let mut connection = get_conn(&pool).await.unwrap();
    let count = sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_clients WHERE client_id = $1 OR client_id = $2")
        .bind::<Text, _>(&client_ids[0])
        .bind::<Text, _>(&client_ids[1])
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap()
        .count;
    assert_eq!(
        count, 1,
        "losing approval transaction must roll back its client"
    );
    drop(connection);
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn approval_rejects_mismatched_actor_context() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let request = repository
        .create(new_request(
            tenant,
            user_id,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    let actor_error = repository
        .approve(
            tenant,
            request.id,
            UserId::new(Uuid::now_v7()).unwrap(),
            &prepared_client(tenant, client(&Uuid::now_v7().simple().to_string()), false),
        )
        .await
        .unwrap_err();

    assert!(matches!(actor_error, RepositoryError::Consistency(_)));
    assert_eq!(
        repository
            .by_id(tenant.tenant_id, request.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AccessRequestStatus::Pending
    );
    cleanup(&pool, user_id).await;
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[tokio::test]
async fn concurrent_rejection_has_one_cas_winner() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let request = repository
        .create(new_request(
            tenant,
            user_id,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        repository.reject(tenant.tenant_id, request.id, user_id, "left".to_owned()),
        repository.reject(tenant.tenant_id, request.id, user_id, "right".to_owned())
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(RepositoryError::Conflict))
            || matches!(right, Err(RepositoryError::Conflict))
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn duplicate_client_conflict_does_not_report_request_as_processed() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let first = repository
        .create(new_request(tenant, user_id, &format!("first-{suffix}")))
        .await
        .unwrap();
    let mut registration = client(&suffix);
    registration.jwks_uri = Some("https://client.example.test/jwks.json".to_owned());
    registration.jwks = Some(serde_json::json!({"keys": []}));
    registration.request_uris = vec!["https://client.example.test/request.jwt".to_owned()];
    registration.initiate_login_uri = Some("https://client.example.test/initiate".to_owned());
    registration.presentation = nazo_auth::ClientPresentationMetadata {
        logo_uri: Some("https://client.example.test/logo.png".to_owned()),
        policy_uri: Some("https://client.example.test/policy".to_owned()),
        tos_uri: Some("https://client.example.test/terms".to_owned()),
    };
    registration.security_policy = nazo_auth::ClientSecurityPolicy {
        session_management: true,
        ..nazo_auth::ClientSecurityPolicy::default()
    };
    let expected_registration = registration.clone();
    let prepared = prepared_client(tenant, registration, true);
    let approved = repository
        .approve(tenant, first.id, user_id, &prepared)
        .await
        .unwrap();
    let client_repository = OAuthClientRepository::new(pool.clone());
    let persisted = client_repository
        .by_id(tenant.tenant_id.as_uuid(), approved.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.client_id, approved.client_id);
    assert!(
        persisted.require_mtls_bound_tokens,
        "access-request approval must preserve the mTLS sender constraint"
    );
    assert_eq!(persisted.jwks_uri, expected_registration.jwks_uri);
    assert_eq!(persisted.request_uris, expected_registration.request_uris);
    assert_eq!(
        persisted.initiate_login_uri,
        expected_registration.initiate_login_uri
    );
    assert_eq!(
        persisted.presentation.logo_uri,
        expected_registration.presentation.logo_uri
    );
    assert_eq!(
        persisted.presentation.policy_uri,
        expected_registration.presentation.policy_uri
    );
    assert_eq!(
        persisted.presentation.tos_uri,
        expected_registration.presentation.tos_uri
    );
    assert!(
        persisted.security_policy.session_management,
        "access-request approval must preserve composable client security policy"
    );
    assert_eq!(
        client_repository
            .by_client_id(tenant.tenant_id.as_uuid(), &approved.client_id)
            .await
            .unwrap()
            .unwrap()
            .id,
        approved.id
    );
    assert!(
        repository
            .approved_delivery_matches(
                tenant.tenant_id,
                user_id,
                first.id,
                approved.id,
                &approved.client_id,
                None,
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .approved_delivery_matches(
                tenant.tenant_id,
                user_id,
                first.id,
                approved.id,
                "wrong-client-id",
                None,
            )
            .await
            .unwrap()
    );
    let second = repository
        .create(new_request(tenant, user_id, &format!("second-{suffix}")))
        .await
        .unwrap();

    let error = repository
        .approve(tenant, second.id, user_id, &prepared)
        .await
        .unwrap_err();

    assert_eq!(error, RepositoryError::Conflict);
    assert_eq!(
        repository
            .by_id(tenant.tenant_id, second.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AccessRequestStatus::Pending
    );
    cleanup(&pool, user_id).await;
}

// ---------------------------------------------------------------------------
// SELECT EXISTS (DB-010 / EXS-03, EXS-04) matrix coverage.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approved_delivery_matches_requires_every_predicate_to_hold() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let request = repository
        .create(new_request(tenant, user_id, &format!("exists-{suffix}")))
        .await
        .unwrap();
    let approved = repository
        .approve(
            tenant,
            request.id,
            user_id,
            &prepared_client(tenant, client(&suffix), false),
        )
        .await
        .unwrap();

    // Every predicate holds.
    assert!(
        repository
            .approved_delivery_matches(
                tenant.tenant_id,
                user_id,
                request.id,
                approved.id,
                &approved.client_id,
                None,
            )
            .await
            .unwrap(),
        "an approved request with matching bindings must exist"
    );

    // Flipping each predicate individually must turn the check off.
    let pending = repository
        .create(new_request(tenant, user_id, &format!("pending-{suffix}")))
        .await
        .unwrap();
    assert!(
        !repository
            .approved_delivery_matches(
                tenant.tenant_id,
                user_id,
                pending.id,
                approved.id,
                &approved.client_id,
                None,
            )
            .await
            .unwrap(),
        "a pending request is not an approved delivery"
    );
    for (label, flipped_tenant, flipped_user, flipped_request, flipped_approved, flipped_client) in [
        (
            "wrong user",
            tenant.tenant_id,
            UserId::new(Uuid::now_v7()).unwrap(),
            request.id,
            approved.id,
            approved.client_id.as_str(),
        ),
        (
            "wrong tenant",
            TenantId::new(Uuid::now_v7()).unwrap(),
            user_id,
            request.id,
            approved.id,
            approved.client_id.as_str(),
        ),
        (
            "unknown request id",
            tenant.tenant_id,
            user_id,
            Uuid::now_v7(),
            approved.id,
            approved.client_id.as_str(),
        ),
        (
            "mismatched approved client id",
            tenant.tenant_id,
            user_id,
            request.id,
            Uuid::now_v7(),
            approved.client_id.as_str(),
        ),
        (
            "wrong public client id",
            tenant.tenant_id,
            user_id,
            request.id,
            approved.id,
            "wrong-public-client-id",
        ),
    ] {
        assert!(
            !repository
                .approved_delivery_matches(
                    flipped_tenant,
                    flipped_user,
                    flipped_request,
                    flipped_approved,
                    flipped_client,
                    None,
                )
                .await
                .unwrap(),
            "{label} must not match the approved delivery"
        );
    }

    // An approved-but-deactivated client is not a delivery target.
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE oauth_clients SET is_active = FALSE WHERE id = $1")
        .bind::<SqlUuid, _>(approved.id)
        .execute(&mut connection)
        .await
        .unwrap();
    assert!(
        !repository
            .approved_delivery_matches(
                tenant.tenant_id,
                user_id,
                request.id,
                approved.id,
                &approved.client_id,
                None,
            )
            .await
            .unwrap(),
        "an inactive client must not satisfy the approved delivery"
    );
    drop(connection);
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn existence_predicates_return_booleans_while_page_keeps_count_semantics() {
    let Some((pool, tenant, user_id)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let request = repository
        .create(new_request(tenant, user_id, &format!("bool-{suffix}")))
        .await
        .unwrap();
    let approved = repository
        .approve(
            tenant,
            request.id,
            user_id,
            &prepared_client(tenant, client(&suffix), false),
        )
        .await
        .unwrap();

    // The existence predicate returns a plain boolean, not a count.
    let exists: bool = repository
        .approved_delivery_matches(
            tenant.tenant_id,
            user_id,
            request.id,
            approved.id,
            &approved.client_id,
            None,
        )
        .await
        .unwrap();
    assert!(exists);

    // An unrelated count query keeps count semantics: three requests for this
    // user must report total == 3, never a clamped 0/1.  Only one request per
    // user may stay pending (ux_client_access_requests_user_pending), so the
    // first two are resolved before the next is created.
    let first_extra = repository
        .create(new_request(tenant, user_id, &format!("count-0-{suffix}")))
        .await
        .unwrap();
    repository
        .reject(tenant.tenant_id, first_extra.id, user_id, "done".to_owned())
        .await
        .unwrap();
    let second_extra = repository
        .create(new_request(tenant, user_id, &format!("count-1-{suffix}")))
        .await
        .unwrap();
    repository
        .reject(
            tenant.tenant_id,
            second_extra.id,
            user_id,
            "done".to_owned(),
        )
        .await
        .unwrap();
    repository
        .create(new_request(tenant, user_id, &format!("count-2-{suffix}")))
        .await
        .unwrap();
    // The search term is this test's unique suffix so the count is scoped to
    // this test's rows even on a shared tenant.
    let scoped = repository
        .page(tenant.tenant_id, 10, 0, Some(&suffix), None)
        .await
        .unwrap();
    let total: i64 = scoped.total;
    assert_eq!(total, 4, "a count query must keep real counts, got {total}");
    assert_eq!(scoped.items.len(), 4);
    let pending = repository
        .page(
            tenant.tenant_id,
            10,
            0,
            Some(&suffix),
            Some(AccessRequestStatus::Pending),
        )
        .await
        .unwrap();
    assert_eq!(pending.total, 1, "only the newest request stays pending");
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn delivery_binding_requires_the_exact_approved_secret_generation() {
    let Some((pool, tenant, user)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().to_string();
    let request = repository
        .create(new_request(tenant, user, &suffix))
        .await
        .unwrap();
    let mut prepared = prepared_client(tenant, client(&suffix), false);
    prepared.registration.client_type = "confidential".to_owned();
    prepared.registration.token_endpoint_auth_method = "client_secret_post".to_owned();
    prepared.client_secret_hash = Some("client-secret-v1:attempt-salt:attempt-digest".to_owned());
    let approved = repository
        .approve(tenant, request.id, user, &prepared)
        .await
        .unwrap();
    for binding in [None, Some("client-secret-v1:other-salt:other-digest")] {
        assert!(
            !repository
                .approved_delivery_matches(
                    tenant.tenant_id,
                    user,
                    request.id,
                    approved.id,
                    &approved.client_id,
                    binding
                )
                .await
                .unwrap()
        );
    }
    assert!(
        nazo_persistence::AdminAccessRequestStore::approved_delivery_matches(
            &repository,
            tenant.tenant_id,
            user,
            request.id,
            approved.id,
            &approved.client_id,
            prepared.client_secret_hash.as_deref()
        )
        .await
        .unwrap()
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE oauth_clients SET client_secret_hash=$1 WHERE id=$2")
        .bind::<Text, _>("client-secret-v1:rotated-salt:rotated-digest")
        .bind::<SqlUuid, _>(approved.id)
        .execute(&mut connection)
        .await
        .unwrap();
    assert!(
        !repository
            .approved_delivery_matches(
                tenant.tenant_id,
                user,
                request.id,
                approved.id,
                &approved.client_id,
                prepared.client_secret_hash.as_deref()
            )
            .await
            .unwrap()
    );
    cleanup(&pool, user).await;
}

#[tokio::test]
async fn decision_write_ports_return_acknowledged_views_without_a_display_reread() {
    let Some((pool, tenant, user)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let pending = repository
        .create(new_request(tenant, user, &suffix))
        .await
        .unwrap();
    let prepared = prepared_client(tenant, client(&suffix), false);
    let approved = nazo_persistence::AdminAccessRequestStore::approve(
        &repository,
        tenant,
        pending.id,
        user,
        &prepared,
    )
    .await
    .unwrap();
    assert_eq!(approved.request.id, pending.id);
    assert_eq!(approved.request.status, AccessRequestStatus::Approved);
    assert_eq!(
        approved.request.approved_client_id,
        Some(approved.client.id)
    );
    assert_eq!(approved.request.created_at, pending.created_at);
    assert!(approved.request.resolved_at.is_some());
    assert!(approved.request.requester_email.is_some());
    assert_eq!(
        approved.request,
        repository
            .by_id(tenant.tenant_id, pending.id)
            .await
            .unwrap()
            .unwrap()
    );

    let to_reject = repository
        .create(new_request(tenant, user, &format!("rejected-{suffix}")))
        .await
        .unwrap();
    let rejected = nazo_persistence::AdminAccessRequestStore::reject(
        &repository,
        tenant.tenant_id,
        to_reject.id,
        user,
        "reviewed rejection".to_owned(),
    )
    .await
    .unwrap();
    assert_eq!(rejected.status, AccessRequestStatus::Rejected);
    assert_eq!(rejected.created_at, to_reject.created_at);
    assert!(rejected.resolved_at.is_some());
    assert_eq!(rejected.admin_note.as_deref(), Some("reviewed rejection"));
    assert_eq!(
        rejected,
        repository
            .by_id(tenant.tenant_id, to_reject.id)
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        nazo_persistence::AdminAccessRequestStore::reject(
            &repository,
            tenant.tenant_id,
            to_reject.id,
            user,
            "another attempt".to_owned(),
        )
        .await
        .unwrap_err(),
        RepositoryError::Conflict
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE client_access_requests SET admin_note = 'later metadata' WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(to_reject.id)
        .execute(&mut connection).await.unwrap();
    assert_eq!(rejected.admin_note.as_deref(), Some("reviewed rejection"));
    assert_eq!(approved.request.status, AccessRequestStatus::Approved);
    assert_eq!(
        sql_query("DELETE FROM client_access_requests WHERE tenant_id=$1 AND id=$2 AND user_id=$3 AND approved_client_id=$4")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid, _>(pending.id)
            .bind::<SqlUuid, _>(user.as_uuid())
            .bind::<SqlUuid, _>(approved.client.id)
            .execute(&mut connection)
            .await
            .expect("exact approved fixture request must be removed before its client"),
        1,
    );
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(approved.client.id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    cleanup(&pool, user).await;
}

#[tokio::test]
async fn metadata_patch_rejects_stale_semantic_snapshot_and_preserves_unrelated_updates() {
    let Some((pool, tenant, user)) = fixture().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let repository = OAuthClientRepository::new(pool.clone());
    let initial = nazo_auth::OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: tenant.tenant_id.as_uuid(),
        realm_id: tenant.realm_id.as_uuid(),
        organization_id: tenant.organization_id.as_uuid(),
        registration: client(&suffix),
        require_mtls_bound_tokens: false,
        is_active: true,
    };
    let expected = repository.insert(&initial, None, None).await.unwrap();
    let mut name_patch = expected.clone();
    name_patch.client_name = "updated during sector lookup".to_owned();
    let mut stale_redirect_patch = expected.clone();
    stale_redirect_patch
        .redirect_uris
        .push("https://client.example.test/another-callback".to_owned());
    let changed = repository
        .update_metadata_if_current(&expected, &name_patch)
        .await
        .unwrap();
    assert_eq!(
        repository
            .update_metadata_if_current(&expected, &stale_redirect_patch)
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    let still_current = repository
        .by_id(tenant.tenant_id.as_uuid(), initial.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_current, changed);
    assert_eq!(still_current.redirect_uris, expected.redirect_uris);

    let mut retried = still_current.clone();
    retried
        .redirect_uris
        .push("https://client.example.test/another-callback".to_owned());
    let completed = repository
        .update_metadata_if_current(&still_current, &retried)
        .await
        .unwrap();
    assert_eq!(completed.client_name, name_patch.client_name);
    assert_eq!(completed.redirect_uris, retried.redirect_uris);
    let mut cross_identity = retried.clone();
    cross_identity.tenant_id = Uuid::now_v7();
    assert!(matches!(
        repository
            .update_metadata_if_current(&completed, &cross_identity)
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    assert_eq!(
        repository
            .by_id(tenant.tenant_id.as_uuid(), initial.id)
            .await
            .unwrap()
            .unwrap(),
        completed
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(initial.id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    cleanup(&pool, user).await;
}

async fn required_access_outcomes(
    pool: &nazo_postgres::DbPool,
    tenant: TenantContext,
    request: Uuid,
) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Events {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut connection = get_conn(pool).await.unwrap();
    sql_query("SELECT COALESCE(jsonb_agg(payload ORDER BY event_id),'[]'::jsonb) AS value FROM security_audit_events WHERE event_type IN ('client_created','admin_access_request_rejected') AND payload->>'tenant_id'=$1 AND payload->>'request_id'=$2")
        .bind::<Text, _>(tenant.tenant_id.as_uuid().to_string())
        .bind::<Text, _>(request.to_string()).get_result::<Events>(&mut connection).await.unwrap().value
}

#[tokio::test]
async fn required_approval_rolls_back_client_and_decision_and_recovers_only_exact_audit_binding() {
    use diesel_async::SimpleAsyncConnection;
    use futures_util::FutureExt as _;
    let Some((pool, tenant, actor)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let request = repository
        .create(new_request(tenant, actor, &suffix))
        .await
        .unwrap();
    let prepared = prepared_client(tenant, client(&suffix), false);
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role='admin',admin_level=10 WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(actor.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    let name = format!("access_audit_failure_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture required approval failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type='client_created' AND NEW.payload->>'request_id'='{}') EXECUTE FUNCTION {name}();", request.id)).await.unwrap();
    let body = std::panic::AssertUnwindSafe(async {
        assert!(repository.approve_with_required_audit(tenant, request.id, actor, &prepared, "fixture-source-hash".to_owned()).await.is_err());
        assert_eq!(repository.by_id(tenant.tenant_id, request.id).await.unwrap().unwrap().status, AccessRequestStatus::Pending);
        let count = sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_clients WHERE tenant_id=$1 AND client_id=$2")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid()).bind::<Text, _>(&prepared.client_id)
            .get_result::<CountRow>(&mut connection).await.unwrap().count;
        assert_eq!(count, 0, "canonical audit failure rolls back inserted client");
        assert_eq!(required_access_outcomes(&pool, tenant, request.id).await, serde_json::json!([]));
    }).catch_unwind().await;
    let trigger_cleanup = connection
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();"
        ))
        .await;
    if let Err(error) = body {
        drop(connection);
        cleanup(&pool, actor).await;
        std::panic::resume_unwind(error);
    }
    trigger_cleanup.unwrap();
    // A concurrently demoted actor cannot create a client from old admission.
    sql_query("UPDATE users SET role='user',admin_level=0 WHERE id=$1")
        .bind::<SqlUuid, _>(actor.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    assert!(
        repository
            .approve_with_required_audit(
                tenant,
                request.id,
                actor,
                &prepared,
                "fixture-source-hash".to_owned()
            )
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .by_id(tenant.tenant_id, request.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        AccessRequestStatus::Pending
    );
    assert_eq!(
        required_access_outcomes(&pool, tenant, request.id).await,
        serde_json::json!([])
    );
    sql_query("UPDATE users SET role='admin',admin_level=10 WHERE id=$1")
        .bind::<SqlUuid, _>(actor.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let approved = repository
        .approve_with_required_audit(
            tenant,
            request.id,
            actor,
            &prepared,
            "fixture-source-hash".to_owned(),
        )
        .await
        .unwrap();
    let events = required_access_outcomes(&pool, tenant, request.id).await;
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(
        events[0]["approved_client_id"],
        serde_json::json!(approved.client.id)
    );
    assert_eq!(
        events[0]["request_user_id"],
        serde_json::json!(actor.as_uuid())
    );
    assert_eq!(
        events[0]["admin_user_id"],
        serde_json::json!(actor.as_uuid())
    );
    assert_eq!(events[0]["source_ip_hash"], "fixture-source-hash");
    assert!(events[0].get("client_secret").is_none());
    assert!(events[0].get("client_secret_hash").is_none());
    assert!(
        repository
            .approved_delivery_with_required_audit_matches(
                tenant.tenant_id,
                actor,
                request.id,
                approved.client.id,
                &approved.client.client_id,
                None
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .approved_delivery_with_required_audit_matches(
                TenantId::new(Uuid::now_v7()).unwrap(),
                actor,
                request.id,
                approved.client.id,
                &approved.client.client_id,
                None
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .approved_delivery_with_required_audit_matches(
                tenant.tenant_id,
                UserId::new(Uuid::now_v7()).unwrap(),
                request.id,
                approved.client.id,
                &approved.client.client_id,
                None
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .approved_delivery_with_required_audit_matches(
                tenant.tenant_id,
                actor,
                Uuid::now_v7(),
                approved.client.id,
                &approved.client.client_id,
                None
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .approved_delivery_with_required_audit_matches(
                tenant.tenant_id,
                actor,
                request.id,
                approved.client.id,
                "wrong-public-client",
                None
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .approved_delivery_with_required_audit_matches(
                tenant.tenant_id,
                actor,
                request.id,
                Uuid::now_v7(),
                &approved.client.client_id,
                None
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .approved_delivery_with_required_audit_matches(
                tenant.tenant_id,
                actor,
                request.id,
                approved.client.id,
                &approved.client.client_id,
                Some("wrong-generation")
            )
            .await
            .unwrap()
    );
    assert_eq!(
        repository
            .approve_with_required_audit(
                tenant,
                request.id,
                actor,
                &prepared,
                "fixture-source-hash".to_owned()
            )
            .await
            .unwrap_err(),
        RepositoryError::AlreadyProcessed
    );
    assert_eq!(
        required_access_outcomes(&pool, tenant, request.id).await,
        events
    );

    // Confirm the narrow capability works with the actual configured runtime
    // privileges while canonical audit-table SELECT stays forbidden.
    #[derive(diesel::QueryableByName)]
    struct RuntimeEvidence {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        matched: bool,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        may_read_audit: bool,
    }
    let role = format!("access_runtime_{}", Uuid::now_v7().simple());
    let mut connection = get_conn(&pool).await.unwrap();
    connection
        .batch_execute(&format!("CREATE ROLE {role} NOLOGIN"))
        .await
        .unwrap();
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap();
    let runtime_body = std::panic::AssertUnwindSafe(async {
        nazo_postgres::configure_runtime_role(&database_url, &role).await.unwrap();
        connection.batch_execute(&format!("SET ROLE {role}")).await.unwrap();
        let result = sql_query("SELECT public.nazo_access_request_required_approval_matches($1,$2,$3,$4,$5,NULL) AS matched, has_table_privilege(current_user,'public.security_audit_events','SELECT') AS may_read_audit")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid()).bind::<SqlUuid, _>(actor.as_uuid())
            .bind::<SqlUuid, _>(request.id).bind::<SqlUuid, _>(approved.client.id)
            .bind::<Text, _>(&approved.client.client_id).get_result::<RuntimeEvidence>(&mut connection).await.unwrap();
        assert!(result.matched);
        assert!(!result.may_read_audit, "purpose capability must not grant audit-table reads");
    }).catch_unwind().await;
    let reset_result = connection.batch_execute("RESET ROLE").await;
    let role_cleanup_result = connection
        .batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role};"))
        .await;
    if let Err(error) = runtime_body {
        drop(connection);
        if let Ok(mut cleanup_connection) = get_conn(&pool).await {
            let _ = sql_query("DELETE FROM client_access_requests WHERE tenant_id=$1 AND id=$2")
                .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
                .bind::<SqlUuid, _>(request.id)
                .execute(&mut cleanup_connection)
                .await;
            let _ = sql_query("DELETE FROM oauth_clients WHERE tenant_id=$1 AND id=$2")
                .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
                .bind::<SqlUuid, _>(approved.client.id)
                .execute(&mut cleanup_connection)
                .await;
        }
        cleanup(&pool, actor).await;
        std::panic::resume_unwind(error);
    }
    reset_result.unwrap();
    role_cleanup_result.unwrap();
    sql_query("UPDATE client_access_requests SET required_approval_event_id=NULL WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid()).bind::<SqlUuid, _>(request.id).execute(&mut connection).await.unwrap();
    drop(connection);
    assert!(
        !repository
            .approved_delivery_with_required_audit_matches(
                tenant.tenant_id,
                actor,
                request.id,
                approved.client.id,
                &approved.client.client_id,
                None
            )
            .await
            .unwrap(),
        "an Approved row alone cannot recover a secret without its exact canonical outcome reference"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM client_access_requests WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(request.id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(approved.client.id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    cleanup(&pool, actor).await;
}

#[tokio::test]
async fn required_rejection_ledger_failure_rolls_back_decision_and_has_one_acknowledged_outcome() {
    use diesel_async::SimpleAsyncConnection;
    use futures_util::FutureExt as _;
    let Some((pool, tenant, actor)) = fixture().await else {
        return;
    };
    let repository = AccessRequestRepository::new(pool.clone());
    let request = repository
        .create(new_request(
            tenant,
            actor,
            &Uuid::now_v7().simple().to_string(),
        ))
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role='admin',admin_level=10 WHERE id=$1")
        .bind::<SqlUuid, _>(actor.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    let name = format!("access_reject_failure_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture required rejection failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type='admin_access_request_rejected' AND NEW.payload->>'request_id'='{}') EXECUTE FUNCTION {name}();", request.id)).await.unwrap();
    let body = std::panic::AssertUnwindSafe(async {
        assert!(
            repository
                .reject_with_required_audit(
                    tenant,
                    request.id,
                    actor,
                    "reviewed rejection".to_owned()
                )
                .await
                .is_err()
        );
        let actual = repository
            .by_id(tenant.tenant_id, request.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(actual.status, AccessRequestStatus::Pending);
        assert!(actual.admin_note.is_none() && actual.resolved_at.is_none());
        assert_eq!(
            required_access_outcomes(&pool, tenant, request.id).await,
            serde_json::json!([])
        );
    })
    .catch_unwind()
    .await;
    let trigger_cleanup = connection
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();"
        ))
        .await;
    drop(connection);
    if let Err(error) = body {
        cleanup(&pool, actor).await;
        std::panic::resume_unwind(error);
    }
    trigger_cleanup.unwrap();
    let rejected = repository
        .reject_with_required_audit(tenant, request.id, actor, "reviewed rejection".to_owned())
        .await
        .unwrap();
    assert_eq!(rejected.status, AccessRequestStatus::Rejected);
    assert_eq!(rejected.admin_note.as_deref(), Some("reviewed rejection"));
    assert_eq!(
        rejected,
        repository
            .by_id(tenant.tenant_id, request.id)
            .await
            .unwrap()
            .unwrap()
    );
    let events = required_access_outcomes(&pool, tenant, request.id).await;
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(
        events[0]["admin_user_id"],
        serde_json::json!(actor.as_uuid())
    );
    assert_eq!(
        repository
            .reject_with_required_audit(tenant, request.id, actor, "duplicate".to_owned())
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    assert_eq!(
        required_access_outcomes(&pool, tenant, request.id).await,
        events
    );
    cleanup(&pool, actor).await;
}

#[tokio::test]
async fn cancellation_discards_client_cas_and_access_rejection_connections_before_peer_lock_retry()
{
    use diesel_async::SimpleAsyncConnection;
    use futures_util::FutureExt as _;
    #[derive(diesel::QueryableByName)]
    struct Backend {
        #[diesel(sql_type = diesel::sql_types::Integer)]
        pid: i32,
    }
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        waiting: bool,
    }
    let Some((pool, tenant, actor)) = fixture().await else {
        return;
    };
    let requests = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let seed = requests
        .create(new_request(tenant, actor, &suffix))
        .await
        .unwrap();
    let prepared = prepared_client(tenant, client(&suffix), false);
    let client = requests
        .approve(tenant, seed.id, actor, &prepared)
        .await
        .unwrap();
    let pending = requests
        .create(new_request(tenant, actor, &format!("{suffix}-pending")))
        .await
        .unwrap();
    let clients = OAuthClientRepository::new(pool.clone());
    let original = clients
        .by_id(tenant.tenant_id.as_uuid(), client.id)
        .await
        .unwrap()
        .unwrap();
    let mut control = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role='admin',admin_level=10 WHERE id=$1")
        .bind::<SqlUuid, _>(actor.as_uuid())
        .execute(&mut control)
        .await
        .unwrap();
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap();
    for patch_client in [true, false] {
        let cancellation_pool = create_pool(database_url.clone(), 1).unwrap();
        let mut connection = get_conn(&cancellation_pool).await.unwrap();
        let pid = sql_query("SELECT pg_backend_pid() AS pid")
            .get_result::<Backend>(&mut connection)
            .await
            .unwrap()
            .pid;
        drop(connection);
        let gate = i64::from_be_bytes(Uuid::now_v7().as_bytes()[8..].try_into().unwrap());
        let name = format!("owner_cancel_{}", Uuid::now_v7().simple());
        let (table, condition) = if patch_client {
            ("oauth_clients", format!("NEW.id='{}'::uuid", client.id))
        } else {
            (
                "security_audit_events",
                format!(
                    "NEW.event_type='admin_access_request_rejected' AND NEW.payload->>'request_id'='{}'",
                    pending.id
                ),
            )
        };
        control.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_lock({gate}); RETURN NEW; END $$; CREATE TRIGGER {name} BEFORE {} ON {table} FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION {name}();", if patch_client { "UPDATE" } else { "INSERT" })).await.unwrap();
        control
            .batch_execute(&format!("SELECT pg_advisory_lock({gate})"))
            .await
            .unwrap();
        let expected = original.clone();
        let mut edited = expected.clone();
        edited.client_name = "must-not-commit-after-cancellation".to_owned();
        let worker_pool = cancellation_pool.clone();
        let pending_id = pending.id;
        let mut worker = tokio::spawn(async move {
            if patch_client {
                OAuthClientRepository::new(worker_pool)
                    .update_metadata_if_current(&expected, &edited)
                    .await
                    .map(|_| ())
            } else {
                AccessRequestRepository::new(worker_pool)
                    .reject_with_required_audit(
                        tenant,
                        pending_id,
                        actor,
                        "cancelled rejection".to_owned(),
                    )
                    .await
                    .map(|_| ())
            }
        });
        let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                control.batch_execute("SELECT pg_stat_clear_snapshot()").await?;
                let row = sql_query("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory') AS waiting")
                    .bind::<diesel::sql_types::Integer, _>(pid).get_result::<Waiting>(&mut control).await?;
                if row.waiting { return Ok::<(), diesel::result::Error>(()); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await;
        // Always stop the owner and release the fixture gate before asserting
        // observation, including timeout/query-error failures.
        worker.abort();
        let cancelled = (&mut worker).await;
        let unlock_result = control
            .batch_execute(&format!("SELECT pg_advisory_unlock({gate})"))
            .await;
        let body = std::panic::AssertUnwindSafe(async {
            observed
                .expect("owner must hold its real row lock while waiting at the fixture gate")
                .unwrap();
            assert!(cancelled.unwrap_err().is_cancelled());
            unlock_result.unwrap();
            // Do not check out cancellation_pool again: that would trigger
            // recycling and hide an idle transaction retained by the old code.
            let mut peer = get_conn(&pool).await.unwrap();
            peer.batch_execute("SET lock_timeout='2s'").await.unwrap();
            let query = if patch_client {
                "SELECT 1::bigint AS count FROM oauth_clients WHERE id=$1 FOR UPDATE"
            } else {
                "SELECT 1::bigint AS count FROM client_access_requests WHERE id=$1 FOR UPDATE"
            };
            let lock_rows = sql_query(query)
                .bind::<SqlUuid, _>(if patch_client { client.id } else { pending.id })
                .load::<CountRow>(&mut peer)
                .await
                .expect("independent backend must acquire the cancelled owner's row lock");
            assert_eq!(lock_rows.len(), 1);
            if !patch_client {
                assert_eq!(
                    sql_query("SELECT 1::bigint AS count FROM users WHERE id=$1 FOR UPDATE")
                        .bind::<SqlUuid, _>(actor.as_uuid())
                        .load::<CountRow>(&mut peer)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
            }
            peer.batch_execute("RESET lock_timeout").await.unwrap();
            drop(peer);
            assert_eq!(
                clients
                    .by_id(tenant.tenant_id.as_uuid(), client.id)
                    .await
                    .unwrap()
                    .unwrap(),
                original
            );
            assert_eq!(
                requests
                    .by_id(tenant.tenant_id, pending.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                AccessRequestStatus::Pending
            );
            assert_eq!(
                required_access_outcomes(&pool, tenant, pending.id).await,
                serde_json::json!([])
            );
        })
        .catch_unwind()
        .await;
        // Closing the old unguarded pool only after the failed peer-lock
        // assertion cannot turn that failure into a pass, but lets the fixture
        // remove its trigger without waiting on the reproduced retained lock.
        drop(cancellation_pool);
        let fixture_cleanup = control
            .batch_execute(&format!(
                "DROP TRIGGER {name} ON {table}; DROP FUNCTION {name}();"
            ))
            .await;
        if let Err(error) = body {
            let _ = sql_query("DELETE FROM client_access_requests WHERE tenant_id=$1 AND id=$2")
                .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
                .bind::<SqlUuid, _>(seed.id)
                .execute(&mut control)
                .await;
            let _ = sql_query("DELETE FROM oauth_clients WHERE tenant_id=$1 AND id=$2")
                .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
                .bind::<SqlUuid, _>(client.id)
                .execute(&mut control)
                .await;
            drop(control);
            cleanup(&pool, actor).await;
            std::panic::resume_unwind(error);
        }
        fixture_cleanup.unwrap();
    }
    sql_query("DELETE FROM client_access_requests WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(seed.id)
        .execute(&mut control)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut control)
        .await
        .unwrap();
    drop(control);
    cleanup(&pool, actor).await;
}

#[tokio::test]
async fn client_cas_commit_error_after_returning_never_returns_a_success_view() {
    use diesel_async::SimpleAsyncConnection;
    use futures_util::FutureExt as _;
    let Some((pool, tenant, actor)) = fixture().await else {
        return;
    };
    let requests = AccessRequestRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let request = requests
        .create(new_request(tenant, actor, &suffix))
        .await
        .unwrap();
    let prepared = prepared_client(tenant, client(&suffix), false);
    let client = requests
        .approve(tenant, request.id, actor, &prepared)
        .await
        .unwrap();
    let clients = OAuthClientRepository::new(pool.clone());
    let before = clients
        .by_id(tenant.tenant_id.as_uuid(), client.id)
        .await
        .unwrap()
        .unwrap();
    let mut after = before.clone();
    after.client_name = "commit-error-must-not-publish".to_owned();
    let mut control = get_conn(&pool).await.unwrap();
    let name = format!("client_commit_error_{}", Uuid::now_v7().simple());
    control.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture client commit failure after RETURNING'; END $$; CREATE CONSTRAINT TRIGGER {name} AFTER UPDATE ON oauth_clients DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.id='{}'::uuid) EXECUTE FUNCTION {name}();", client.id)).await.unwrap();
    let body = std::panic::AssertUnwindSafe(async {
        assert!(
            clients
                .update_metadata_if_current(&before, &after)
                .await
                .is_err(),
            "a received RETURNING row is not an affirmative transaction ACK"
        );
        assert_eq!(
            clients
                .by_id(tenant.tenant_id.as_uuid(), client.id)
                .await
                .unwrap()
                .unwrap(),
            before
        );
    })
    .catch_unwind()
    .await;
    let fixture_cleanup = control
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON oauth_clients; DROP FUNCTION {name}();"
        ))
        .await;
    if let Err(error) = body {
        let _ = sql_query("DELETE FROM client_access_requests WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid, _>(request.id)
            .execute(&mut control)
            .await;
        let _ = sql_query("DELETE FROM oauth_clients WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid, _>(client.id)
            .execute(&mut control)
            .await;
        drop(control);
        cleanup(&pool, actor).await;
        std::panic::resume_unwind(error);
    }
    fixture_cleanup.unwrap();
    sql_query("DELETE FROM client_access_requests WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(request.id)
        .execute(&mut control)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE tenant_id=$1 AND id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut control)
        .await
        .unwrap();
    drop(control);
    cleanup(&pool, actor).await;
}
