use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use diesel::{
    sql_query,
    sql_types::{Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    TenantContext, TenantId, UserId,
    ports::{
        AdminUserUpdate, FederationLogin, NewFederatedIdentity, NewFederationLink, RepositoryError,
    },
    scim::NormalizedScimUser,
};
use nazo_postgres::{
    FederationRepository, MfaRepository, PasskeyRepository, ScimRepository, UserRepository,
    create_pool, get_conn,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn repositories_accept_validated_tenant_and_user_ids() {
    fn assert_user_repository(_: &UserRepository) {}
    fn assert_mfa_repository(_: &MfaRepository) {}

    let _tenant = TenantContext::default_system();
    let _user = UserId::new(Uuid::now_v7()).expect("generated ID is non-nil");
    let _ = (assert_user_repository, assert_mfa_repository);
}

async fn database_fixture() -> Option<(nazo_postgres::DbPool, TenantContext, UserId)> {
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
    let user_id = UserId::new(Uuid::now_v7()).expect("generated ID is non-nil");
    let token = Uuid::now_v7().simple().to_string();
    let mut connection = get_conn(&pool).await.expect("test database is reachable");
    sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
        .bind::<SqlUuid, _>(user_id.as_uuid()).bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.realm_id.as_uuid()).bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
        .bind::<Text, _>(format!("postgres-{token}")).bind::<Text, _>(format!("postgres-{token}@example.test"))
        .execute(&mut connection).await.expect("fixture user can be inserted");
    drop(connection);
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

#[tokio::test]
async fn user_lookup_is_tenant_scoped() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let repository = UserRepository::new(pool.clone());
    assert!(
        repository
            .principal_by_id(tenant, user_id)
            .await
            .expect("lookup succeeds")
            .is_some()
    );
    let other_tenant = TenantContext {
        tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
        ..tenant
    };
    assert!(
        repository
            .principal_by_id(other_tenant, user_id)
            .await
            .expect("lookup succeeds")
            .is_none()
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn totp_last_step_compare_and_set_has_one_concurrent_winner() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO user_totp_credentials (tenant_id,user_id,secret_base32,label,confirmed_at) VALUES ($1,$2,'JBSWY3DPEHPK3PXP','test',CURRENT_TIMESTAMP)").bind::<SqlUuid,_>(tenant.tenant_id.as_uuid()).bind::<SqlUuid,_>(user_id.as_uuid()).execute(&mut connection).await.unwrap();
    drop(connection);
    let repository = MfaRepository::new(pool.clone());
    let (left, right) = tokio::join!(
        repository.compare_and_set_totp_step(tenant.tenant_id, user_id, 42),
        repository.compare_and_set_totp_step(tenant.tenant_id, user_id, 42)
    );
    assert_ne!(left.unwrap(), right.unwrap());
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn backup_code_is_consumed_once_atomically() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let code = "ABCD-EFGH";
    let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
    let hash = Argon2::default()
        .hash_password(code.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let repository = MfaRepository::new(pool.clone());
    repository
        .replace_backup_code_hashes(tenant.tenant_id, user_id, vec![hash])
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        repository.consume_backup_code(tenant.tenant_id, user_id, code),
        repository.consume_backup_code(tenant.tenant_id, user_id, code)
    );
    assert_ne!(left.unwrap(), right.unwrap());
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn passkey_and_federation_uniqueness_are_typed_conflicts() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let passkeys = PasskeyRepository::new(pool.clone());
    passkeys
        .insert(
            tenant.tenant_id,
            user_id,
            "credential".into(),
            json!({}),
            "test".into(),
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        passkeys
            .insert(
                tenant.tenant_id,
                user_id,
                "credential".into(),
                json!({}),
                "test".into(),
                0
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    let federation = FederationRepository::new(pool.clone());
    let new_link = NewFederationLink {
        tenant_id: tenant.tenant_id,
        user_id,
        provider_type: "oidc".into(),
        provider_id: "provider".into(),
        subject: "subject".into(),
        email: "a@example.test".into(),
        claims: json!({}),
    };
    federation.insert(new_link.clone()).await.unwrap();
    assert_eq!(
        federation.insert(new_link).await.unwrap_err(),
        RepositoryError::Conflict
    );
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn passkey_counter_update_is_monotonic_compare_and_set() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = PasskeyRepository::new(pool.clone());
    repository
        .insert(
            tenant.tenant_id,
            user_id,
            "counter-cas".into(),
            json!({"counter": 0}),
            "counter test".into(),
            0,
        )
        .await
        .unwrap();

    let (left, right) = tokio::join!(
        repository.update_counter(
            tenant.tenant_id,
            user_id,
            "counter-cas",
            0,
            1,
            json!({"counter": 1})
        ),
        repository.update_counter(
            tenant.tenant_id,
            user_id,
            "counter-cas",
            0,
            1,
            json!({"counter": 1})
        )
    );
    assert!(matches!(
        (&left, &right),
        (Ok(()), Err(RepositoryError::Conflict)) | (Err(RepositoryError::Conflict), Ok(()))
    ));
    assert_eq!(
        repository
            .update_counter(
                tenant.tenant_id,
                user_id,
                "counter-cas",
                0,
                2,
                json!({"counter": 2})
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    assert_eq!(
        repository
            .update_counter(
                tenant.tenant_id,
                user_id,
                "counter-cas",
                1,
                1,
                json!({"counter": 1})
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );

    repository
        .insert(
            tenant.tenant_id,
            user_id,
            "zero-counter".into(),
            json!({"counter": 0}),
            "zero counter".into(),
            0,
        )
        .await
        .unwrap();
    repository
        .update_counter(
            tenant.tenant_id,
            user_id,
            "zero-counter",
            0,
            0,
            json!({"counter": 0}),
        )
        .await
        .unwrap();
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn concurrent_federated_create_is_idempotent_and_tenant_scoped() {
    let Some((pool, tenant, fixture_user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = FederationRepository::new(pool.clone());
    let suffix = Uuid::now_v7();
    let login = FederationLogin {
        tenant,
        provider_type: "oidc".into(),
        provider_id: format!("provider-{suffix}"),
        subject: format!("subject-{suffix}"),
        email: Some(format!("federated-{suffix}@example.test")),
        claims: json!({"sub": format!("subject-{suffix}")}),
    };
    let new_identity = NewFederatedIdentity {
        login: login.clone(),
        email: login.email.clone().unwrap(),
        display_name: Some("Concurrent Federation".into()),
        password_hash: nazo_identity::PasswordHash::new("test-only-bootstrap-hash").unwrap(),
    };

    let (left, right) = tokio::join!(
        repository.create_federated(new_identity.clone()),
        repository.create_federated(new_identity)
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.user_id(), right.user_id());

    let other_tenant = TenantContext {
        tenant_id: TenantId::new(Uuid::now_v7()).unwrap(),
        ..tenant
    };
    assert!(
        repository
            .resolve_existing(FederationLogin {
                tenant: other_tenant,
                ..login
            })
            .await
            .unwrap()
            .is_none()
    );
    cleanup(&pool, left.user_id()).await;
    cleanup(&pool, fixture_user_id).await;
}

#[tokio::test]
async fn subject_claims_reject_invalid_persisted_role_invariant() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role = 'admin', admin_level = 0 WHERE id = $1")
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let error = UserRepository::new(pool.clone())
        .subject_claims_by_id(tenant, user_id)
        .await
        .unwrap_err();
    assert!(matches!(error, RepositoryError::Consistency(_)));
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn mfa_backup_code_bounds_and_enrollment_conflict_are_explicit() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = MfaRepository::new(pool.clone());
    assert_eq!(
        repository
            .replace_backup_code_hashes(
                tenant.tenant_id,
                user_id,
                (0..=nazo_identity::mfa::MFA_BACKUP_CODE_COUNT)
                    .map(|index| format!("hash-{index}"))
                    .collect(),
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );

    let mut connection = get_conn(&pool).await.unwrap();
    for index in 0..=nazo_identity::mfa::MFA_BACKUP_CODE_COUNT {
        sql_query(
            "INSERT INTO user_mfa_backup_codes (tenant_id,user_id,code_hash) VALUES ($1,$2,$3)",
        )
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .bind::<Text, _>(format!("invalid-hash-{index}"))
        .execute(&mut connection)
        .await
        .unwrap();
    }
    drop(connection);
    assert!(matches!(
        repository
            .consume_backup_code(tenant.tenant_id, user_id, "candidate")
            .await,
        Err(RepositoryError::Consistency(_))
    ));

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM user_mfa_backup_codes WHERE tenant_id=$1 AND user_id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM user_totp_credentials WHERE tenant_id=$1 AND user_id=$2")
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(user_id.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let (left, right) = tokio::join!(
        repository.begin_totp_enrollment(
            tenant.tenant_id,
            user_id,
            "JBSWY3DPEHPK3PXP".into(),
            "first".into()
        ),
        repository.begin_totp_enrollment(
            tenant.tenant_id,
            user_id,
            "GEZDGNBVGY3TQOJQ".into(),
            "second".into()
        )
    );
    assert!(
        left.is_ok() || right.is_ok(),
        "left={left:?}, right={right:?}"
    );
    assert!(matches!(left, Ok(()) | Err(RepositoryError::Conflict)));
    assert!(matches!(right, Ok(()) | Err(RepositoryError::Conflict)));
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn scim_replace_returns_domain_claims_from_one_transaction() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        return;
    };
    let user = ScimRepository::new(pool.clone())
        .replace(
            tenant,
            user_id,
            NormalizedScimUser {
                user_name: "replacement".into(),
                email: "replacement@example.test".into(),
                active: false,
                display_name: Some("Replacement".into()),
                given_name: None,
                family_name: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(user.user_id(), user_id);
    assert_eq!(user.account.username, "replacement");
    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn admin_partial_update_validates_final_role_level_before_commit() {
    let Some((pool, tenant, user_id)) = database_fixture().await else {
        panic!("NAZO_TEST_DATABASE_URL or DATABASE_URL is required");
    };
    let repository = UserRepository::new(pool.clone());

    assert_eq!(
        repository
            .admin_update(
                user_id,
                AdminUserUpdate {
                    role: Some("admin".into()),
                    admin_level: None,
                    active: None,
                },
            )
            .await
            .unwrap_err(),
        RepositoryError::Conflict
    );
    let unchanged = repository
        .public_account_by_id(tenant.tenant_id, user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.role_name(), "user");
    assert_eq!(unchanged.admin_level(), 0);

    let promoted = repository
        .admin_update(
            user_id,
            AdminUserUpdate {
                role: Some("admin".into()),
                admin_level: Some(5),
                active: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(promoted.role_name(), "admin");
    assert_eq!(promoted.admin_level(), 5);

    let level_only = repository
        .admin_update(
            user_id,
            AdminUserUpdate {
                role: None,
                admin_level: Some(7),
                active: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(level_only.role_name(), "admin");
    assert_eq!(level_only.admin_level(), 7);
    cleanup(&pool, user_id).await;
}

#[test]
fn server_mfa_verification_does_not_query_migrated_tables_directly() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../server/src/support/mfa.rs"
    ))
    .expect("server MFA support source is readable");
    assert!(!source.contains("user_totp_credentials"));
    assert!(!source.contains("user_mfa_backup_codes"));
}

#[test]
fn server_has_no_identity_rows_or_identity_diesel_queries() {
    const FORBIDDEN: &[&str] = &[
        "UserRow",
        "PasskeyCredentialRow",
        "ExternalIdentityLinkRow",
        "TotpCredentialRow",
        "users::",
        "user_totp_credentials::",
        "user_mfa_backup_codes::",
        "user_mfa_remembered_devices::",
        "user_passkey_credentials::",
        "external_identity_links::",
        "users (id) {",
        "user_totp_credentials (id) {",
        "user_mfa_backup_codes (id) {",
        "user_mfa_remembered_devices (id) {",
        "user_passkey_credentials (id) {",
        "external_identity_links (id) {",
    ];

    fn visit(path: &std::path::Path, violations: &mut Vec<String>) {
        for entry in std::fs::read_dir(path).expect("server source directory is readable") {
            let entry = entry.expect("server source entry is readable");
            let path = entry.path();
            if path.is_dir() {
                visit(&path, violations);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).expect("server source is UTF-8");
                for forbidden in FORBIDDEN {
                    let module_reexport = *forbidden == "users::"
                        && source.lines().any(|line| {
                            line.trim() == "pub(crate) use users::*;"
                                && source.matches(forbidden).count() == 1
                        });
                    if source.contains(forbidden) && !module_reexport {
                        violations.push(format!("{} contains {forbidden}", path.display()));
                    }
                }
            }
        }
    }

    let mut violations = Vec::new();
    visit(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../server/src"),
        &mut violations,
    );
    assert!(
        violations.is_empty(),
        "server identity persistence leaked outside nazo-postgres:\n{}",
        violations.join("\n")
    );
}
