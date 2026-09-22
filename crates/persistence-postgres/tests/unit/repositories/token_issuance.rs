use super::*;
use nazo_auth::TokenIssuedAuditFields;

// Real PostgreSQL cursor/bind/transaction coverage. Session-local tables keep
// scale fixtures independent from all application and audit data.
#[tokio::test]
async fn owner_revocation_streams_large_sets_and_rolls_back_all_batches() {
    use diesel_async::SimpleAsyncConnection;
    let Some(url) = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
    else {
        assert!(std::env::var_os("CI").is_none(), "CI requires PostgreSQL");
        return;
    };
    let mut connection = diesel_async::AsyncPgConnection::establish(&url)
        .await
        .unwrap();
    connection
        .batch_execute(
            "CREATE TEMP TABLE oauth_token_issuances (
            tenant_id uuid, client_id uuid, user_id uuid,
            access_token_jti text, access_token_expires_at timestamptz);
         CREATE TEMP TABLE oauth_clients (id uuid, tenant_id uuid, client_id text);
         CREATE TEMP TABLE openid4vci_access_grants (
            tenant_id uuid, client_id text, subject_id uuid, token_id uuid,
            expires_at timestamptz, revoked_at timestamptz);
         CREATE TEMP TABLE access_token_revocations (
            id uuid, access_token_jti_blake3 text, client_id uuid, tenant_id uuid,
            revoked_at timestamptz, expires_at timestamptz,
            UNIQUE (tenant_id, access_token_jti_blake3));",
        )
        .await
        .unwrap();
    let tenant = Uuid::now_v7();
    let client = Uuid::now_v7();
    let user = Uuid::now_v7();
    #[derive(QueryableByName)]
    struct Count {
        #[diesel(sql_type = sql_types::BigInt)]
        count: i64,
    }
    for total in [0_i32, 1, 512, 513, 11_000, 100_000] {
        connection
            .batch_execute("TRUNCATE oauth_token_issuances, access_token_revocations")
            .await
            .unwrap();
        sql_query("INSERT INTO oauth_token_issuances SELECT $1, $2, $3, 'jti-' || n, CURRENT_TIMESTAMP + INTERVAL '1 hour' FROM generate_series(1, $4) n")
            .bind::<sql_types::Uuid, _>(tenant).bind::<sql_types::Uuid, _>(client)
            .bind::<sql_types::Uuid, _>(user).bind::<sql_types::Integer, _>(total)
            .execute(&mut connection).await.unwrap();
        let inserted = connection
            .transaction::<_, diesel::result::Error, _>(async |connection| {
                revoke_access_tokens_for_owner_on_connection(
                    connection,
                    tenant,
                    Some(client),
                    Some(user),
                )
                .await
            })
            .await
            .unwrap();
        assert_eq!(inserted, total as usize);
        let count = sql_query("SELECT count(*)::bigint AS count FROM access_token_revocations")
            .get_result::<Count>(&mut connection)
            .await
            .unwrap();
        assert_eq!(count.count, i64::from(total));
        let repeated = connection
            .transaction::<_, diesel::result::Error, _>(async |connection| {
                revoke_access_tokens_for_owner_on_connection(connection, tenant, Some(client), None)
                    .await
            })
            .await
            .unwrap();
        assert_eq!(repeated, 0);
    }

    connection
        .batch_execute("TRUNCATE oauth_token_issuances, access_token_revocations")
        .await
        .unwrap();
    sql_query("INSERT INTO oauth_clients VALUES ($1, $2, 'credential-client')")
        .bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Uuid, _>(tenant)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("INSERT INTO openid4vci_access_grants VALUES ($1, 'credential-client', $2, gen_random_uuid(), CURRENT_TIMESTAMP + INTERVAL '1 hour', NULL)")
        .bind::<sql_types::Uuid, _>(tenant).bind::<sql_types::Uuid, _>(user)
        .execute(&mut connection).await.unwrap();
    sql_query("INSERT INTO oauth_token_issuances SELECT $1, $2, $3, 'rollback-' || n, CURRENT_TIMESTAMP + INTERVAL '1 hour' FROM generate_series(1, 513) n")
        .bind::<sql_types::Uuid, _>(tenant).bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Uuid, _>(user).execute(&mut connection).await.unwrap();
    for (scope_tenant, scope_client, scope_user) in [
        (Uuid::now_v7(), Some(client), Some(user)),
        (tenant, Some(Uuid::now_v7()), Some(user)),
        (tenant, Some(client), Some(Uuid::now_v7())),
    ] {
        let count = connection
            .transaction::<_, diesel::result::Error, _>(async |connection| {
                revoke_access_tokens_for_owner_on_connection(
                    connection,
                    scope_tenant,
                    scope_client,
                    scope_user,
                )
                .await
            })
            .await
            .unwrap();
        assert_eq!(count, 0, "revocation must preserve other owners");
    }
    let aborted = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            assert_eq!(
                revoke_access_tokens_for_owner_on_connection(connection, tenant, None, Some(user))
                    .await?,
                514
            );
            Err(diesel::result::Error::RollbackTransaction)
        })
        .await;
    assert!(matches!(
        aborted,
        Err(diesel::result::Error::RollbackTransaction)
    ));
    let count = sql_query("SELECT count(*)::bigint AS count FROM access_token_revocations")
        .get_result::<Count>(&mut connection)
        .await
        .unwrap();
    assert_eq!(count.count, 0);
    let active = sql_query(
        "SELECT count(*)::bigint AS count FROM openid4vci_access_grants WHERE revoked_at IS NULL",
    )
    .get_result::<Count>(&mut connection)
    .await
    .unwrap();
    assert_eq!(active.count, 1);
    let committed = connection
        .transaction::<_, diesel::result::Error, _>(async |connection| {
            revoke_access_tokens_for_owner_on_connection(connection, tenant, None, Some(user)).await
        })
        .await
        .unwrap();
    assert_eq!(committed, 514);
}

fn valid_commit_input(mode: TokenIssuanceMode) -> CommitTokenIssuance {
    CommitTokenIssuance {
        issuance_id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: Some(Uuid::now_v7()),
        mode,
        access_token_jti: "access-jti".to_owned(),
        access_token_expires_at: (Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        refresh_token: None,
        audit_fields: TokenIssuedAuditFields {
            client_id: "client".to_owned(),
            subject_hash: "subject-hash".to_owned(),
            scope: "openid".to_owned(),
            audience: vec!["resource".to_owned()],
        },
    }
}

fn refresh_token_for(input: &CommitTokenIssuance) -> NewRefreshToken {
    NewRefreshToken {
        raw_token: "refresh".to_owned(),
        member_id: Uuid::now_v7(),
        tenant_id: input.tenant_id,
        family_id: Uuid::now_v7(),
        rotated_from_id: None,
        lost_response_retry: None,
        client_id: input.client_id,
        user_id: input.user_id,
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource".to_owned()],
        authorization_details: serde_json::json!([]),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        subject: "subject".to_owned(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
        authentication_context: nazo_auth::RefreshTokenAuthenticationContext {
            version: 1,
            issuer: "https://issuer.example".to_owned(),
            audience: "resource".to_owned(),
            auth_time: 1,
            amr: vec!["pwd".to_owned()],
            oidc_sid: None,
            id_token_sid: None,
            acr: None,
            nonce: None,
            userinfo_claims: vec![],
            userinfo_claim_requests: vec![],
            id_token_claims: vec![],
            id_token_claim_requests: vec![],
        },
    }
}

#[test]
fn commit_input_validation_enforces_mode_ownership_and_expiry_contracts() {
    let fresh = valid_commit_input(TokenIssuanceMode::Fresh);
    assert!(validate_commit_input(&fresh).is_ok());

    let single = valid_commit_input(TokenIssuanceMode::SingleUse {
        grant_key: "grant".to_owned(),
        grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
    });
    assert!(validate_commit_input(&single).is_ok());

    for malformed in [
        {
            let mut value = fresh.clone();
            value.issuance_id = Uuid::nil();
            value
        },
        {
            let mut value = fresh.clone();
            value.tenant_id = Uuid::nil();
            value
        },
        {
            let mut value = fresh.clone();
            value.client_id = Uuid::nil();
            value
        },
        {
            let mut value = fresh.clone();
            value.access_token_jti.clear();
            value
        },
    ] {
        assert!(matches!(
            validate_commit_input(&malformed),
            Err(RepositoryError::Consistency(message)) if message.contains("malformed")
        ));
    }

    let mut empty_grant_key = valid_commit_input(TokenIssuanceMode::SingleUse {
        grant_key: " ".to_owned(),
        grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
    });
    assert!(matches!(
        validate_commit_input(&empty_grant_key),
        Err(RepositoryError::Consistency(message)) if message.contains("grant key is empty")
    ));
    empty_grant_key.mode = TokenIssuanceMode::SingleUse {
        grant_key: "grant".to_owned(),
        grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
    };
    assert!(validate_commit_input(&empty_grant_key).is_ok());

    let mut wrong_owner = fresh.clone();
    wrong_owner.refresh_token = Some(refresh_token_for(&wrong_owner));
    wrong_owner.refresh_token.as_mut().unwrap().tenant_id = Uuid::now_v7();
    assert!(matches!(
        validate_commit_input(&wrong_owner),
        Err(RepositoryError::Consistency(message)) if message.contains("owner")
    ));

    let mut invalid_expiry = fresh;
    invalid_expiry.access_token_expires_at = i64::MAX;
    assert!(matches!(
        validate_commit_input(&invalid_expiry),
        Err(RepositoryError::Consistency(message)) if message.contains("expiry")
    ));
}

#[test]
fn audit_events_cover_issuance_rotation_and_reuse_shapes() {
    let input = valid_commit_input(TokenIssuanceMode::SingleUse {
        grant_key: "grant".to_owned(),
        grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
    });

    let issued = token_issued_audit_event(&input, None);
    assert_eq!(issued.event_type, "token_issued");
    assert_eq!(issued.event_category, "token_lifecycle");
    assert_eq!(
        issued.payload["tenant_id"],
        serde_json::json!(input.tenant_id)
    );
    assert_eq!(
        issued.payload["issuance_id"],
        serde_json::json!(input.issuance_id)
    );
    assert_eq!(
        issued.payload["access_token_jti"],
        serde_json::json!(&input.access_token_jti)
    );
    assert_eq!(
        issued.payload["refresh_token_family_id"],
        serde_json::Value::Null
    );

    let mut refresh = refresh_token_for(&input);
    refresh.rotated_from_id = Some(Uuid::now_v7());
    refresh.lost_response_retry = Some(nazo_auth::LostResponseRetry {
        original_id: Uuid::now_v7(),
        original_blake3: [7u8; 32],
        retry_started_at: Utc::now(),
    });
    // A rotation is the same logical issuance: the rotated_from_id fact rides
    // on the single token_issued event instead of a second ledger row.
    let rotated = token_issued_audit_event(&input, Some(&refresh));
    assert_eq!(rotated.event_type, "token_issued");
    assert_eq!(
        rotated.payload["refresh_token_family_id"],
        serde_json::json!(refresh.family_id)
    );
    assert_eq!(
        rotated.payload["rotated_from_id"],
        serde_json::json!(refresh.rotated_from_id)
    );
    let reused = refresh_reuse_audit_event(&input, &refresh);
    assert_eq!(reused.event_type, "refresh_reuse_detected");
    assert_eq!(reused.event_category, "token_replay");
    assert_eq!(
        reused.payload["source_token_id"],
        serde_json::json!(
            refresh
                .lost_response_retry
                .as_ref()
                .map(|retry| retry.original_id)
        )
    );
    refresh.lost_response_retry = None;
    assert_eq!(
        refresh_reuse_audit_event(&input, &refresh).event_type,
        "refresh_reuse_detected"
    );
}

#[test]
fn commit_transaction_conversion_preserves_diesel_errors() {
    let error = CommitTransactionError::from(diesel::result::Error::NotFound);
    assert!(matches!(
        error,
        CommitTransactionError::Diesel(diesel::result::Error::NotFound)
    ));
}

#[test]
fn token_error_mappings_preserve_conflicts_and_corruption_boundaries() {
    assert!(matches!(
        map_repository_error(RepositoryError::Unavailable),
        TokenPortError::Unavailable
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::Conflict),
        TokenPortError::Conflict
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::AlreadyProcessed),
        TokenPortError::Conflict
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::Consistency("bad row".to_owned())),
        TokenPortError::CorruptData
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::NotFound),
        TokenPortError::Unexpected
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::Unexpected("db".to_owned())),
        TokenPortError::Unexpected
    ));

    assert!(matches!(
        map_diesel_error(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            Box::new("duplicate".to_owned()),
        )),
        TokenPortError::Conflict
    ));
    assert!(matches!(
        map_diesel_error(diesel::result::Error::NotFound),
        TokenPortError::CorruptData
    ));
    assert!(matches!(
        map_diesel_error(diesel::result::Error::RollbackTransaction),
        TokenPortError::Unexpected
    ));
}
