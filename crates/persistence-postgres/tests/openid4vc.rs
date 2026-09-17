use argon2::{Argon2, PasswordHasher};
use chrono::{DateTime, Duration, Utc};
use diesel::{
    OptionalExtension, QueryableByName, sql_query,
    sql_types::{BigInt, Binary, Text, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_digital_credentials::{CredentialFormat, CredentialQuery, DcqlQuery};
use nazo_openid4vci::{
    AuthorizationCodeGrant, AuthorizationOfferPort, CredentialAccess, CredentialOfferGrants,
    CredentialResponseEncoding, CredentialStoreError, CredentialStorePort, DeferredCredential,
    IssuanceNotification, NonceRecord, NotificationEvent, NotificationHandle,
    PreAuthorizedCodeGrant, StoredCredentialOffer, StoredCredentialResponse, TxCodeDescription,
};
use nazo_openid4vp::{
    AuthorizationRequest, ClientIdPrefix, PresentationResult, PresentationStorePort,
    PresentationTransaction, RequestMethod, ResponseMode,
};
use nazo_postgres::{
    ManagedCredentialDatasetWrite, Openid4vciDatasetRepository, Openid4vciRepository,
    Openid4vpRepository, create_pool, get_conn,
};
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI OpenID4VC repository tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct CiphertextRow {
    #[diesel(sql_type = Binary)]
    claims_ciphertext: Vec<u8>,
}

#[derive(QueryableByName)]
struct NonceStateRow {
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    claim_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    claim_expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_dataset_mutations_require_an_active_admin_and_are_audited_atomically() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let organization_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let admin_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let subject_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    for (id, role, admin_level) in [
        (admin_id, "admin", 1),
        (user_id, "user", 0),
        (subject_id, "user", 0),
    ] {
        sql_query(
            "INSERT INTO users
                (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level)
             VALUES ($1,$2,$3,$4,$5,$6,'test',$7,$8)",
        )
        .bind::<SqlUuid, _>(id)
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(realm_id)
        .bind::<SqlUuid, _>(organization_id)
        .bind::<Text, _>(format!("openid4vc-dataset-{id}"))
        .bind::<Text, _>(format!("openid4vc-dataset-{id}@example.test"))
        .bind::<Text, _>(role)
        .bind::<diesel::sql_types::Integer, _>(admin_level)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    drop(connection);

    let repository = Openid4vciDatasetRepository::new(pool.clone(), [0x51; 32]);
    let claims = serde_json::json!({"given_name":"Ada"});
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = FALSE WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(admin_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        !repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "inactive-admin-pid",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap(),
        "inactive administrators cannot write issuer-authoritative datasets"
    );
    assert!(
        repository
            .managed_dataset(tenant_id, subject_id, "inactive-admin-pid")
            .await
            .unwrap()
            .is_none(),
        "a rejected inactive-admin write must not make data readable"
    );
    assert!(
        !repository
            .delete_managed_dataset(tenant_id, admin_id, subject_id, "inactive-admin-pid")
            .await
            .unwrap(),
        "inactive administrators cannot delete issuer-authoritative datasets"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = TRUE WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(admin_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        !repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: user_id,
                subject_id,
                credential_configuration_id: "pid",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap()
    );
    assert!(
        repository
            .managed_dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .is_none()
    );

    assert!(
        repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "pid",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap()
    );
    assert_eq!(
        repository
            .managed_dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .unwrap()
            .claims,
        claims
    );
    assert_eq!(
        repository
            .dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .expect("an unbounded dataset should be active"),
        claims
    );
    assert!(
        repository
            .dataset(Uuid::now_v7(), subject_id, "pid")
            .await
            .unwrap()
            .is_none(),
        "dataset reads must remain tenant scoped"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET valid_from = CURRENT_TIMESTAMP + INTERVAL '5 minutes'
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = 'pid'",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(
        repository
            .dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .is_none(),
        "future-valid datasets must not be available to issuance"
    );
    assert!(
        repository
            .managed_dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .is_some(),
        "management reads retain future validity metadata"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET valid_from = NULL, valid_until = CURRENT_TIMESTAMP - INTERVAL '1 second'
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = 'pid'",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(
        repository
            .dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .is_none(),
        "expired datasets must not be available to issuance"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET valid_until = NULL
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = 'pid'",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role = 'admin', admin_level = 0 WHERE id = $1")
        .bind::<SqlUuid, _>(admin_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        !repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "zero-level-admin",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap(),
        "an admin without a positive level cannot write datasets"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role = 'admin', admin_level = 1, is_active = TRUE WHERE id = $1")
        .bind::<SqlUuid, _>(admin_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("UPDATE users SET is_active = FALSE WHERE id = $1")
        .bind::<SqlUuid, _>(subject_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        !repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "inactive-subject",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap(),
        "inactive subjects cannot receive issuer-authoritative datasets"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = TRUE WHERE id = $1")
        .bind::<SqlUuid, _>(subject_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let mut connection = get_conn(&pool).await.unwrap();
    let raw = sql_query(
        "SELECT claims_ciphertext FROM openid4vci_credential_datasets
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = 'pid'",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .get_result::<CiphertextRow>(&mut connection)
    .await
    .unwrap();
    assert!(
        !raw.claims_ciphertext
            .windows(3)
            .any(|window| window == b"Ada"),
        "issuer-authoritative credential claims must not be stored as plaintext"
    );
    drop(connection);
    let copied_claims = serde_json::json!({"given_name":"Grace"});
    assert!(
        repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "pid-copy",
                claims: &copied_claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap()
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET claims_ciphertext = $4
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = $3",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .bind::<Text, _>("pid-copy")
    .bind::<Binary, _>(raw.claims_ciphertext)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert_eq!(
        repository
            .managed_dataset(tenant_id, subject_id, "pid-copy")
            .await,
        Err(CredentialStoreError::InvalidTransition),
        "ciphertext copied to another dataset identity must fail AAD authentication"
    );
    assert!(
        !repository
            .delete_managed_dataset(tenant_id, user_id, subject_id, "pid")
            .await
            .unwrap()
    );
    assert!(
        repository
            .delete_managed_dataset(tenant_id, admin_id, subject_id, "pid")
            .await
            .unwrap()
    );
    assert!(
        repository
            .delete_managed_dataset(tenant_id, admin_id, subject_id, "pid-copy")
            .await
            .unwrap()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    let events = sql_query(
        "SELECT COUNT(*)::bigint AS count
         FROM openid4vci_credential_dataset_events
         WHERE tenant_id = $1 AND subject_id = $2 AND actor_user_id = $3",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .bind::<SqlUuid, _>(admin_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        events.count, 4,
        "each dataset upsert and delete must append an audit event"
    );
    sql_query(
        "DELETE FROM openid4vci_credential_dataset_events
         WHERE tenant_id = $1 AND subject_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id IN ($2,$3,$4)")
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(admin_id)
        .bind::<SqlUuid, _>(user_id)
        .bind::<SqlUuid, _>(subject_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openid4vc_state_is_tenant_bound_and_sensitive_values_are_single_use_and_encrypted_at_rest()
{
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let organization_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let subject_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
        .bind::<SqlUuid,_>(subject_id)
        .bind::<SqlUuid,_>(tenant_id)
        .bind::<SqlUuid,_>(realm_id)
        .bind::<SqlUuid,_>(organization_id)
        .bind::<Text,_>(format!("openid4vc-{subject_id}"))
        .bind::<Text,_>(format!("openid4vc-{subject_id}@example.test"))
        .execute(&mut connection).await.unwrap();
    drop(connection);

    let now = Utc::now();
    let data_key = [23_u8; 32];
    let issuer = Openid4vciRepository::new(pool.clone(), data_key);
    let offer_tenant_b_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO tenants (id, slug, display_name, status) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind::<SqlUuid, _>(offer_tenant_b_id)
    .bind::<Text, _>(format!("openid4vc-offer-isolation-{offer_tenant_b_id}"))
    .bind::<Text, _>("OpenID4VC offer isolation test tenant")
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let issuer_state = format!("issuer-state-{}", Uuid::now_v7());
    let offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(
            Some(AuthorizationCodeGrant {
                issuer_state: Some(issuer_state.clone()),
                authorization_server: Some("https://issuer.example".to_owned()),
            }),
            None,
        ),
        expires_at: now + Duration::minutes(5),
    };
    let issuer_state_hash = blake3::hash(issuer_state.as_bytes()).to_hex().to_string();
    issuer
        .insert_offer(&offer, Some(&issuer_state_hash), None, None)
        .await
        .unwrap();
    let loaded_offer = issuer
        .offer(tenant_id, offer.id, now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        issuer
            .offer(offer_tenant_b_id, offer.id, now)
            .await
            .unwrap()
            .is_none(),
        "a credential offer must not be readable from another tenant"
    );
    assert_eq!(loaded_offer.id, offer.id);
    assert_eq!(loaded_offer.tenant_id, offer.tenant_id);
    assert_eq!(loaded_offer.subject_id, offer.subject_id);
    assert_eq!(
        loaded_offer.credential_configuration_ids,
        offer.credential_configuration_ids
    );
    assert_eq!(loaded_offer.grants, offer.grants);
    assert_eq!(
        loaded_offer.expires_at.timestamp_micros(),
        offer.expires_at.timestamp_micros()
    );
    let resolve_at = Utc::now();
    for client_id in ["wallet", "wallet-2"] {
        let authorization = issuer
            .resolve_authorization_offer(
                tenant_id,
                &issuer_state_hash,
                subject_id,
                client_id,
                resolve_at,
            )
            .await
            .unwrap()
            .expect("the offer should remain valid for multiple wallet clients");
        assert_eq!(authorization.client_id, client_id);
    }
    assert!(
        issuer
            .resolve_authorization_offer(
                offer_tenant_b_id,
                &issuer_state_hash,
                subject_id,
                "cross-tenant-wallet",
                resolve_at,
            )
            .await
            .unwrap()
            .is_none(),
        "issuer-state offers must not resolve from another tenant"
    );

    let pre_authorized_code = format!("preauth-{}", Uuid::now_v7());
    let pre_authorized_hash = blake3::hash(pre_authorized_code.as_bytes())
        .to_hex()
        .to_string();
    let pre_authorized_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(
            None,
            Some(PreAuthorizedCodeGrant {
                pre_authorized_code,
                tx_code: None,
                authorization_server: Some("https://issuer.example".to_owned()),
            }),
        ),
        expires_at: now + Duration::minutes(5),
    };
    issuer
        .insert_offer(
            &pre_authorized_offer,
            None,
            Some(&pre_authorized_hash),
            None,
        )
        .await
        .unwrap();
    let pre_authorized_consume_at = Utc::now();
    assert!(
        issuer
            .consume_pre_authorized_offer(
                offer_tenant_b_id,
                &pre_authorized_hash,
                None,
                "cross-tenant-wallet",
                pre_authorized_consume_at,
            )
            .await
            .unwrap()
            .is_none(),
        "a pre-authorized offer must not be consumable from another tenant"
    );
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &pre_authorized_hash,
                None,
                "wallet-a",
                pre_authorized_consume_at,
            )
            .await
            .unwrap()
            .is_some(),
        "the original tenant must still be able to consume its offer"
    );
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &pre_authorized_hash,
                None,
                "wallet-b",
                pre_authorized_consume_at,
            )
            .await
            .unwrap()
            .is_none()
    );

    let access = CredentialAccess {
        token_id: Uuid::now_v7(),
        tenant_id,
        subject_id,
        client_id: "wallet".to_owned(),
        configuration_ids: vec!["pid".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: now + Duration::minutes(5),
    };
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    let nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: nonce_hash.clone(),
            expires_at: now + Duration::minutes(1),
        })
        .await
        .unwrap();
    let nonce_transition_at = Utc::now();
    assert!(
        issuer
            .claim_nonce(&nonce_hash, "state-boundary", nonce_transition_at)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_nonce(&nonce_hash, "state-boundary", nonce_transition_at)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .claim_nonce(&nonce_hash, "state-boundary-replay", nonce_transition_at)
            .await
            .unwrap()
    );

    let verifier = Openid4vpRepository::new(pool.clone(), tenant_id, data_key);
    let transaction_id = Uuid::now_v7();
    let presentation_state = format!("state-{}", Uuid::now_v7());
    let request = AuthorizationRequest {
        client_id: "redirect_uri:https://verifier.example/response".to_owned(),
        response_type: "vp_token".to_owned(),
        response_mode: "direct_post".to_owned(),
        response_uri: "https://verifier.example/response".to_owned(),
        nonce: "nonce".to_owned(),
        state: presentation_state.clone(),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".to_owned(),
                format: CredentialFormat::SdJwtVc,
                multiple: false,
                meta: None,
                claims: None,
                claim_sets: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
            }],
            credential_sets: None,
        },
        client_metadata: None,
        verifier_info: None,
        transaction_data: None,
        wallet_nonce: None,
    };
    let transaction = PresentationTransaction {
        id: transaction_id,
        client_id_prefix: ClientIdPrefix::RedirectUri,
        request_method: RequestMethod::UrlQuery,
        response_mode: ResponseMode::DirectPost,
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        request,
        request_object: None,
        request_uri: None,
        openid4vc_trust_policy_binding_id: None,
        openid4vc_trust_policy_resource_id: None,
        openid4vc_trust_policy_digest: None,
        response_encryption_private_key: Some(vec![7_u8; 32]),
        created_at: now,
        expires_at: now + Duration::minutes(5),
    };
    let create_request_jti = Uuid::now_v7().to_string();
    let normalized_create = nazo_operator_protocol::Openid4vpNormalizedCreateRequest {
        wallet_authorization_endpoint: transaction.wallet_authorization_endpoint.clone(),
        dcql_query: serde_json::to_value(&transaction.request.dcql_query).unwrap(),
        haip: false,
        client_id_prefix: transaction.client_id_prefix.as_str().to_owned(),
        request_method: transaction.request_method.as_str().to_owned(),
        response_mode: transaction.response_mode.as_str().to_owned(),
        transaction_data: None,
        openid4vc_trust_policy_resource_id: None,
        openid4vc_trust_policy_digest: None,
    };
    let (create_request, create_request_sha256) =
        nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized_create)
            .unwrap();
    assert_eq!(
        verifier
            .create(
                &transaction,
                nazo_openid4vp::PresentationCreateIdempotency {
                    request_jti: &create_request_jti,
                    request_sha256: &create_request_sha256,
                    canonical_request: &create_request,
                },
            )
            .await
            .unwrap(),
        nazo_openid4vp::PresentationCreateOutcome::Created
    );
    let replay = verifier
        .create(
            &transaction,
            nazo_openid4vp::PresentationCreateIdempotency {
                request_jti: &create_request_jti,
                request_sha256: &create_request_sha256,
                canonical_request: &create_request,
            },
        )
        .await
        .unwrap();
    let nazo_openid4vp::PresentationCreateOutcome::Existing(existing) = replay else {
        panic!("an exact create replay must return the persisted transaction");
    };
    assert_eq!(existing.id, transaction_id);
    assert_eq!(
        existing.created_at.timestamp_micros(),
        transaction.created_at.timestamp_micros(),
        "the persistence boundary must retain the transaction creation time"
    );
    assert_eq!(
        existing
            .expires_at
            .signed_duration_since(existing.created_at),
        transaction
            .expires_at
            .signed_duration_since(transaction.created_at),
        "an idempotent replay must retain the original transaction lifetime"
    );
    let mut different_normalized_create = normalized_create.clone();
    different_normalized_create.haip = true;
    let (different_request, different_sha256) =
        nazo_operator_protocol::canonical_openid4vp_normalized_create_request(
            &different_normalized_create,
        )
        .unwrap();
    assert_eq!(
        verifier
            .create(
                &transaction,
                nazo_openid4vp::PresentationCreateIdempotency {
                    request_jti: &create_request_jti,
                    request_sha256: &different_sha256,
                    canonical_request: &different_request,
                },
            )
            .await
            .expect_err("same create JTI must reject different canonical input"),
        nazo_openid4vp::PresentationStoreError::IdempotencyConflict
    );
    let unrelated_jti = Uuid::now_v7().to_string();
    assert_eq!(
        verifier
            .create(
                &transaction,
                nazo_openid4vp::PresentationCreateIdempotency {
                    request_jti: &unrelated_jti,
                    request_sha256: &create_request_sha256,
                    canonical_request: &create_request,
                },
            )
            .await
            .expect_err("transaction primary-key conflicts must not masquerade as replay"),
        nazo_openid4vp::PresentationStoreError::Unavailable
    );
    let invalid_binding_jti = Uuid::now_v7().to_string();
    let invalid_binding_sha256 = "f".repeat(64);
    assert_eq!(
        verifier
            .create(
                &transaction,
                nazo_openid4vp::PresentationCreateIdempotency {
                    request_jti: &invalid_binding_jti,
                    request_sha256: &invalid_binding_sha256,
                    canonical_request: &create_request,
                },
            )
            .await
            .expect_err("canonical create JSON and digest must agree"),
        nazo_openid4vp::PresentationStoreError::InvalidTransition
    );
    let concurrent_jti = Uuid::now_v7().to_string();
    let mut concurrent_a = transaction.clone();
    concurrent_a.id = Uuid::now_v7();
    concurrent_a.request.state = format!("concurrent-a-{}", Uuid::now_v7());
    let mut concurrent_b = transaction.clone();
    concurrent_b.id = Uuid::now_v7();
    concurrent_b.request.state = format!("concurrent-b-{}", Uuid::now_v7());
    let binding = nazo_openid4vp::PresentationCreateIdempotency {
        request_jti: &concurrent_jti,
        request_sha256: &create_request_sha256,
        canonical_request: &create_request,
    };
    let (created_a, created_b) = tokio::join!(
        verifier.create(&concurrent_a, binding),
        verifier.create(&concurrent_b, binding)
    );
    let created_a = created_a.unwrap();
    let created_b = created_b.unwrap();
    let winner_ids = [created_a, created_b]
        .into_iter()
        .map(|outcome| match outcome {
            nazo_openid4vp::PresentationCreateOutcome::Created => None,
            nazo_openid4vp::PresentationCreateOutcome::Existing(transaction) => {
                Some(transaction.id)
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        winner_ids.iter().filter(|id| id.is_none()).count(),
        1,
        "concurrent exact create must have exactly one insert winner"
    );
    let replayed_winner = winner_ids
        .into_iter()
        .flatten()
        .next()
        .expect("the losing create must return the persisted winner");
    assert!(replayed_winner == concurrent_a.id || replayed_winner == concurrent_b.id);
    let loaded = verifier
        .request(transaction_id, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.response_encryption_private_key, Some(vec![7_u8; 32]));
    let bound = verifier
        .bind_wallet_nonce(transaction_id, "wallet-nonce", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bound.request.wallet_nonce.as_deref(), Some("wallet-nonce"));
    assert_eq!(
        verifier
            .request(transaction_id, now)
            .await
            .unwrap()
            .unwrap()
            .request
            .wallet_nonce
            .as_deref(),
        Some("wallet-nonce")
    );
    let completed_at = Utc::now();
    let result = PresentationResult {
        transaction_id,
        credentials: Vec::new(),
        completed_at,
    };
    let state_hash = blake3::hash(presentation_state.as_bytes())
        .to_hex()
        .to_string();
    let tenant_b_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO tenants (id, slug, display_name, status) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind::<SqlUuid, _>(tenant_b_id)
    .bind::<Text, _>(format!("openid4vc-isolation-{tenant_b_id}"))
    .bind::<Text, _>("OpenID4VC isolation test tenant")
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let other_verifier = Openid4vpRepository::new(pool.clone(), tenant_b_id, data_key);
    let mut other_tenant_transaction = transaction.clone();
    other_tenant_transaction.id = Uuid::now_v7();
    other_tenant_transaction.request.state = format!("other-tenant-{}", Uuid::now_v7());
    assert_eq!(
        other_verifier
            .create(
                &other_tenant_transaction,
                nazo_openid4vp::PresentationCreateIdempotency {
                    request_jti: &create_request_jti,
                    request_sha256: &create_request_sha256,
                    canonical_request: &create_request,
                },
            )
            .await
            .unwrap(),
        nazo_openid4vp::PresentationCreateOutcome::Created,
        "different tenants may independently use the same create JTI"
    );
    assert!(
        other_verifier
            .request(transaction_id, now)
            .await
            .unwrap()
            .is_none(),
        "a presentation transaction must not be readable from another tenant"
    );

    assert!(
        other_verifier
            .bind_wallet_nonce(transaction_id, "cross-tenant-wallet-nonce", now)
            .await
            .unwrap()
            .is_none(),
        "a cross-tenant wallet nonce bind must not update the source transaction"
    );
    assert!(
        !other_verifier
            .complete(transaction_id, &state_hash, &result, completed_at)
            .await
            .unwrap(),
        "a cross-tenant completion must not consume the source transaction"
    );
    assert!(
        other_verifier
            .result(transaction_id, now)
            .await
            .unwrap()
            .is_none(),
        "a presentation result must remain invisible across tenants"
    );
    assert_eq!(
        verifier
            .request(transaction_id, now)
            .await
            .unwrap()
            .unwrap()
            .request
            .wallet_nonce
            .as_deref(),
        Some("wallet-nonce"),
        "cross-tenant operations must leave the source transaction unchanged"
    );
    assert!(
        verifier
            .complete(transaction_id, &state_hash, &result, completed_at)
            .await
            .unwrap()
    );
    assert!(
        !verifier
            .complete(transaction_id, &state_hash, &result, completed_at)
            .await
            .unwrap()
    );
    let stored_result = verifier.result(transaction_id, now).await.unwrap().unwrap();
    assert_eq!(stored_result.completed, Some(result));
    assert_eq!(
        stored_result.transaction.response_encryption_private_key, None,
        "successful completion must erase the no-longer-consumed ephemeral response key"
    );
    let mut late_transaction = transaction.clone();
    late_transaction.id = Uuid::now_v7();
    late_transaction.request.state = format!("late-state-{}", Uuid::now_v7());
    late_transaction.created_at = now;
    late_transaction.expires_at = now + Duration::minutes(1);
    let late_create_request_jti = Uuid::now_v7().to_string();
    let (late_create_request, late_create_request_sha256) =
        nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized_create)
            .unwrap();
    verifier
        .create(
            &late_transaction,
            nazo_openid4vp::PresentationCreateIdempotency {
                request_jti: &late_create_request_jti,
                request_sha256: &late_create_request_sha256,
                canonical_request: &late_create_request,
            },
        )
        .await
        .unwrap();
    let late_completion_at = late_transaction.expires_at + Duration::seconds(1);
    let late_result = PresentationResult {
        transaction_id: late_transaction.id,
        credentials: Vec::new(),
        completed_at: late_completion_at,
    };
    assert!(
        !verifier
            .complete(
                late_transaction.id,
                blake3::hash(late_transaction.request.state.as_bytes())
                    .to_hex()
                    .as_ref(),
                &late_result,
                late_completion_at,
            )
            .await
            .unwrap(),
        "late completion must not create a verified result"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    let late_row = sql_query(
        "SELECT COUNT(*) AS count FROM openid4vp_transactions \
         WHERE id = $1 AND completed_at IS NULL AND result_ciphertext IS NULL",
    )
    .bind::<SqlUuid, _>(late_transaction.id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        late_row.count, 1,
        "late completion must leave the persisted transaction unverified"
    );
    drop(connection);

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash = $1")
        .bind::<Text, _>(&nonce_hash)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vp_transactions WHERE id = $1")
        .bind::<SqlUuid, _>(transaction_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vp_transactions WHERE id = $1")
        .bind::<SqlUuid, _>(late_transaction.id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vci_offers WHERE id IN ($1,$2)")
        .bind::<SqlUuid, _>(offer.id)
        .bind::<SqlUuid, _>(pre_authorized_offer.id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1 AND tenant_id = $2")
        .bind::<SqlUuid, _>(subject_id)
        .bind::<SqlUuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(tenant_b_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(offer_tenant_b_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recoverable_issuance_leases_commit_responses_and_deferred_credentials_once() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let organization_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let subject_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) \
         VALUES ($1,$2,$3,$4,$5,$6,'test')",
    )
    .bind::<SqlUuid, _>(subject_id)
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(realm_id)
    .bind::<SqlUuid, _>(organization_id)
    .bind::<Text, _>(format!("openid4vc-recovery-{subject_id}"))
    .bind::<Text, _>(format!("openid4vc-recovery-{subject_id}@example.test"))
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let now = Utc::now();
    let issuer = Openid4vciRepository::new(pool.clone(), [0x37_u8; 32]);
    let access = CredentialAccess {
        token_id: Uuid::now_v7(),
        tenant_id,
        subject_id,
        client_id: "wallet".to_owned(),
        configuration_ids: vec!["pid".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: now + Duration::minutes(10),
    };
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();

    let nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: nonce_hash.clone(),
            expires_at: now + Duration::minutes(5),
        })
        .await
        .unwrap();
    let nonce_now = Utc::now();
    assert!(
        issuer
            .claim_nonce(&nonce_hash, "claim-a", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .claim_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .release_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .release_nonce(&nonce_hash, "claim-a", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .finalize_nonce(&nonce_hash, "claim-a", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .finalize_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );

    let reclaim_nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    let reclaim_nonce_issued_at = Utc::now();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: reclaim_nonce_hash.clone(),
            expires_at: reclaim_nonce_issued_at + Duration::minutes(30),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(
                &reclaim_nonce_hash,
                "expired-claim-a",
                reclaim_nonce_issued_at
            )
            .await
            .unwrap()
    );
    let reclaim_nonce_now = reclaim_nonce_issued_at + Duration::minutes(6);
    assert!(
        issuer
            .claim_nonce(&reclaim_nonce_hash, "expired-claim-b", reclaim_nonce_now)
            .await
            .unwrap(),
        "a nonce lease must be reclaimable after claim_expires_at without sleeping"
    );
    assert!(
        !issuer
            .finalize_nonce(&reclaim_nonce_hash, "expired-claim-a", reclaim_nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .release_nonce(&reclaim_nonce_hash, "expired-claim-a", reclaim_nonce_now)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_nonce(&reclaim_nonce_hash, "expired-claim-b", reclaim_nonce_now)
            .await
            .unwrap()
    );

    let response_nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: response_nonce_hash.clone(),
            expires_at: now + Duration::minutes(5),
        })
        .await
        .unwrap();
    let response_now = Utc::now();
    assert!(
        issuer
            .claim_nonce(&response_nonce_hash, "response-claim", response_now)
            .await
            .unwrap()
    );
    let response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"issuance-request").to_hex().to_string(),
        body: br#"{"credentials":[]}"#.to_vec(),
        encoding: CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: None,
        expires_at: now + Duration::minutes(5),
    };
    let handle = NotificationHandle {
        notification_id: format!("notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: now + Duration::minutes(5),
    };
    assert!(
        issuer
            .finalize_nonce_with_notification_and_response(
                &response_nonce_hash,
                "response-claim",
                &handle,
                &response,
                response_now,
            )
            .await
            .unwrap()
    );
    let stored_response = issuer
        .find_response(
            response.issuance_id,
            response.token_id,
            &response.request_digest,
            response_now,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_response.issuance_id, response.issuance_id);
    assert_eq!(stored_response.token_id, response.token_id);
    assert_eq!(stored_response.request_digest, response.request_digest);
    assert_eq!(stored_response.body, response.body);
    assert_eq!(stored_response.encoding, response.encoding);
    assert_eq!(stored_response.status, response.status);
    assert_eq!(stored_response.dpop_nonce, response.dpop_nonce);
    assert_eq!(
        stored_response.expires_at.timestamp_micros(),
        response.expires_at.timestamp_micros()
    );
    assert!(
        !issuer
            .claim_nonce(&response_nonce_hash, "response-retry", response_now)
            .await
            .unwrap()
    );
    let notification = IssuanceNotification {
        notification_id: handle.notification_id.clone(),
        token_id: handle.token_id,
        event: NotificationEvent::CredentialAccepted,
        description: Some("issued".to_owned()),
        occurred_at: now + Duration::seconds(1),
    };
    assert!(issuer.record_notification(&notification).await.unwrap());
    assert!(!issuer.record_notification(&notification).await.unwrap());

    let deferred_ready_at = Utc::now() + Duration::seconds(1);
    let deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"deferred-transaction").to_hex().to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"holder"}})],
        payload_ciphertext: b"deferred-payload".to_vec(),
        ready_at: deferred_ready_at,
        expires_at: deferred_ready_at + Duration::minutes(5),
    };
    issuer.store_deferred(&deferred).await.unwrap();
    let first_claim = issuer
        .claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "deferred-a",
            deferred_ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_claim.claim_id, "deferred-a");
    assert_eq!(
        first_claim.credential.payload_ciphertext,
        b"deferred-payload"
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-b",
                deferred_ready_at,
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        issuer
            .release_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-a",
                deferred_ready_at,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-b",
                deferred_ready_at,
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        !issuer
            .release_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-a",
                deferred_ready_at,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-b",
                deferred_ready_at,
            )
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .finalize_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-b",
                now,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-replay",
                deferred_ready_at,
            )
            .await
            .unwrap()
            .is_none()
    );

    let reclaim_deferred_ready_at = Utc::now() + Duration::seconds(1);
    let reclaim_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"deferred-reclaim-transaction")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"reclaim"}})],
        payload_ciphertext: b"reclaim-payload".to_vec(),
        ready_at: reclaim_deferred_ready_at,
        expires_at: reclaim_deferred_ready_at + Duration::minutes(30),
    };
    issuer.store_deferred(&reclaim_deferred).await.unwrap();
    assert!(
        issuer
            .claim_ready_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-a",
                reclaim_deferred_ready_at,
            )
            .await
            .unwrap()
            .is_some()
    );
    let reclaim_deferred_now = reclaim_deferred_ready_at + Duration::minutes(6);
    assert!(
        issuer
            .claim_ready_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-b",
                reclaim_deferred_now,
            )
            .await
            .unwrap()
            .is_some(),
        "a deferred lease must be reclaimable after claim_expires_at without sleeping"
    );
    assert!(
        !issuer
            .finalize_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-a",
                reclaim_deferred_now,
            )
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .release_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-a",
                reclaim_deferred_now,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-b",
                reclaim_deferred_now,
            )
            .await
            .unwrap()
    );

    let atomic_nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: atomic_nonce_hash.clone(),
            expires_at: now + Duration::minutes(5),
        })
        .await
        .unwrap();
    let atomic_now = Utc::now();
    assert!(
        issuer
            .claim_nonce(&atomic_nonce_hash, "atomic-claim", atomic_now)
            .await
            .unwrap()
    );
    let atomic_deferred_ready_at = Utc::now() + Duration::seconds(1);
    let atomic_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"atomic-deferred-transaction")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"holder"}})],
        payload_ciphertext: b"atomic-payload".to_vec(),
        ready_at: atomic_deferred_ready_at,
        expires_at: atomic_deferred_ready_at + Duration::minutes(5),
    };
    let atomic_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"atomic-request").to_hex().to_string(),
        body: b"atomic-response".to_vec(),
        encoding: CredentialResponseEncoding::Jwt,
        status: 202,
        dpop_nonce: Some("dpop-nonce".to_owned()),
        expires_at: now + Duration::minutes(5),
    };
    issuer
        .store_deferred_and_finalize_nonce_with_response(
            &atomic_deferred,
            &atomic_nonce_hash,
            "atomic-claim",
            &atomic_response,
            atomic_deferred_ready_at,
        )
        .await
        .unwrap();
    assert!(
        !issuer
            .claim_nonce(&atomic_nonce_hash, "atomic-retry", atomic_now)
            .await
            .unwrap()
    );
    assert_eq!(
        issuer
            .find_response(
                atomic_response.issuance_id,
                atomic_response.token_id,
                &atomic_response.request_digest,
                atomic_deferred_ready_at,
            )
            .await
            .unwrap()
            .unwrap()
            .body,
        atomic_response.body
    );
    let atomic_claim = issuer
        .claim_ready_deferred(
            &atomic_deferred.transaction_hash,
            access.token_id,
            "atomic-deferred-claim",
            atomic_deferred_ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        atomic_claim.credential.payload_ciphertext,
        b"atomic-payload"
    );
    assert!(
        issuer
            .finalize_deferred(
                &atomic_deferred.transaction_hash,
                access.token_id,
                &atomic_claim.claim_id,
                atomic_deferred_ready_at,
            )
            .await
            .unwrap()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash IN ($1,$2,$3,$4)")
        .bind::<Text, _>(&nonce_hash)
        .bind::<Text, _>(&response_nonce_hash)
        .bind::<Text, _>(&atomic_nonce_hash)
        .bind::<Text, _>(&reclaim_nonce_hash)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1 AND tenant_id = $2")
        .bind::<SqlUuid, _>(subject_id)
        .bind::<SqlUuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuance_store_covers_atomic_recovery_and_terminal_error_boundaries() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let organization_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let subject_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) \
         VALUES ($1,$2,$3,$4,$5,$6,'test')",
    )
    .bind::<SqlUuid, _>(subject_id)
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(realm_id)
    .bind::<SqlUuid, _>(organization_id)
    .bind::<Text, _>(format!("openid4vc-boundary-{subject_id}"))
    .bind::<Text, _>(format!("openid4vc-boundary-{subject_id}@example.test"))
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let issuer = Openid4vciRepository::new(pool.clone(), [0x48_u8; 32]);
    let now = Utc::now();
    let access = CredentialAccess {
        token_id: Uuid::now_v7(),
        tenant_id,
        subject_id,
        client_id: "boundary-wallet".to_owned(),
        configuration_ids: vec!["pid".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: now + Duration::minutes(30),
    };
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    assert_eq!(
        issuer
            .resolve_access(&token_hash, Utc::now())
            .await
            .unwrap()
            .unwrap()
            .token_id,
        access.token_id
    );
    assert!(
        issuer
            .resolve_access("missing-access-hash", Utc::now())
            .await
            .unwrap()
            .is_none()
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_access_grants SET revoked_at = CURRENT_TIMESTAMP WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(access.token_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(
        issuer
            .resolve_access(&token_hash, Utc::now())
            .await
            .unwrap()
            .is_none(),
        "revoked access grants must not be returned"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE openid4vci_access_grants SET revoked_at = NULL, credential_identifiers = $2 WHERE token_id = $1")
        .bind::<SqlUuid, _>(access.token_id)
        .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!([1]))
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        issuer.resolve_access(&token_hash, Utc::now()).await,
        Err(CredentialStoreError::Unavailable),
        "invalid credential identifier JSON must fail closed"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_access_grants SET credential_identifiers = $2 WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(access.token_id)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!([]))
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    // Pre-authorized offers exercise tx-code verification, subject binding,
    // replay protection, and the expired/no-subject branches.
    let pre_authorized_code = format!("preauth-boundary-{}", Uuid::now_v7());
    let pre_authorized_hash = blake3::hash(pre_authorized_code.as_bytes())
        .to_hex()
        .to_string();
    let tx_code_hash = Argon2::default()
        .hash_password_with_salt(b"2468", b"0123456789abcdef")
        .unwrap()
        .to_string();
    let pre_authorized_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(
            None,
            Some(PreAuthorizedCodeGrant {
                pre_authorized_code,
                tx_code: Some(TxCodeDescription {
                    input_mode: Some("numeric".to_owned()),
                    length: Some(4),
                    description: None,
                }),
                authorization_server: Some("https://issuer.example".to_owned()),
            }),
        ),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .insert_offer(
            &pre_authorized_offer,
            None,
            Some(&pre_authorized_hash),
            Some(&tx_code_hash),
        )
        .await
        .unwrap();
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &pre_authorized_hash,
                Some("0000"),
                "boundary-wallet",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none()
    );
    let authorization = issuer
        .consume_pre_authorized_offer(
            tenant_id,
            &pre_authorized_hash,
            Some("2468"),
            "boundary-wallet",
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authorization.subject_id, subject_id);
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &pre_authorized_hash,
                Some("2468"),
                "boundary-wallet",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none()
    );

    let no_subject_code = format!("preauth-no-subject-{}", Uuid::now_v7());
    let no_subject_hash = blake3::hash(no_subject_code.as_bytes())
        .to_hex()
        .to_string();
    let no_subject_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: None,
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(
            None,
            Some(PreAuthorizedCodeGrant {
                pre_authorized_code: no_subject_code,
                tx_code: None,
                authorization_server: None,
            }),
        ),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .insert_offer(&no_subject_offer, None, Some(&no_subject_hash), None)
        .await
        .unwrap();
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &no_subject_hash,
                None,
                "boundary-wallet",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none(),
        "offers without a subject cannot authorize a token"
    );
    let expired_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(None, None),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .insert_offer(&expired_offer, None, None, None)
        .await
        .unwrap();
    assert!(
        issuer
            .offer(
                tenant_id,
                expired_offer.id,
                expired_offer.expires_at + Duration::seconds(1)
            )
            .await
            .unwrap()
            .is_none()
    );
    let corrupt_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(None, None),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .insert_offer(&corrupt_offer, None, None, None)
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE openid4vci_offers SET grants_ciphertext = $2 WHERE id = $1")
        .bind::<SqlUuid, _>(corrupt_offer.id)
        .bind::<Binary, _>(vec![0_u8, 1, 2])
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        issuer.offer(tenant_id, corrupt_offer.id, Utc::now()).await,
        Err(CredentialStoreError::InvalidTransition)
    );

    // Nonce lease timestamps are monotonic even when a caller supplies an
    // earlier clock value, and notification finalization is all-or-nothing.
    let monotonic_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    let monotonic_first_expires_at = Utc::now() + Duration::minutes(10);
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: monotonic_nonce.clone(),
            expires_at: monotonic_first_expires_at,
        })
        .await
        .unwrap();
    let monotonic_second_expires_at = Utc::now() + Duration::minutes(20);
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: monotonic_nonce.clone(),
            expires_at: monotonic_second_expires_at,
        })
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    let before_consume = sql_query(
        "SELECT created_at, expires_at, claim_id, claim_expires_at, consumed_at
         FROM openid4vci_nonces WHERE nonce_hash = $1",
    )
    .bind::<Text, _>(&monotonic_nonce)
    .get_result::<NonceStateRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        before_consume.expires_at.timestamp_micros(),
        monotonic_first_expires_at.timestamp_micros(),
        "duplicate issue_nonce must not extend or otherwise rewrite the original expiry"
    );
    assert!(before_consume.claim_id.is_none());
    assert!(before_consume.claim_expires_at.is_none());
    assert!(before_consume.consumed_at.is_none());
    drop(connection);
    let monotonic_transition_at = Utc::now() - Duration::minutes(1);
    assert!(
        issuer
            .claim_nonce(&monotonic_nonce, "monotonic-owner", monotonic_transition_at,)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_nonce(&monotonic_nonce, "monotonic-owner", monotonic_transition_at,)
            .await
            .unwrap()
    );
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: monotonic_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(30),
        })
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    let after_consume = sql_query(
        "SELECT created_at, expires_at, claim_id, claim_expires_at, consumed_at
         FROM openid4vci_nonces WHERE nonce_hash = $1",
    )
    .bind::<Text, _>(&monotonic_nonce)
    .get_result::<NonceStateRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        after_consume.expires_at.timestamp_micros(),
        monotonic_first_expires_at.timestamp_micros()
    );
    let consumed_at = after_consume
        .consumed_at
        .expect("the first consumption must persist the terminal marker");
    assert!(consumed_at >= after_consume.created_at);
    assert!(after_consume.claim_id.is_none());
    assert!(after_consume.claim_expires_at.is_none());
    drop(connection);
    assert!(
        !issuer
            .claim_nonce(&monotonic_nonce, "monotonic-replay", Utc::now())
            .await
            .unwrap()
    );

    let notification_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: notification_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(&notification_nonce, "notification-owner", Utc::now())
            .await
            .unwrap()
    );
    let notification_handle = NotificationHandle {
        notification_id: format!("notification-boundary-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    assert_eq!(
        issuer
            .finalize_nonce_with_notification(
                &notification_nonce,
                "wrong-owner",
                &notification_handle,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable),
        "a failed atomic nonce finalization must roll back the notification insert"
    );
    assert!(
        issuer
            .finalize_nonce_with_notification(
                &notification_nonce,
                "notification-owner",
                &notification_handle,
                Utc::now(),
            )
            .await
            .unwrap()
    );

    let response_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: response_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(&response_nonce, "response-owner", Utc::now())
            .await
            .unwrap()
    );
    let response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"boundary-response").to_hex().to_string(),
        body: br#"{"credentials":[]}"#.to_vec(),
        encoding: CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: Some("boundary-dpop".to_owned()),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let response_handle = NotificationHandle {
        notification_id: format!("response-boundary-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    assert_eq!(
        issuer
            .finalize_nonce_with_notification_and_response(
                &response_nonce,
                "wrong-owner",
                &response_handle,
                &response,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    assert!(
        issuer
            .finalize_nonce_with_notification_and_response(
                &response_nonce,
                "response-owner",
                &response_handle,
                &response,
                Utc::now(),
            )
            .await
            .unwrap()
    );
    let stored_response = issuer
        .find_response(
            response.issuance_id,
            response.token_id,
            &response.request_digest,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_response.issuance_id, response.issuance_id);
    assert_eq!(stored_response.token_id, response.token_id);
    assert_eq!(stored_response.request_digest, response.request_digest);
    assert_eq!(stored_response.body, response.body);
    assert_eq!(stored_response.encoding, response.encoding);
    assert_eq!(stored_response.status, response.status);
    assert_eq!(stored_response.dpop_nonce, response.dpop_nonce);
    assert_eq!(
        stored_response.expires_at.timestamp_micros(),
        response.expires_at.timestamp_micros()
    );
    let invalid_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        status: u16::MAX,
        ..response.clone()
    };
    assert_eq!(
        issuer
            .store_response_with_notification(&response_handle, &invalid_response, Utc::now())
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );
    assert!(
        issuer
            .store_response_with_notification(&response_handle, &response, Utc::now())
            .await
            .is_err(),
        "replaying the issuance response must not create a second notification"
    );

    let corrupt_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        request_digest: blake3::hash(b"corrupt-response").to_hex().to_string(),
        ..response.clone()
    };
    let corrupt_handle = NotificationHandle {
        notification_id: format!("corrupt-response-{}", Uuid::now_v7()),
        ..response_handle.clone()
    };
    issuer
        .store_response_with_notification(&corrupt_handle, &corrupt_response, Utc::now())
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_issuance_responses SET body_ciphertext = $2 WHERE issuance_id = $1",
    )
    .bind::<SqlUuid, _>(corrupt_response.issuance_id)
    .bind::<Binary, _>(vec![0_u8, 1, 2])
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert_eq!(
        issuer
            .find_response(
                corrupt_response.issuance_id,
                corrupt_response.token_id,
                &corrupt_response.request_digest,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );

    let failure_handle = NotificationHandle {
        notification_id: format!("failure-notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .issue_notification_handle(&failure_handle)
        .await
        .unwrap();
    let failure_notification = IssuanceNotification {
        notification_id: failure_handle.notification_id.clone(),
        token_id: access.token_id,
        event: NotificationEvent::CredentialFailure,
        description: Some("signing failed".to_owned()),
        occurred_at: Utc::now(),
    };
    assert!(
        issuer
            .record_notification(&failure_notification)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .record_notification(&failure_notification)
            .await
            .unwrap()
    );
    let deleted_handle = NotificationHandle {
        notification_id: format!("deleted-notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .issue_notification_handle(&deleted_handle)
        .await
        .unwrap();
    assert!(
        issuer
            .record_notification(&IssuanceNotification {
                notification_id: deleted_handle.notification_id.clone(),
                token_id: access.token_id,
                event: NotificationEvent::CredentialDeleted,
                description: None,
                occurred_at: Utc::now(),
            })
            .await
            .unwrap()
    );
    let expired_handle = NotificationHandle {
        notification_id: format!("expired-notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .issue_notification_handle(&expired_handle)
        .await
        .unwrap();
    assert!(
        !issuer
            .record_notification(&IssuanceNotification {
                notification_id: expired_handle.notification_id.clone(),
                token_id: access.token_id,
                event: NotificationEvent::CredentialAccepted,
                description: None,
                occurred_at: expired_handle.expires_at + Duration::seconds(1),
            })
            .await
            .unwrap()
    );

    // Exercise every deferred transition, including all transaction rollback paths.
    let deferred_ready_at = Utc::now() + Duration::seconds(10);
    let deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred").to_hex().to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"boundary"}})],
        payload_ciphertext: b"boundary-deferred-payload".to_vec(),
        ready_at: deferred_ready_at,
        expires_at: deferred_ready_at + Duration::minutes(10),
    };
    issuer.store_deferred(&deferred).await.unwrap();
    assert!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "not-ready",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none()
    );
    let consumed_deferred = issuer
        .claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "boundary-owner",
            deferred_ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        consumed_deferred.credential.payload_ciphertext,
        deferred.payload_ciphertext
    );
    assert!(
        issuer
            .finalize_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "boundary-owner",
                deferred_ready_at,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "boundary-replay",
                deferred_ready_at,
            )
            .await
            .unwrap()
            .is_none()
    );

    let lease_deferred_ready_at = Utc::now() + Duration::seconds(10);
    let lease_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred-lease")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"lease"}})],
        payload_ciphertext: b"lease-payload".to_vec(),
        ready_at: lease_deferred_ready_at,
        expires_at: lease_deferred_ready_at + Duration::minutes(10),
    };
    issuer.store_deferred(&lease_deferred).await.unwrap();
    let lease_claim = issuer
        .claim_ready_deferred(
            &lease_deferred.transaction_hash,
            access.token_id,
            "lease-owner",
            lease_deferred_ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease_claim.claim_id, "lease-owner");
    assert!(
        issuer
            .release_deferred(
                &lease_deferred.transaction_hash,
                access.token_id,
                "lease-owner",
                lease_deferred_ready_at,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &lease_deferred.transaction_hash,
                access.token_id,
                "lease-owner-2",
                lease_deferred_ready_at,
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        issuer
            .finalize_deferred(
                &lease_deferred.transaction_hash,
                access.token_id,
                "lease-owner-2",
                lease_deferred_ready_at - Duration::seconds(1),
            )
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .finalize_deferred(
                &lease_deferred.transaction_hash,
                access.token_id,
                "lease-owner-2",
                lease_deferred_ready_at,
            )
            .await
            .unwrap()
    );

    let atomic_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: atomic_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(&atomic_nonce, "atomic-owner", Utc::now())
            .await
            .unwrap()
    );
    let atomic_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-atomic-deferred")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"atomic"}})],
        payload_ciphertext: b"atomic-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    // Keep the expiry after ready_at despite taking two clock samples above.
    let atomic_deferred = DeferredCredential {
        expires_at: atomic_deferred.ready_at + Duration::minutes(10),
        ..atomic_deferred
    };
    assert_eq!(
        issuer
            .store_deferred_and_finalize_nonce(
                &atomic_deferred,
                &atomic_nonce,
                "wrong-owner",
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    issuer
        .store_deferred_and_finalize_nonce(
            &atomic_deferred,
            &atomic_nonce,
            "atomic-owner",
            atomic_deferred.ready_at,
        )
        .await
        .unwrap();
    assert!(
        !issuer
            .claim_nonce(&atomic_nonce, "atomic-replay", Utc::now())
            .await
            .unwrap()
    );

    let atomic_response_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: atomic_response_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(&atomic_response_nonce, "atomic-response-owner", Utc::now())
            .await
            .unwrap()
    );
    let atomic_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"boundary-atomic-response")
            .to_hex()
            .to_string(),
        body: b"atomic-response".to_vec(),
        encoding: CredentialResponseEncoding::Jwt,
        status: 202,
        dpop_nonce: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let atomic_response_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-atomic-response-deferred")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"atomic-response"}})],
        payload_ciphertext: b"atomic-response-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let atomic_response_deferred = DeferredCredential {
        expires_at: atomic_response_deferred.ready_at + Duration::minutes(10),
        ..atomic_response_deferred
    };
    assert_eq!(
        issuer
            .store_deferred_and_finalize_nonce_with_response(
                &atomic_response_deferred,
                &atomic_response_nonce,
                "wrong-owner",
                &atomic_response,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    issuer
        .store_deferred_and_finalize_nonce_with_response(
            &atomic_response_deferred,
            &atomic_response_nonce,
            "atomic-response-owner",
            &atomic_response,
            atomic_response_deferred.ready_at,
        )
        .await
        .unwrap();
    assert_eq!(
        issuer
            .find_response(
                atomic_response.issuance_id,
                access.token_id,
                &atomic_response.request_digest,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap()
            .encoding,
        CredentialResponseEncoding::Jwt
    );

    let response_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred-response")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"response"}})],
        payload_ciphertext: b"response-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let response_deferred = DeferredCredential {
        expires_at: response_deferred.ready_at + Duration::minutes(10),
        ..response_deferred
    };
    let deferred_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"boundary-deferred-response-body")
            .to_hex()
            .to_string(),
        body: b"deferred-response".to_vec(),
        encoding: CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .store_deferred_with_response(&response_deferred, &deferred_response, Utc::now())
        .await
        .unwrap();
    assert_eq!(
        issuer
            .find_response(
                deferred_response.issuance_id,
                access.token_id,
                &deferred_response.request_digest,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap()
            .body,
        deferred_response.body
    );

    let notification_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred-notification")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"notification"}})],
        payload_ciphertext: b"notification-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let notification_deferred = DeferredCredential {
        expires_at: notification_deferred.ready_at + Duration::minutes(10),
        ..notification_deferred
    };
    issuer.store_deferred(&notification_deferred).await.unwrap();
    issuer
        .claim_ready_deferred(
            &notification_deferred.transaction_hash,
            access.token_id,
            "notification-deferred-owner",
            notification_deferred.ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    let deferred_handle = NotificationHandle {
        notification_id: format!("deferred-notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    assert_eq!(
        issuer
            .finalize_deferred_with_notification(
                &notification_deferred.transaction_hash,
                access.token_id,
                "wrong-owner",
                &deferred_handle,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    assert!(
        issuer
            .finalize_deferred_with_notification(
                &notification_deferred.transaction_hash,
                access.token_id,
                "notification-deferred-owner",
                &deferred_handle,
                Utc::now(),
            )
            .await
            .unwrap()
    );

    let deferred_response_notification = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred-notification-response")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"notification-response"}})],
        payload_ciphertext: b"notification-response-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let deferred_response_notification = DeferredCredential {
        expires_at: deferred_response_notification.ready_at + Duration::minutes(10),
        ..deferred_response_notification
    };
    issuer
        .store_deferred(&deferred_response_notification)
        .await
        .unwrap();
    issuer
        .claim_ready_deferred(
            &deferred_response_notification.transaction_hash,
            access.token_id,
            "deferred-response-owner",
            deferred_response_notification.ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    let deferred_response_handle = NotificationHandle {
        notification_id: format!("deferred-response-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let final_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"boundary-final-response")
            .to_hex()
            .to_string(),
        body: b"final-response".to_vec(),
        encoding: CredentialResponseEncoding::Jwt,
        status: 202,
        dpop_nonce: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    assert_eq!(
        issuer
            .finalize_deferred_with_notification_and_response(
                &deferred_response_notification.transaction_hash,
                access.token_id,
                "wrong-owner",
                &deferred_response_handle,
                &final_response,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    assert!(
        issuer
            .finalize_deferred_with_notification_and_response(
                &deferred_response_notification.transaction_hash,
                access.token_id,
                "deferred-response-owner",
                &deferred_response_handle,
                &final_response,
                Utc::now(),
            )
            .await
            .unwrap()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash IN ($1,$2,$3,$4)")
        .bind::<Text, _>(&monotonic_nonce)
        .bind::<Text, _>(&notification_nonce)
        .bind::<Text, _>(&response_nonce)
        .bind::<Text, _>(&atomic_nonce)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash = $1")
        .bind::<Text, _>(&atomic_response_nonce)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vci_offers WHERE id IN ($1,$2,$3,$4)")
        .bind::<SqlUuid, _>(pre_authorized_offer.id)
        .bind::<SqlUuid, _>(no_subject_offer.id)
        .bind::<SqlUuid, _>(expired_offer.id)
        .bind::<SqlUuid, _>(corrupt_offer.id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1 AND tenant_id = $2")
        .bind::<SqlUuid, _>(subject_id)
        .bind::<SqlUuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

// ===========================================================================
// DB-014 (VF), DB-012 (UP) and DB-009 (DF) matrix coverage.
// ===========================================================================

fn openid4vc_boundary_ids() -> (Uuid, Uuid, Uuid) {
    (
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
    )
}

fn openid4vc_access_fixture(
    tenant_id: Uuid,
    subject_id: Uuid,
    client_id: &str,
    expires_in: Duration,
) -> CredentialAccess {
    CredentialAccess {
        token_id: Uuid::now_v7(),
        tenant_id,
        subject_id,
        client_id: client_id.to_owned(),
        configuration_ids: vec!["pid".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: DateTime::from_timestamp_micros((Utc::now() + expires_in).timestamp_micros())
            .expect("access expiry must fit the timestamp range"),
    }
}

fn openid4vc_deferred_fixture(
    access: &CredentialAccess,
    tag: &str,
    ready_in: Duration,
    lifetime: Duration,
) -> DeferredCredential {
    let base = DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
        .expect("claim base must fit the timestamp range");
    let ready_at = base + ready_in;
    DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(format!("{tag}-{}", Uuid::now_v7()).as_bytes())
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid": format!("{tag}-holder")}})],
        payload_ciphertext: format!("{tag}-payload").into_bytes(),
        ready_at,
        expires_at: ready_at + lifetime,
    }
}

async fn insert_openid4vc_subject(
    pool: &nazo_postgres::DbPool,
    tenant_id: Uuid,
    tag: &str,
) -> Uuid {
    let (_, realm_id, organization_id) = openid4vc_boundary_ids();
    let subject_id = Uuid::now_v7();
    let mut connection = get_conn(pool).await.unwrap();
    sql_query(
        "INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) \
         VALUES ($1,$2,$3,$4,$5,$6,'test')",
    )
    .bind::<SqlUuid, _>(subject_id)
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(realm_id)
    .bind::<SqlUuid, _>(organization_id)
    .bind::<Text, _>(format!("{tag}-{subject_id}"))
    .bind::<Text, _>(format!("{tag}-{subject_id}@example.test"))
    .execute(&mut connection)
    .await
    .unwrap();
    subject_id
}

/// Inserts an active OAuth client row under the shared test tenant and returns
/// its database uuid; the `client_id` column remains the public protocol id
/// that `persist_pre_authorized_access` re-verifies.
async fn insert_openid4vc_client(pool: &nazo_postgres::DbPool, client_id: &str) -> Uuid {
    let (tenant_id, realm_id, organization_id) = openid4vc_boundary_ids();
    let id = Uuid::now_v7();
    let mut connection = get_conn(pool).await.unwrap();
    sql_query(
        "INSERT INTO oauth_clients (\
             id, tenant_id, realm_id, organization_id, client_id, client_name, client_type, \
             redirect_uris, scopes, grant_types, token_endpoint_auth_method, security_policy) \
         VALUES ($1,$2,$3,$4,$5,'OpenID4VC persist test','public',\
             '[]'::jsonb,'[\"openid\"]'::jsonb,\
             '[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"]'::jsonb,'none',$6)",
    )
    .bind::<SqlUuid, _>(id)
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(realm_id)
    .bind::<SqlUuid, _>(organization_id)
    .bind::<Text, _>(client_id)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({
        "version": 1,
        "assurance": "baseline",
        "require_signed_authorization_request": false,
        "require_signed_authorization_response": false,
        "require_signed_introspection_response": false,
        "session_management": false,
        "allow_cross_device_flows": false,
        "allow_confidential_oidc_without_pkce": false
    }))
    .execute(&mut connection)
    .await
    .expect("test oauth client should insert");
    id
}

/// Removes the client plus its dependent revocation rows (deactivation writes
/// `access_token_revocations` that FK back to the client) and the subject,
/// whose delete cascades the access grants, deferred transactions and
/// notification rows created by the test.
async fn delete_openid4vc_subject_and_client(
    pool: &nazo_postgres::DbPool,
    subject_id: Uuid,
    client_uuid: Option<Uuid>,
) {
    let mut connection = get_conn(pool).await.unwrap();
    if let Some(client_uuid) = client_uuid {
        sql_query("DELETE FROM access_token_revocations WHERE client_id = $1")
            .bind::<SqlUuid, _>(client_uuid)
            .execute(&mut connection)
            .await
            .unwrap();
        sql_query("DELETE FROM oauth_clients WHERE id = $1")
            .bind::<SqlUuid, _>(client_uuid)
            .execute(&mut connection)
            .await
            .unwrap();
    }
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(subject_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[derive(QueryableByName)]
struct PersistedAccessGrantRow {
    #[diesel(sql_type = SqlUuid)]
    token_id: Uuid,
    #[diesel(sql_type = Text)]
    token_hash: String,
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    subject_id: Uuid,
    #[diesel(sql_type = Text)]
    client_id: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    credential_configuration_ids: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    credential_identifiers: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    dpop_jkt: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Text)]
    xmin: String,
}

async fn persisted_access_grant(
    pool: &nazo_postgres::DbPool,
    token_hash: &str,
) -> Option<PersistedAccessGrantRow> {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query(
        "SELECT token_id, token_hash, tenant_id, subject_id, client_id, \
                credential_configuration_ids, credential_identifiers, dpop_jkt, \
                expires_at, revoked_at, xmin::text AS xmin \
         FROM openid4vci_access_grants WHERE token_hash = $1",
    )
    .bind::<Text, _>(token_hash)
    .get_result::<PersistedAccessGrantRow>(&mut connection)
    .await
    .optional()
    .unwrap()
}

fn assert_persisted_access_grant(
    row: &PersistedAccessGrantRow,
    token_hash: &str,
    access: &CredentialAccess,
) {
    assert_eq!(row.token_id, access.token_id, "token_id must stay stable");
    assert_eq!(row.token_hash, token_hash);
    assert_eq!(
        row.tenant_id, access.tenant_id,
        "tenant_id must stay stable"
    );
    assert_eq!(
        row.subject_id, access.subject_id,
        "subject_id must stay stable"
    );
    assert_eq!(
        row.client_id, access.client_id,
        "client_id must stay stable"
    );
    assert_eq!(
        row.credential_configuration_ids,
        serde_json::json!(access.configuration_ids),
        "credential_configuration_ids projection mismatch"
    );
    assert_eq!(
        row.credential_identifiers,
        serde_json::json!(access.credential_identifiers),
        "credential_identifiers projection mismatch"
    );
    assert_eq!(row.dpop_jkt.as_deref(), access.dpop_jkt.as_deref());
    assert_eq!(
        row.expires_at.timestamp_micros(),
        access.expires_at.timestamp_micros()
    );
}

#[derive(QueryableByName)]
struct DeferredLeaseRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    claim_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    claim_expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
}

async fn deferred_lease_row(pool: &nazo_postgres::DbPool, deferred_id: Uuid) -> DeferredLeaseRow {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query(
        "SELECT claim_id, claim_expires_at, consumed_at \
         FROM openid4vci_deferred_transactions WHERE id = $1",
    )
    .bind::<SqlUuid, _>(deferred_id)
    .get_result::<DeferredLeaseRow>(&mut connection)
    .await
    .unwrap()
}

#[derive(QueryableByName)]
struct ClientActiveRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_active: bool,
}

#[derive(QueryableByName)]
struct TextValueRow {
    #[diesel(sql_type = Text)]
    value: String,
}

fn tagged_openid4vc_database_url(database_url: &str, application_name: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}application_name={application_name}")
}

async fn wait_for_openid4vc_lock_wait(connection: &mut AsyncPgConnection, application_name: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let blocked = sql_query(
            "SELECT COUNT(*)::bigint AS count \
             FROM pg_stat_activity \
             WHERE application_name = $1 AND wait_event_type = 'Lock'",
        )
        .bind::<Text, _>(application_name)
        .get_result::<CountRow>(connection)
        .await
        .expect("blocked PostgreSQL activity should be observable");
        if blocked.count > 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for lock wait from {application_name}");
}

async fn wait_for_openid4vc_lock_wait_or_task<T: std::fmt::Debug>(
    connection: &mut AsyncPgConnection,
    application_name: &str,
    task: &mut tokio::task::JoinHandle<T>,
) {
    tokio::select! {
        () = wait_for_openid4vc_lock_wait(connection, application_name) => {}
        result = task => panic!(
            "task ended before reaching a PostgreSQL lock wait from {application_name}: {result:?}"
        ),
    }
}

async fn wait_for_openid4vc_blocked_by_or_task<T: std::fmt::Debug>(
    connection: &mut AsyncPgConnection,
    waiter_application_name: &str,
    blocker_application_name: &str,
    task: &mut tokio::task::JoinHandle<T>,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let wait = async {
        while std::time::Instant::now() < deadline {
            let blocked = sql_query(
                "SELECT COUNT(*)::bigint AS count \
                 FROM pg_stat_activity AS waiter \
                 WHERE waiter.application_name = $1 \
                   AND waiter.wait_event_type = 'Lock' \
                   AND EXISTS ( \
                       SELECT 1 FROM pg_stat_activity AS blocker \
                       WHERE blocker.application_name = $2 \
                         AND blocker.pid = ANY (pg_blocking_pids(waiter.pid)))",
            )
            .bind::<Text, _>(waiter_application_name)
            .bind::<Text, _>(blocker_application_name)
            .get_result::<CountRow>(connection)
            .await
            .expect("blocking PostgreSQL activity should be observable");
            if blocked.count > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "timed out waiting for {waiter_application_name} to block on {blocker_application_name}"
        );
    };
    tokio::select! {
        () = wait => {}
        result = task => panic!(
            "task ended before {waiter_application_name} blocked on {blocker_application_name}: {result:?}"
        ),
    }
}

// VF-02: a registered client deactivated after the token request was
// authenticated must fail the grant persistence with ClientInactive, and no
// grant row may be written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pre_authorized_persist_rejects_a_client_deactivated_after_authentication() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-vf02").await;
    let client_id = format!("openid4vc-vf02-{}", Uuid::now_v7().simple());
    let client_uuid = insert_openid4vc_client(&pool, &client_id).await;

    let mut connection = get_conn(&pool).await.unwrap();
    let deactivated = connection
        .transaction::<bool, diesel::result::Error, _>(async |connection| {
            nazo_postgres::deactivate_client_on_connection(connection, tenant_id, client_uuid).await
        })
        .await
        .expect("client deactivation should commit");
    assert!(deactivated, "the seeded client must start active");
    drop(connection);

    let issuer = Openid4vciRepository::new(pool.clone(), [0x61_u8; 32]);
    let access = openid4vc_access_fixture(tenant_id, subject_id, &client_id, Duration::minutes(10));
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    assert_eq!(
        issuer
            .persist_pre_authorized_access(&token_hash, &access, Some(&client_id))
            .await,
        Err(CredentialStoreError::ClientInactive),
        "a registered client deactivated after authentication must fail closed"
    );
    assert!(
        persisted_access_grant(&pool, &token_hash).await.is_none(),
        "a rejected persist must not write the access grant"
    );

    delete_openid4vc_subject_and_client(&pool, subject_id, Some(client_uuid)).await;
}

// VF-03: the persist transaction re-verifies the registered client under a FOR
// SHARE row lock before writing the grant. A concurrent deactivation must wait
// for that transaction to commit; the committed deactivation then revokes the
// freshly written grant through its dependent-cleanup path, so no usable grant
// survives for a deactivated client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pre_authorized_persist_holds_the_client_lock_until_deactivation_wins() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-vf03").await;
    let client_id = format!("openid4vc-vf03-{}", Uuid::now_v7().simple());
    let client_uuid = insert_openid4vc_client(&pool, &client_id).await;

    let issuer = Openid4vciRepository::new(pool.clone(), [0x62_u8; 32]);
    let access = openid4vc_access_fixture(tenant_id, subject_id, &client_id, Duration::minutes(10));
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();

    // Gate connection: a SHARE table lock on the grants table blocks the
    // RowExclusive grant INSERT but not the client FOR SHARE check, so the
    // persist transaction is guaranteed to hold the client lock while waiting.
    let mut gate = AsyncPgConnection::establish(&database_url)
        .await
        .expect("gate connection should establish");
    gate.batch_execute("BEGIN; LOCK TABLE openid4vci_access_grants IN SHARE MODE")
        .await
        .expect("grant table gate should lock");

    let persist_name = format!("vci-persist-{}", Uuid::now_v7().simple());
    let persist_repository = Openid4vciRepository::new(
        create_pool(
            tagged_openid4vc_database_url(&database_url, &persist_name),
            1,
        )
        .unwrap(),
        [0x62_u8; 32],
    );
    let persist_access = access.clone();
    let persist_hash = token_hash.clone();
    let persist_client_id = client_id.clone();
    let mut persist_task = tokio::spawn(async move {
        persist_repository
            .persist_pre_authorized_access(&persist_hash, &persist_access, Some(&persist_client_id))
            .await
    });

    let mut observer = AsyncPgConnection::establish(&database_url)
        .await
        .expect("lock observer should connect");
    wait_for_openid4vc_lock_wait_or_task(&mut observer, &persist_name, &mut persist_task).await;

    // With the persist transaction parked on the grant INSERT (client FOR
    // SHARE already held), the real deactivation path must block on it.
    let deactivate_name = format!("vci-deactivate-{}", Uuid::now_v7().simple());
    let deactivate_url = tagged_openid4vc_database_url(&database_url, &deactivate_name);
    let mut deactivate_task = tokio::spawn(async move {
        let mut connection = AsyncPgConnection::establish(&deactivate_url)
            .await
            .expect("deactivation connection should establish");
        connection
            .transaction::<bool, diesel::result::Error, _>(async |connection| {
                nazo_postgres::deactivate_client_on_connection(connection, tenant_id, client_uuid)
                    .await
            })
            .await
    });
    wait_for_openid4vc_blocked_by_or_task(
        &mut observer,
        &deactivate_name,
        &persist_name,
        &mut deactivate_task,
    )
    .await;

    gate.batch_execute("COMMIT")
        .await
        .expect("the grant table gate should commit");

    tokio::time::timeout(std::time::Duration::from_secs(15), &mut persist_task)
        .await
        .expect("the persist task must finish once the gate commits")
        .expect("persist task should join")
        .expect("the client was still active inside the persist transaction");
    let deactivated =
        tokio::time::timeout(std::time::Duration::from_secs(15), &mut deactivate_task)
            .await
            .expect("the deactivation task must finish once the persist commits")
            .expect("deactivation task should join")
            .expect("deactivation transaction should commit");
    assert!(deactivated, "the registered client must deactivate");

    let mut connection = get_conn(&pool).await.unwrap();
    let client = sql_query("SELECT is_active FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(client_uuid)
        .get_result::<ClientActiveRow>(&mut connection)
        .await
        .unwrap();
    assert!(!client.is_active, "the committed deactivation must persist");
    drop(connection);

    let grant = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the committed persist must have written the grant");
    assert!(
        grant.revoked_at.is_some(),
        "client deactivation revokes committed grants as dependent cleanup"
    );
    assert!(
        issuer
            .resolve_access(&token_hash, Utc::now())
            .await
            .unwrap()
            .is_none(),
        "a revoked grant must not resolve"
    );

    delete_openid4vc_subject_and_client(&pool, subject_id, Some(client_uuid)).await;
}

// VF-04: an anonymous pre-authorized grant carries no registered client, so
// the persist path must not touch oauth_clients — it succeeds even when the
// access's client_id names an inactive client row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_pre_authorized_persist_never_reads_client_rows() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-vf04").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x63_u8; 32]);

    // The production anonymous fallback (offers.rs) resolves to the literal
    // "pre-authorized-wallet" client id with no registered client at all.
    let anonymous = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "pre-authorized-wallet",
        Duration::minutes(10),
    );
    let anonymous_hash = blake3::hash(anonymous.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer
        .persist_pre_authorized_access(&anonymous_hash, &anonymous, None)
        .await
        .expect("anonymous persist must not consult oauth_clients");
    let anonymous_row = persisted_access_grant(&pool, &anonymous_hash)
        .await
        .expect("the anonymous grant must persist");
    assert_persisted_access_grant(&anonymous_row, &anonymous_hash, &anonymous);

    // A grant whose access.client_id names an *inactive* registered client
    // still succeeds with registered_client_id = None, proving no lookup ran.
    let inactive_client_id = format!("openid4vc-vf04-{}", Uuid::now_v7().simple());
    let inactive_client_uuid = insert_openid4vc_client(&pool, &inactive_client_id).await;
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE oauth_clients SET is_active = FALSE WHERE id = $1")
        .bind::<SqlUuid, _>(inactive_client_uuid)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let mut impersonating = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        &inactive_client_id,
        Duration::minutes(10),
    );
    impersonating.token_id = Uuid::now_v7();
    let impersonating_hash = blake3::hash(impersonating.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer
        .persist_pre_authorized_access(&impersonating_hash, &impersonating, None)
        .await
        .expect(
            "registered_client_id = None must skip the client check even when \
             the access client id names an inactive client",
        );
    let impersonating_row = persisted_access_grant(&pool, &impersonating_hash)
        .await
        .expect("the anonymous grant must persist");
    assert_persisted_access_grant(&impersonating_row, &impersonating_hash, &impersonating);

    delete_openid4vc_subject_and_client(&pool, subject_id, Some(inactive_client_uuid)).await;
}

// VF-05: a mismatched registered client id is rejected before any SQL runs;
// a matching-but-inactive client is a distinct ClientInactive failure; a
// matching active client succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pre_authorized_persist_distinguishes_mismatched_and_inactive_clients() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-vf05").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x64_u8; 32]);

    let client_id = format!("openid4vc-vf05-{}", Uuid::now_v7().simple());

    // Mismatch: rejected before touching the database, so no client row is
    // needed and no grant may appear.
    let mismatch =
        openid4vc_access_fixture(tenant_id, subject_id, &client_id, Duration::minutes(10));
    let mismatch_hash = blake3::hash(mismatch.token_id.as_bytes())
        .to_hex()
        .to_string();
    assert_eq!(
        issuer
            .persist_pre_authorized_access(
                &mismatch_hash,
                &mismatch,
                Some("other-registered-client")
            )
            .await,
        Err(CredentialStoreError::InvalidTransition),
        "a registered client id that differs from the grant client must fail before SQL"
    );
    assert!(
        persisted_access_grant(&pool, &mismatch_hash)
            .await
            .is_none(),
        "a mismatched persist must not write the access grant"
    );

    // Matching-but-inactive: rejected by the FOR SHARE re-check.
    let inactive_uuid = insert_openid4vc_client(&pool, &client_id).await;
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE oauth_clients SET is_active = FALSE WHERE id = $1")
        .bind::<SqlUuid, _>(inactive_uuid)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let inactive =
        openid4vc_access_fixture(tenant_id, subject_id, &client_id, Duration::minutes(10));
    let inactive_hash = blake3::hash(inactive.token_id.as_bytes())
        .to_hex()
        .to_string();
    assert_eq!(
        issuer
            .persist_pre_authorized_access(&inactive_hash, &inactive, Some(&client_id))
            .await,
        Err(CredentialStoreError::ClientInactive),
        "a matching-but-inactive registered client must fail closed"
    );
    assert!(
        persisted_access_grant(&pool, &inactive_hash)
            .await
            .is_none(),
        "an inactive-client persist must not write the access grant"
    );

    // Positive control: a matching active client persists the grant.
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE oauth_clients SET is_active = TRUE WHERE id = $1")
        .bind::<SqlUuid, _>(inactive_uuid)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let active = openid4vc_access_fixture(tenant_id, subject_id, &client_id, Duration::minutes(10));
    let active_hash = blake3::hash(active.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer
        .persist_pre_authorized_access(&active_hash, &active, Some(&client_id))
        .await
        .expect("an active matching client must persist the grant");
    let active_row = persisted_access_grant(&pool, &active_hash)
        .await
        .expect("the grant must persist");
    assert_persisted_access_grant(&active_row, &active_hash, &active);

    delete_openid4vc_subject_and_client(&pool, subject_id, Some(inactive_uuid)).await;
}

// VF-07: the shared upsert body never touches revoked_at; a revoked grant
// stays revoked through both the plain upsert and the pre-authorized persist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_access_grants_stay_revoked_through_every_persist_path() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-vf07").await;
    let client_id = format!("openid4vc-vf07-{}", Uuid::now_v7().simple());
    let client_uuid = insert_openid4vc_client(&pool, &client_id).await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x65_u8; 32]);

    // Plain upsert path.
    let upserted =
        openid4vc_access_fixture(tenant_id, subject_id, &client_id, Duration::minutes(10));
    let upserted_hash = blake3::hash(upserted.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer
        .upsert_access(&upserted_hash, &upserted)
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_access_grants SET revoked_at = CURRENT_TIMESTAMP WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(upserted.token_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let mut mutated = upserted.clone();
    mutated.configuration_ids = vec!["pid".to_owned(), "alt".to_owned()];
    issuer
        .upsert_access(&upserted_hash, &mutated)
        .await
        .expect("the projection update on a revoked grant is still Ok");
    let row = persisted_access_grant(&pool, &upserted_hash)
        .await
        .expect("the grant row remains");
    assert!(
        row.revoked_at.is_some(),
        "the upsert must not resurrect a revoked grant"
    );
    assert!(
        issuer
            .resolve_access(&upserted_hash, Utc::now())
            .await
            .unwrap()
            .is_none()
    );

    // Pre-authorized persist path with a registered (still active) client.
    let persisted =
        openid4vc_access_fixture(tenant_id, subject_id, &client_id, Duration::minutes(10));
    let persisted_hash = blake3::hash(persisted.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer
        .persist_pre_authorized_access(&persisted_hash, &persisted, Some(&client_id))
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_access_grants SET revoked_at = CURRENT_TIMESTAMP WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(persisted.token_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let mut repersisted = persisted.clone();
    repersisted.dpop_jkt = Some("openid4vc-vf07-dpop-thumbprint".to_owned());
    issuer
        .persist_pre_authorized_access(&persisted_hash, &repersisted, Some(&client_id))
        .await
        .expect("the pre-authorized persist on a revoked grant is still Ok");
    let row = persisted_access_grant(&pool, &persisted_hash)
        .await
        .expect("the grant row remains");
    assert!(
        row.revoked_at.is_some(),
        "the pre-authorized persist must not resurrect a revoked grant"
    );
    assert_eq!(
        row.dpop_jkt.as_deref(),
        repersisted.dpop_jkt.as_deref(),
        "the mutable projection still updates"
    );

    delete_openid4vc_subject_and_client(&pool, subject_id, Some(client_uuid)).await;
}

// UP-01: an identical upsert is a successful no-op — the IS DISTINCT FROM
// guard must not create a new row version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_access_upsert_leaves_the_row_version_untouched() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-up01").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x66_u8; 32]);
    let access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-up01-wallet",
        Duration::minutes(10),
    );
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let before = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant must exist");
    issuer
        .upsert_access(&token_hash, &access)
        .await
        .expect("an identical upsert must succeed");
    let after = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant must remain");
    assert_eq!(
        after.xmin, before.xmin,
        "an identical upsert must not write a new row version"
    );
    assert_persisted_access_grant(&after, &token_hash, &access);
    assert!(after.revoked_at.is_none());

    issuer
        .upsert_access(&token_hash, &access)
        .await
        .expect("repeated identical upserts stay idempotent");
    let third = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant must remain");
    assert_eq!(third.xmin, before.xmin);

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// UP-02: each of the four mutable projection columns updates independently,
// including dpop_jkt NULL -> value -> NULL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_upsert_updates_each_mutable_projection_column() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-up02").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x67_u8; 32]);
    let mut access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-up02-wallet",
        Duration::minutes(10),
    );
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let mut previous = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant must exist");

    access.configuration_ids.push("alternate".to_owned());
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let row = persisted_access_grant(&pool, &token_hash).await.unwrap();
    assert_ne!(
        row.xmin, previous.xmin,
        "a changed credential_configuration_ids must write a new row version"
    );
    assert_persisted_access_grant(&row, &token_hash, &access);
    previous = row;

    access
        .credential_identifiers
        .push(nazo_openid4vci::CredentialIdentifier("pid-1".to_owned()));
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let row = persisted_access_grant(&pool, &token_hash).await.unwrap();
    assert_ne!(
        row.xmin, previous.xmin,
        "a changed credential_identifiers must write a new row version"
    );
    assert_persisted_access_grant(&row, &token_hash, &access);
    previous = row;

    access.dpop_jkt = Some("openid4vc-up02-dpop-thumbprint".to_owned());
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let row = persisted_access_grant(&pool, &token_hash).await.unwrap();
    assert_ne!(
        row.xmin, previous.xmin,
        "dpop_jkt NULL -> Some must write a new row version"
    );
    assert_persisted_access_grant(&row, &token_hash, &access);
    previous = row;

    access.dpop_jkt = None;
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let row = persisted_access_grant(&pool, &token_hash).await.unwrap();
    assert_ne!(
        row.xmin, previous.xmin,
        "dpop_jkt Some -> NULL must write a new row version"
    );
    assert_persisted_access_grant(&row, &token_hash, &access);
    previous = row;

    access.expires_at += Duration::minutes(5);
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let row = persisted_access_grant(&pool, &token_hash).await.unwrap();
    assert_ne!(
        row.xmin, previous.xmin,
        "a changed expires_at must write a new row version"
    );
    assert_persisted_access_grant(&row, &token_hash, &access);

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// UP-03: an upsert that loses the token_hash conflict but mismatches any
// persisted identity column is a no-op that still reports success — the
// discarded candidate row is never visible and its foreign keys are never
// checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_upsert_conflict_with_a_different_identity_is_a_noop() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-up03").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x68_u8; 32]);
    let access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-up03-wallet",
        Duration::minutes(10),
    );
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let original = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant must exist");

    let flips: Vec<(&str, CredentialAccess)> = vec![
        (
            "token_id",
            CredentialAccess {
                token_id: Uuid::now_v7(),
                ..access.clone()
            },
        ),
        (
            "tenant_id",
            CredentialAccess {
                tenant_id: Uuid::now_v7(),
                ..access.clone()
            },
        ),
        (
            "subject_id",
            CredentialAccess {
                subject_id: Uuid::now_v7(),
                ..access.clone()
            },
        ),
        (
            "client_id",
            CredentialAccess {
                client_id: format!("openid4vc-up03-other-{}", Uuid::now_v7().simple()),
                ..access.clone()
            },
        ),
    ];
    for (field, flipped) in flips {
        issuer
            .upsert_access(&token_hash, &flipped)
            .await
            .unwrap_or_else(|error| panic!("a {field} flip must still report success: {error}"));
        let row = persisted_access_grant(&pool, &token_hash)
            .await
            .expect("the original grant row must remain");
        assert_eq!(
            row.xmin, original.xmin,
            "a {field} flip must not update the persisted row"
        );
        assert_persisted_access_grant(&row, &token_hash, &access);
    }

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// UP-04: the update column list never names revoked_at, so a changed
// projection on a revoked grant cannot resurrect it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_upsert_preserves_the_revocation_marker() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-up04").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x69_u8; 32]);
    let access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-up04-wallet",
        Duration::minutes(10),
    );
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_access_grants SET revoked_at = CURRENT_TIMESTAMP WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(access.token_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let revoked = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant must exist");
    let revoked_at = revoked.revoked_at.expect("the grant must be revoked");

    let mut mutated = access.clone();
    mutated
        .credential_identifiers
        .push(nazo_openid4vci::CredentialIdentifier("pid-9".to_owned()));
    issuer
        .upsert_access(&token_hash, &mutated)
        .await
        .expect("a projection update on a revoked grant is still Ok");
    let row = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant row must remain");
    assert_eq!(
        row.revoked_at.map(|value| value.timestamp_micros()),
        Some(revoked_at.timestamp_micros()),
        "the upsert must not resurrect or rewrite the revocation marker"
    );
    assert_ne!(
        row.xmin, revoked.xmin,
        "the changed projection still produces an update"
    );
    assert!(
        issuer
            .resolve_access(&token_hash, Utc::now())
            .await
            .unwrap()
            .is_none()
    );

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// UP-05: persist_pre_authorized_access(None) is exactly the shared upsert body
// — it must produce the identical row shape as upsert_access.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_pre_authorized_persist_writes_the_upsert_row_shape() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-up05").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x6a_u8; 32]);

    let mut via_upsert = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-up05-wallet",
        Duration::minutes(10),
    );
    via_upsert
        .credential_identifiers
        .push(nazo_openid4vci::CredentialIdentifier("pid-1".to_owned()));
    via_upsert.dpop_jkt = Some("openid4vc-up05-dpop-thumbprint".to_owned());
    let upsert_hash = blake3::hash(via_upsert.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer
        .upsert_access(&upsert_hash, &via_upsert)
        .await
        .unwrap();

    let mut via_persist = via_upsert.clone();
    via_persist.token_id = Uuid::now_v7();
    let persist_hash = blake3::hash(via_persist.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer
        .persist_pre_authorized_access(&persist_hash, &via_persist, None)
        .await
        .unwrap();

    let upsert_row = persisted_access_grant(&pool, &upsert_hash)
        .await
        .expect("the upsert grant must exist");
    let persist_row = persisted_access_grant(&pool, &persist_hash)
        .await
        .expect("the persist grant must exist");
    assert_persisted_access_grant(&persist_row, &persist_hash, &via_persist);
    for (expected, actual) in [
        (upsert_row.tenant_id, persist_row.tenant_id),
        (upsert_row.subject_id, persist_row.subject_id),
    ] {
        assert_eq!(expected, actual);
    }
    assert_eq!(upsert_row.client_id, persist_row.client_id);
    assert_eq!(
        upsert_row.credential_configuration_ids,
        persist_row.credential_configuration_ids
    );
    assert_eq!(
        upsert_row.credential_identifiers,
        persist_row.credential_identifiers
    );
    assert_eq!(upsert_row.dpop_jkt, persist_row.dpop_jkt);
    assert_eq!(upsert_row.expires_at, persist_row.expires_at);
    assert!(persist_row.revoked_at.is_none());

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// UP-06: two concurrent identical upserts on separate pools both succeed, the
// row count stays one, and the existing row version is never rewritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_identical_access_upserts_are_noops() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-up06").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x6b_u8; 32]);
    let access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-up06-wallet",
        Duration::minutes(10),
    );
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();

    // Pre-existing row: both writers take the conflict path and must no-op.
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let before = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant must exist");
    let issuer_a = Openid4vciRepository::new(create_pool(&database_url, 1).unwrap(), [0x6b_u8; 32]);
    let issuer_b = Openid4vciRepository::new(create_pool(&database_url, 1).unwrap(), [0x6b_u8; 32]);
    let (first, second) = tokio::join!(
        issuer_a.upsert_access(&token_hash, &access),
        issuer_b.upsert_access(&token_hash, &access)
    );
    first.expect("first concurrent upsert must succeed without retry");
    second.expect("second concurrent upsert must succeed without retry");
    let after = persisted_access_grant(&pool, &token_hash)
        .await
        .expect("the grant must remain");
    assert_eq!(
        after.xmin, before.xmin,
        "concurrent identical upserts must not rewrite the row"
    );
    assert_persisted_access_grant(&after, &token_hash, &access);

    // Fresh row: the speculative-insert race still yields exactly one row.
    let fresh = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-up06-wallet",
        Duration::minutes(10),
    );
    let fresh_hash = blake3::hash(fresh.token_id.as_bytes()).to_hex().to_string();
    let (first, second) = tokio::join!(
        issuer_a.upsert_access(&fresh_hash, &fresh),
        issuer_b.upsert_access(&fresh_hash, &fresh)
    );
    first.expect("first racing insert must succeed without retry");
    second.expect("second racing insert must succeed without retry");
    let mut connection = get_conn(&pool).await.unwrap();
    let count = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants WHERE token_hash = $1",
    )
    .bind::<Text, _>(&fresh_hash)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        count.count, 1,
        "the racing upserts must persist exactly one row"
    );
    drop(connection);
    let fresh_row = persisted_access_grant(&pool, &fresh_hash)
        .await
        .expect("the raced grant must exist");
    assert_persisted_access_grant(&fresh_row, &fresh_hash, &fresh);

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// DF-01: the claim returns the deferred and joined access domain data in one
// statement and writes the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_claim_returns_joined_domain_state_and_writes_the_lease() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-df01").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x6c_u8; 32]);
    let mut access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-df01-wallet",
        Duration::minutes(30),
    );
    access.configuration_ids.push("secondary".to_owned());
    access
        .credential_identifiers
        .push(nazo_openid4vci::CredentialIdentifier("pid-1".to_owned()));
    access.dpop_jkt = Some("openid4vc-df01-dpop-thumbprint".to_owned());
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let deferred = openid4vc_deferred_fixture(
        &access,
        "openid4vc-df01",
        Duration::seconds(1),
        Duration::minutes(30),
    );
    issuer.store_deferred(&deferred).await.unwrap();

    let claim_now = deferred.ready_at;
    let claim = issuer
        .claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "df01-claim",
            claim_now,
        )
        .await
        .unwrap()
        .expect("a ready deferred transaction must be claimable");
    assert_eq!(claim.claim_id, "df01-claim");
    assert_eq!(
        claim.credential, deferred,
        "the claim must return the full domain row"
    );

    let lease = deferred_lease_row(&pool, deferred.id).await;
    assert_eq!(lease.claim_id.as_deref(), Some("df01-claim"));
    assert_eq!(
        lease
            .claim_expires_at
            .expect("the lease must record its expiry")
            .timestamp(),
        (claim_now + Duration::minutes(5)).timestamp(),
        "the claim lease is five minutes from the supplied clock"
    );
    assert!(lease.consumed_at.is_none());

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// DF-02: every non-claimable branch returns None and leaves the row untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_claim_rejects_unclaimable_rows_without_leasing() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-df02").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x6d_u8; 32]);
    let access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-df02-wallet",
        Duration::minutes(30),
    );
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();

    // Unknown transaction hash.
    assert!(
        issuer
            .claim_ready_deferred(
                blake3::hash(b"openid4vc-df02-missing").to_hex().as_ref(),
                access.token_id,
                "missing",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none()
    );

    // ready_at still in the future.
    let unready = openid4vc_deferred_fixture(
        &access,
        "openid4vc-df02-unready",
        Duration::seconds(30),
        Duration::minutes(30),
    );
    issuer.store_deferred(&unready).await.unwrap();
    assert!(
        issuer
            .claim_ready_deferred(
                &unready.transaction_hash,
                access.token_id,
                "early",
                Utc::now()
            )
            .await
            .unwrap()
            .is_none(),
        "a not-yet-ready deferred must not be claimable"
    );
    let lease = deferred_lease_row(&pool, unready.id).await;
    assert!(lease.claim_id.is_none() && lease.claim_expires_at.is_none());
    assert!(lease.consumed_at.is_none());

    // expires_at in the past relative to the supplied clock.
    let expired = openid4vc_deferred_fixture(
        &access,
        "openid4vc-df02-expired",
        Duration::seconds(1),
        Duration::seconds(10),
    );
    issuer.store_deferred(&expired).await.unwrap();
    assert!(
        issuer
            .claim_ready_deferred(
                &expired.transaction_hash,
                access.token_id,
                "late",
                expired.expires_at + Duration::seconds(1),
            )
            .await
            .unwrap()
            .is_none(),
        "an expired deferred must not be claimable"
    );
    let lease = deferred_lease_row(&pool, expired.id).await;
    assert!(lease.claim_id.is_none() && lease.claim_expires_at.is_none());
    assert!(lease.consumed_at.is_none());

    // Already claimed and still inside its lease.
    let leased = openid4vc_deferred_fixture(
        &access,
        "openid4vc-df02-leased",
        Duration::seconds(1),
        Duration::minutes(30),
    );
    issuer.store_deferred(&leased).await.unwrap();
    assert!(
        issuer
            .claim_ready_deferred(
                &leased.transaction_hash,
                access.token_id,
                "first-owner",
                leased.ready_at,
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &leased.transaction_hash,
                access.token_id,
                "second-owner",
                leased.ready_at + Duration::minutes(1),
            )
            .await
            .unwrap()
            .is_none(),
        "a live lease must reject a competing claimant"
    );
    let lease = deferred_lease_row(&pool, leased.id).await;
    assert_eq!(lease.claim_id.as_deref(), Some("first-owner"));

    // Already consumed.
    let consumed = openid4vc_deferred_fixture(
        &access,
        "openid4vc-df02-consumed",
        Duration::seconds(1),
        Duration::minutes(30),
    );
    issuer.store_deferred(&consumed).await.unwrap();
    assert!(
        issuer
            .claim_ready_deferred(
                &consumed.transaction_hash,
                access.token_id,
                "consumer",
                consumed.ready_at,
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        issuer
            .finalize_deferred(
                &consumed.transaction_hash,
                access.token_id,
                "consumer",
                consumed.ready_at,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &consumed.transaction_hash,
                access.token_id,
                "replay",
                consumed.ready_at,
            )
            .await
            .unwrap()
            .is_none(),
        "a consumed deferred must not be claimable"
    );
    let lease = deferred_lease_row(&pool, consumed.id).await;
    assert!(lease.claim_id.is_none() && lease.claim_expires_at.is_none());
    assert!(lease.consumed_at.is_some());

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// DF-03: concurrent claimants on one deferred row get exactly one winner; once
// the winner's lease expires the loser can claim it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_deferred_claims_lease_to_one_owner() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-df03").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x6e_u8; 32]);
    let access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-df03-wallet",
        Duration::minutes(60),
    );
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let deferred = openid4vc_deferred_fixture(
        &access,
        "openid4vc-df03",
        Duration::seconds(1),
        Duration::minutes(30),
    );
    issuer.store_deferred(&deferred).await.unwrap();

    let claim_now = deferred.ready_at;
    let issuer_a = Openid4vciRepository::new(create_pool(&database_url, 1).unwrap(), [0x6e_u8; 32]);
    let issuer_b = Openid4vciRepository::new(create_pool(&database_url, 1).unwrap(), [0x6e_u8; 32]);
    let (claim_a, claim_b) = tokio::join!(
        issuer_a.claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "df03-a",
            claim_now,
        ),
        issuer_b.claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "df03-b",
            claim_now,
        ),
    );
    let claim_a = claim_a.expect("claimant a must not error");
    let claim_b = claim_b.expect("claimant b must not error");
    let winners = [&claim_a, &claim_b]
        .iter()
        .filter(|claim| claim.is_some())
        .count();
    assert_eq!(
        winners, 1,
        "exactly one concurrent claimant must win the lease"
    );
    if let Some(claim) = &claim_a {
        assert_eq!(claim.claim_id, "df03-a");
    }
    if let Some(claim) = &claim_b {
        assert_eq!(claim.claim_id, "df03-b");
    }

    // The lease expires five minutes after claim_now; a later clock lets the
    // losing claimant (or any retry) reclaim without sleeping.
    let reclaim_now = claim_now + Duration::minutes(6);
    let reclaim = issuer
        .claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "df03-reclaim",
            reclaim_now,
        )
        .await
        .unwrap()
        .expect("an expired lease must be reclaimable");
    assert_eq!(reclaim.claim_id, "df03-reclaim");
    let lease = deferred_lease_row(&pool, deferred.id).await;
    assert_eq!(lease.claim_id.as_deref(), Some("df03-reclaim"));

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// DF-04: the join used by deferred_claim_ready is guaranteed by the schema —
// deferred.token_id is NOT NULL, FKs to openid4vci_access_grants(token_id)
// with ON DELETE CASCADE, and access.token_id is the primary key. No orphan
// fixtures: the schema forbids them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_access_join_is_guaranteed_by_the_schema() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 1).unwrap();
    let mut connection = get_conn(&pool).await.unwrap();

    let nullable = sql_query(
        "SELECT is_nullable AS value FROM information_schema.columns \
         WHERE table_schema = current_schema() \
           AND table_name = 'openid4vci_deferred_transactions' AND column_name = 'token_id'",
    )
    .get_result::<TextValueRow>(&mut connection)
    .await
    .expect("the deferred token_id column must exist");
    assert_eq!(nullable.value, "NO", "deferred.token_id must be NOT NULL");

    let delete_rule = sql_query(
        "SELECT rc.delete_rule AS value \
         FROM information_schema.referential_constraints rc \
         JOIN information_schema.key_column_usage kcu \
           ON kcu.constraint_name = rc.constraint_name \
          AND kcu.constraint_schema = rc.constraint_schema \
         JOIN information_schema.constraint_column_usage ccu \
           ON ccu.constraint_name = rc.unique_constraint_name \
          AND ccu.constraint_schema = rc.unique_constraint_schema \
         WHERE kcu.table_schema = current_schema() \
           AND kcu.table_name = 'openid4vci_deferred_transactions' \
           AND kcu.column_name = 'token_id' \
           AND ccu.table_name = 'openid4vci_access_grants' \
           AND ccu.column_name = 'token_id'",
    )
    .get_result::<TextValueRow>(&mut connection)
    .await
    .expect("the deferred token_id foreign key must exist");
    assert_eq!(delete_rule.value, "CASCADE", "the FK must cascade deletes");

    let primary_key = sql_query(
        "SELECT COUNT(*)::bigint AS count \
         FROM information_schema.table_constraints tc \
         JOIN information_schema.key_column_usage kcu \
           ON kcu.constraint_name = tc.constraint_name \
          AND kcu.constraint_schema = tc.constraint_schema \
         WHERE tc.table_schema = current_schema() \
           AND tc.table_name = 'openid4vci_access_grants' \
           AND tc.constraint_type = 'PRIMARY KEY' AND kcu.column_name = 'token_id'",
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        primary_key.count, 1,
        "access_grants.token_id must be the primary key so the join is unique"
    );
    drop(connection);
}

// DF-05: a corrupt payload fails the claim with an error, and the lease write
// inside the same transaction is rolled back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_deferred_payload_rolls_back_the_claim_lease() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-df05").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x6f_u8; 32]);
    let access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-df05-wallet",
        Duration::minutes(30),
    );
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let deferred = openid4vc_deferred_fixture(
        &access,
        "openid4vc-df05",
        Duration::seconds(1),
        Duration::minutes(30),
    );
    issuer.store_deferred(&deferred).await.unwrap();

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE openid4vci_deferred_transactions SET payload_ciphertext = $2 WHERE id = $1")
        .bind::<SqlUuid, _>(deferred.id)
        .bind::<Binary, _>(b"not-a-valid-aead-frame".to_vec())
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);

    assert_eq!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "df05-claim",
                deferred.ready_at,
            )
            .await,
        Err(CredentialStoreError::Unavailable),
        "a corrupt payload must fail the whole claim"
    );
    let lease = deferred_lease_row(&pool, deferred.id).await;
    assert!(
        lease.claim_id.is_none() && lease.claim_expires_at.is_none(),
        "the lease write must roll back with the failed decode"
    );
    assert!(lease.consumed_at.is_none());

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}

// DF-06: a NULL dpop_jkt access column is legal — the claim decodes it back to
// None; the remaining access columns are NOT NULL by construction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_claim_supports_grants_without_dpop_binding() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let (tenant_id, ..) = openid4vc_boundary_ids();
    let subject_id = insert_openid4vc_subject(&pool, tenant_id, "openid4vc-df06").await;
    let issuer = Openid4vciRepository::new(pool.clone(), [0x70_u8; 32]);
    let access = openid4vc_access_fixture(
        tenant_id,
        subject_id,
        "openid4vc-df06-wallet",
        Duration::minutes(30),
    );
    assert!(access.dpop_jkt.is_none());
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    let deferred = openid4vc_deferred_fixture(
        &access,
        "openid4vc-df06",
        Duration::seconds(1),
        Duration::minutes(30),
    );
    issuer.store_deferred(&deferred).await.unwrap();

    let claim = issuer
        .claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "df06-claim",
            deferred.ready_at,
        )
        .await
        .unwrap()
        .expect("a NULL dpop_jkt grant must not block the deferred claim");
    assert!(claim.credential.access.dpop_jkt.is_none());
    assert_eq!(claim.credential.access, access);

    delete_openid4vc_subject_and_client(&pool, subject_id, None).await;
}
