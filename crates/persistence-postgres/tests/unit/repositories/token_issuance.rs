use super::*;
use nazo_auth::TokenIssuedAuditFields;

fn context<'a>(
    issuance_id: Uuid,
    tenant_id: Uuid,
    client_id: Uuid,
    digest: &'a str,
    envelope_version: &'a str,
    key_id: &'a str,
) -> ResponseEnvelopeContext<'a> {
    ResponseEnvelopeContext {
        issuance_id,
        tenant_id,
        client_id,
        grant_key_hash: "grant-hash",
        response_digest: digest,
        envelope_version,
        key_id,
    }
}

fn row() -> TokenIssuanceRow {
    let now = Utc::now();
    TokenIssuanceRow {
        issuance_id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: None,
        grant_key_blake3: "grant-hash".to_owned(),
        request_digest: "request-digest".to_owned(),
        access_token_jti: None,
        access_token_expires_at: None,
        response_ciphertext: None,
        response_digest: None,
        response_envelope_version: None,
        response_key_id: None,
        expires_at: now + chrono::Duration::minutes(5),
        created_at: now,
        updated_at: now,
    }
}

fn row_with_response(
    ring: &TokenIssuanceResponseKeyRing,
    body: &[u8],
    digest: &str,
) -> TokenIssuanceRow {
    let mut row = row();
    row.access_token_jti = Some("jti".to_owned());
    row.access_token_expires_at = Some(Utc::now() + chrono::Duration::minutes(1));
    let envelope_context = context(
        row.issuance_id,
        row.tenant_id,
        row.client_id,
        digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );
    row.response_ciphertext = Some(
        seal_response(Some(ring), &envelope_context, body).expect("response seals successfully"),
    );
    row.response_digest = Some(digest.to_owned());
    row.response_envelope_version = Some(TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION.to_owned());
    row.response_key_id = Some(ring.current_id().to_owned());
    row
}

fn valid_commit_input(
    mode: TokenIssuanceMode,
    response_body: Option<Vec<u8>>,
) -> CommitTokenIssuance {
    CommitTokenIssuance {
        issuance_id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: Some(Uuid::now_v7()),
        mode,
        request_digest: "a".repeat(64),
        access_token_jti: "access-jti".to_owned(),
        access_token_expires_at: (Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        response_body,
        refresh_token: None,
        audit_fields: TokenIssuedAuditFields {
            client_id: "client".to_owned(),
            subject_hash: "subject-hash".to_owned(),
            scope: "openid".to_owned(),
            audience: vec!["resource".to_owned()],
        },
    }
}

fn existing_record(request_digest: &str, response_body: Option<&[u8]>) -> TokenIssuanceRecord {
    TokenIssuanceRecord {
        issuance_id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: None,
        grant_key: "grant-hash".to_owned(),
        request_digest: request_digest.to_owned(),
        access_token_jti: Some("jti".to_owned()),
        access_token_expires_at: Some((Utc::now() + chrono::Duration::minutes(1)).timestamp()),
        response_body: response_body.map(ToOwned::to_owned),
        response_digest: None,
        response_key_version: None,
    }
}

#[test]
fn response_envelope_round_trips_with_current_key_and_separate_format() {
    let ring = TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None)
        .expect("current key ring is valid");
    let issuance_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let body = br#"{"access_token":"opaque"}"#;
    let digest = blake3::hash(body).to_hex().to_string();
    let base_context = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );

    let protected = seal_response(Some(&ring), &base_context, body).expect("encryption succeeds");
    assert_eq!(
        unseal_response(&ring, &base_context, &protected).expect("decryption succeeds"),
        body
    );
    assert_eq!(base_context.envelope_version, "v1");
    assert_eq!(base_context.key_id, "current");
    assert_ne!(&protected[..RESPONSE_NONCE_LEN], body);
}

#[test]
fn previous_key_decrypts_but_removed_key_fails_closed() {
    let previous_id = "previous".to_owned();
    let rotating_ring = TokenIssuanceResponseKeyRing::new(
        "current",
        [0x22; 32],
        Some((previous_id.clone(), [0x11; 32])),
    )
    .expect("rotating key ring is valid");
    let issuance_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let body = b"previously encrypted response";
    let digest = blake3::hash(body).to_hex().to_string();
    let context = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        &previous_id,
    );
    let protected = seal_response(Some(&rotating_ring), &context, body)
        .expect("encryption with current key succeeds");

    // The helper intentionally only emits current-key envelopes. Re-encrypt
    // with the previous key directly to model a row written before rotation.
    let previous_key = rotating_ring
        .key_for(&previous_id)
        .expect("previous key is in the overlap ring");
    let cipher = Aes256Gcm::new_from_slice(previous_key).expect("key is valid");
    let mut nonce = [0_u8; RESPONSE_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: body,
                aad: &response_aad(&context),
            },
        )
        .expect("previous-key encryption succeeds");
    let mut previous_protected = vec![TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE];
    previous_protected.extend_from_slice(&nonce);
    previous_protected.extend_from_slice(&ciphertext);

    assert_eq!(
        unseal_response(&rotating_ring, &context, &previous_protected)
            .expect("previous key remains decryptable"),
        body
    );
    let retired_ring = TokenIssuanceResponseKeyRing::new("current", [0x22; 32], None)
        .expect("retired ring is valid");
    assert!(matches!(
        unseal_response(&retired_ring, &context, &previous_protected),
        Err(RepositoryError::Consistency(_))
    ));
    // Avoid allowing a test helper to accidentally regress current-key use.
    assert_ne!(protected, previous_protected);
}

#[test]
fn unknown_format_and_unknown_key_are_rejected() {
    let ring = TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None)
        .expect("current key ring is valid");
    let body = b"response";
    let digest = blake3::hash(body).to_hex().to_string();
    let issuance_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let current_context = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );
    let protected =
        seal_response(Some(&ring), &current_context, body).expect("encryption succeeds");
    let unknown_version = context(issuance_id, tenant_id, client_id, &digest, "v2", "current");
    assert!(matches!(
        unseal_response(&ring, &unknown_version, &protected),
        Err(RepositoryError::Consistency(_))
    ));
    let unknown_key = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        "retired",
    );
    assert!(matches!(
        unseal_response(&ring, &unknown_key, &protected),
        Err(RepositoryError::Consistency(_))
    ));
}

#[test]
fn key_ring_rejects_empty_long_and_duplicate_ids() {
    assert!(matches!(
        TokenIssuanceResponseKeyRing::new("", [0; 32], None),
        Err(TokenIssuanceResponseKeyError::EmptyId)
    ));
    assert!(matches!(
        TokenIssuanceResponseKeyRing::new("   ", [0; 32], None),
        Err(TokenIssuanceResponseKeyError::EmptyId)
    ));
    assert!(matches!(
        TokenIssuanceResponseKeyRing::new(
            "current",
            [0; 32],
            Some(("current".to_owned(), [1; 32]))
        ),
        Err(TokenIssuanceResponseKeyError::DuplicateId)
    ));
    assert!(matches!(
        TokenIssuanceResponseKeyRing::new("x".repeat(129), [0; 32], None),
        Err(TokenIssuanceResponseKeyError::IdTooLong)
    ));
}

#[test]
fn response_key_ring_preflight_rejects_unsupported_metadata() {
    let ring = TokenIssuanceResponseKeyRing::new(
        "current",
        [0x11; 32],
        Some(("previous".to_owned(), [0x22; 32])),
    )
    .expect("key ring is valid");
    assert!(
        validate_response_key_metadata(
            &ring,
            [
                (Some("current".to_owned()), Some("v1".to_owned())),
                (Some("previous".to_owned()), Some("v1".to_owned())),
            ],
        )
        .is_ok()
    );
    assert!(matches!(
        validate_response_key_metadata(
            &ring,
            [(Some("retired".to_owned()), Some("v1".to_owned()))],
        ),
        Err(RepositoryError::Consistency(message)) if message.contains("retired")
    ));
    assert!(matches!(
        validate_response_key_metadata(&ring, [(None, Some("v1".to_owned()))]),
        Err(RepositoryError::Consistency(message)) if message.contains("missing")
    ));
    assert!(matches!(
        validate_response_key_metadata(
            &ring,
            [(Some("current".to_owned()), Some("v2".to_owned()))],
        ),
        Err(RepositoryError::Consistency(message)) if message.contains("unsupported")
    ));
    assert!(matches!(
        validate_response_key_metadata(&ring, [(Some("current".to_owned()), None)]),
        Err(RepositoryError::Consistency(message)) if message.contains("missing")
    ));
}

#[test]
fn response_key_ring_preflight_ignores_corrupt_response_body() {
    let ring = TokenIssuanceResponseKeyRing::new("current", rand::random::<[u8; 32]>(), None)
        .expect("key ring is valid");
    let body = b"response";
    let digest = blake3::hash(body).to_hex().to_string();
    let mut corrupted = row_with_response(&ring, body, &digest);
    let ciphertext = corrupted
        .response_ciphertext
        .as_mut()
        .expect("response ciphertext is present");
    *ciphertext
        .last_mut()
        .expect("response ciphertext is non-empty") ^= 1;

    assert!(
        validate_response_key_metadata(
            &ring,
            [(
                corrupted.response_key_id.clone(),
                corrupted.response_envelope_version.clone(),
            )],
        )
        .is_ok()
    );
    assert!(matches!(
        corrupted.into_record(Some(&ring)),
        Err(RepositoryError::Consistency(message)) if message.contains("authentication")
    ));
}

#[test]
fn key_ring_display_debug_and_lookup_do_not_expose_key_material() {
    let ring = TokenIssuanceResponseKeyRing::new(
        "current",
        [0x11; 32],
        Some(("previous".to_owned(), [0x22; 32])),
    )
    .expect("key ring is valid");

    assert_eq!(ring.current_id(), "current");
    assert!(ring.key_for("current").is_some());
    assert!(ring.key_for("previous").is_some());
    assert!(ring.key_for("retired").is_none());
    let debug = format!("{ring:?}");
    assert!(debug.contains("current"));
    assert!(debug.contains("previous"));
    assert!(!debug.contains("11".repeat(32).as_str()));

    assert_eq!(
        TokenIssuanceResponseKeyError::EmptyId.to_string(),
        "token issuance response encryption key id must not be empty"
    );
    assert_eq!(
        TokenIssuanceResponseKeyError::IdTooLong.to_string(),
        "token issuance response encryption key id must be at most 128 bytes"
    );
    assert_eq!(
        TokenIssuanceResponseKeyError::DuplicateId.to_string(),
        "token issuance response current and previous key ids must differ"
    );
}

#[test]
fn issuance_rows_preserve_sealed_response_state() {
    let ring =
        TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None).expect("key ring is valid");
    let body = b"signed response";
    let digest = blake3::hash(body).to_hex().to_string();

    let prepared = row()
        .into_record(None)
        .expect("row has no response envelope");
    assert!(prepared.response_body.is_none());

    let record = row_with_response(&ring, body, &digest)
        .into_record(Some(&ring))
        .expect("sealed response row is valid");
    assert_eq!(record.response_body.as_deref(), Some(body.as_slice()));
    assert_eq!(record.response_digest.as_deref(), Some(digest.as_str()));
    assert_eq!(record.response_key_version.as_deref(), Some("v1"));
}

#[test]
fn expired_response_preserves_terminal_metadata_without_recovering_credentials() {
    let ring = TokenIssuanceResponseKeyRing::new("current", rand::random(), None).unwrap();
    let body = b"signed response";
    let digest = blake3::hash(body).to_hex().to_string();
    for expires_at in [Utc::now(), Utc::now() - chrono::Duration::seconds(1)] {
        let mut expired = row_with_response(&ring, body, &digest);
        expired.access_token_expires_at = Some(expires_at);
        expired.response_key_id = Some("retired".to_owned());
        expired.response_ciphertext = Some(vec![0]);
        let record = expired.into_record(None).unwrap();
        assert!(record.response_body.is_none());
        assert_eq!(record.access_token_jti.as_deref(), Some("jti"));
        assert_eq!(record.access_token_expires_at, Some(expires_at.timestamp()));
        assert_eq!(record.response_digest.as_deref(), Some(digest.as_str()));
    }
}

#[test]
fn issuance_rows_reject_incomplete_or_inconsistent_response_envelopes() {
    let ring =
        TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None).expect("key ring is valid");
    let body = b"response";
    let digest = blake3::hash(body).to_hex().to_string();

    let missing_envelope = row();
    assert!(missing_envelope.into_record(None).is_ok());

    let mut incomplete = row();
    incomplete.response_ciphertext = Some(vec![1, 2, 3]);
    assert!(matches!(
        incomplete.into_record(None),
        Err(RepositoryError::Consistency(message)) if message.contains("incomplete")
    ));

    let mut unsupported = row_with_response(&ring, body, &digest);
    unsupported.response_envelope_version = Some("v2".to_owned());
    assert!(matches!(
        unsupported.into_record(Some(&ring)),
        Err(RepositoryError::Consistency(message)) if message.contains("unsupported")
    ));

    let no_keys = row_with_response(&ring, body, &digest);
    assert!(matches!(
        no_keys.into_record(None),
        Err(RepositoryError::Consistency(message)) if message.contains("not configured")
    ));

    let mut missing_expiry = row();
    missing_expiry.access_token_jti = Some("jti".to_owned());
    assert!(matches!(
        missing_expiry.into_record(None),
        Err(RepositoryError::Consistency(message)) if message.contains("JTI and expiry")
    ));

    let mut missing_jti = row();
    missing_jti.access_token_expires_at = Some(Utc::now());
    assert!(matches!(
        missing_jti.into_record(None),
        Err(RepositoryError::Consistency(message)) if message.contains("JTI and expiry")
    ));

    let mut envelope_without_access_token = row_with_response(&ring, body, &digest);
    envelope_without_access_token.access_token_jti = None;
    envelope_without_access_token.access_token_expires_at = None;
    assert!(matches!(
        envelope_without_access_token.into_record(Some(&ring)),
        Err(RepositoryError::Consistency(message)) if message.contains("unsupported")
    ));
}

#[test]
fn commit_input_validation_enforces_mode_ownership_and_expiry_contracts() {
    let fresh = valid_commit_input(TokenIssuanceMode::Fresh, None);
    assert!(validate_commit_input(&fresh, "ephemeral").is_ok());

    let single = valid_commit_input(
        TokenIssuanceMode::SingleUse {
            grant_key: "grant".to_owned(),
        },
        None,
    );
    assert!(validate_commit_input(&single, "grant").is_ok());

    let idempotent = valid_commit_input(
        TokenIssuanceMode::Idempotent {
            grant_key: "grant".to_owned(),
        },
        Some(b"{}".to_vec()),
    );
    assert!(validate_commit_input(&idempotent, "grant").is_ok());

    for malformed in [
        {
            let mut value = fresh.clone();
            value.issuance_id = Uuid::nil();
            value
        },
        {
            let mut value = fresh.clone();
            value.request_digest = "A".repeat(64);
            value
        },
        {
            let mut value = fresh.clone();
            value.access_token_jti.clear();
            value
        },
    ] {
        assert!(matches!(
            validate_commit_input(&malformed, "grant"),
            Err(RepositoryError::Consistency(message)) if message.contains("malformed")
        ));
    }

    let mut missing_response = idempotent.clone();
    missing_response.response_body = None;
    assert!(matches!(
        validate_commit_input(&missing_response, "grant"),
        Err(RepositoryError::Consistency(message)) if message.contains("requires a response")
    ));

    let mut empty_idempotency_key = idempotent.clone();
    empty_idempotency_key.mode = TokenIssuanceMode::Idempotent {
        grant_key: " ".to_owned(),
    };
    assert!(matches!(
        validate_commit_input(&empty_idempotency_key, "grant"),
        Err(RepositoryError::Consistency(message)) if message.contains("grant key is empty")
    ));

    let mut non_idempotent_body = fresh.clone();
    non_idempotent_body.response_body = Some(b"{}".to_vec());
    assert!(matches!(
        validate_commit_input(&non_idempotent_body, "grant"),
        Err(RepositoryError::Consistency(message)) if message.contains("cannot persist")
    ));

    let mut wrong_owner = idempotent.clone();
    wrong_owner.refresh_token = Some(NewRefreshToken {
        raw_token: "refresh".to_owned(),
        tenant_id: Uuid::now_v7(),
        family_id: Uuid::now_v7(),
        rotated_from_id: None,
        lost_response_retry: None,
        client_id: wrong_owner.client_id,
        user_id: wrong_owner.user_id,
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
    });
    wrong_owner.refresh_token.as_mut().unwrap().tenant_id = Uuid::now_v7();
    assert!(matches!(
        validate_commit_input(&wrong_owner, "grant"),
        Err(RepositoryError::Consistency(message)) if message.contains("owner")
    ));

    let mut invalid_expiry = idempotent;
    invalid_expiry.access_token_expires_at = i64::MAX;
    assert!(matches!(
        validate_commit_input(&invalid_expiry, "grant"),
        Err(RepositoryError::Consistency(message)) if message.contains("expiry")
    ));
}

#[test]
fn response_material_and_audit_events_cover_current_and_refresh_shapes() {
    let ring = TokenIssuanceResponseKeyRing::new("current", rand::random::<[u8; 32]>(), None)
        .expect("key ring is valid");
    let no_body = valid_commit_input(TokenIssuanceMode::Fresh, None);
    assert_eq!(
        response_material(Some(&ring), &no_body, "grant-hash").expect("no body is valid"),
        (None, None, None, None)
    );

    let with_body = valid_commit_input(
        TokenIssuanceMode::Idempotent {
            grant_key: "grant".to_owned(),
        },
        Some(b"response".to_vec()),
    );
    assert!(matches!(
        response_material(None, &with_body, "grant-hash"),
        Err(RepositoryError::Unavailable)
    ));
    let material = response_material(Some(&ring), &with_body, "grant-hash")
        .expect("response body should seal");
    assert!(material.0.is_some());
    assert_eq!(material.2.as_deref(), Some("v1"));
    assert_eq!(material.3.as_deref(), Some("current"));
    let response_digest = material.1.as_deref().expect("response digest is present");
    let response_context = context(
        with_body.issuance_id,
        with_body.tenant_id,
        with_body.client_id,
        response_digest,
        material.2.as_deref().expect("envelope version is present"),
        material.3.as_deref().expect("key id is present"),
    );
    assert_eq!(
        unseal_response(
            &ring,
            &response_context,
            material.0.as_deref().expect("ciphertext is present"),
        )
        .expect("response material should decrypt"),
        b"response"
    );

    let issued = token_issued_audit_event(&with_body, None);
    assert_eq!(issued.event_type, "token_issued");
    assert_eq!(issued.event_category, "token_lifecycle");
    assert_eq!(
        issued.payload["tenant_id"],
        serde_json::json!(with_body.tenant_id)
    );
    assert_eq!(
        issued.payload["issuance_id"],
        serde_json::json!(with_body.issuance_id)
    );
    assert_eq!(
        issued.payload["access_token_jti"],
        serde_json::json!(&with_body.access_token_jti)
    );
    assert_eq!(
        issued.payload["refresh_token_family_id"],
        serde_json::Value::Null
    );

    let mut refresh = NewRefreshToken {
        raw_token: "refresh".to_owned(),
        tenant_id: with_body.tenant_id,
        family_id: Uuid::now_v7(),
        rotated_from_id: Some(Uuid::now_v7()),
        lost_response_retry: Some(nazo_auth::LostResponseRetry {
            original_id: Uuid::now_v7(),
            retry_started_at: Utc::now(),
        }),
        client_id: with_body.client_id,
        user_id: with_body.user_id,
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
    };
    let rotated = refresh_rotated_audit_event(&with_body, &refresh);
    assert_eq!(rotated.event_type, "refresh_rotated");
    assert_eq!(
        rotated.payload["token_family_id"],
        serde_json::json!(refresh.family_id)
    );
    assert_eq!(
        rotated.payload["rotated_from_id"],
        serde_json::json!(refresh.rotated_from_id)
    );
    let reused = refresh_reuse_audit_event(&with_body, &refresh);
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
        refresh_reuse_audit_event(&with_body, &refresh).event_type,
        "refresh_reuse_detected"
    );
}

#[test]
fn existing_issuance_classification_preserves_request_and_replay_modes() {
    let fresh = valid_commit_input(TokenIssuanceMode::Fresh, None);
    assert!(matches!(
        classify_existing_issuance(&fresh, existing_record(&fresh.request_digest, None)),
        CommitTokenIssuanceResult::AlreadyUsed
    ));
    let single_use = valid_commit_input(
        TokenIssuanceMode::SingleUse {
            grant_key: "grant".to_owned(),
        },
        None,
    );
    assert!(matches!(
        classify_existing_issuance(
            &single_use,
            existing_record(&single_use.request_digest, None),
        ),
        CommitTokenIssuanceResult::AlreadyUsed
    ));

    let idempotent = valid_commit_input(
        TokenIssuanceMode::Idempotent {
            grant_key: "grant".to_owned(),
        },
        Some(b"response".to_vec()),
    );
    let existing = classify_existing_issuance(
        &idempotent,
        existing_record(&idempotent.request_digest, Some(b"response")),
    );
    match existing {
        CommitTokenIssuanceResult::Existing(record) => {
            assert_eq!(record.request_digest, idempotent.request_digest);
            assert_eq!(
                record.response_body.as_deref(),
                Some(b"response".as_slice())
            );
        }
        other => panic!("expected an existing recoverable issuance, got {other:?}"),
    }

    let idempotent_without_response = valid_commit_input(
        TokenIssuanceMode::Idempotent {
            grant_key: "grant".to_owned(),
        },
        None,
    );
    assert!(matches!(
        classify_existing_issuance(
            &idempotent_without_response,
            existing_record(&idempotent_without_response.request_digest, None),
        ),
        CommitTokenIssuanceResult::Conflict
    ));
    assert!(matches!(
        classify_existing_issuance(
            &idempotent,
            existing_record("different-digest", Some(b"response")),
        ),
        CommitTokenIssuanceResult::Conflict
    ));
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
fn response_envelopes_fail_closed_on_missing_keys_tampering_and_digest_mismatch() {
    let ring =
        TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None).expect("key ring is valid");
    let body = b"response";
    let digest = blake3::hash(body).to_hex().to_string();
    let base_context = context(
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );
    assert!(matches!(
        seal_response(None, &base_context, body),
        Err(RepositoryError::Unavailable)
    ));
    assert!(matches!(
        unseal_response(&ring, &base_context, &[]),
        Err(RepositoryError::Consistency(message)) if message.contains("malformed")
    ));
    assert!(matches!(
        unseal_response(
            &ring,
            &base_context,
            &[TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE + 1; RESPONSE_MIN_PROTECTED_LEN],
        ),
        Err(RepositoryError::Consistency(message)) if message.contains("malformed")
    ));

    let mut protected =
        seal_response(Some(&ring), &base_context, body).expect("seals successfully");
    let last = protected.len() - 1;
    protected[last] ^= 1;
    assert!(matches!(
        unseal_response(&ring, &base_context, &protected),
        Err(RepositoryError::Consistency(message)) if message.contains("authentication")
    ));

    let wrong_digest = "0".repeat(64);
    let wrong_context = context(
        base_context.issuance_id,
        base_context.tenant_id,
        base_context.client_id,
        &wrong_digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );
    let wrong_digest_protected =
        seal_response(Some(&ring), &wrong_context, body).expect("seals successfully");
    assert!(matches!(
        unseal_response(&ring, &wrong_context, &wrong_digest_protected),
        Err(RepositoryError::Consistency(message)) if message.contains("digest mismatch")
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

#[test]
fn grant_hash_and_response_aad_bind_all_issuance_context_fields() {
    assert_eq!(grant_key_hash("grant-key"), grant_key_hash("grant-key"));
    assert_ne!(grant_key_hash("grant-key"), grant_key_hash("other-grant"));
    let issuance_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let first = context(
        issuance_id,
        tenant_id,
        client_id,
        "digest-a",
        "v1",
        "current",
    );
    let mut second = context(
        issuance_id,
        tenant_id,
        client_id,
        "digest-a",
        "v1",
        "current",
    );
    second.key_id = "previous";
    assert_ne!(response_aad(&first), response_aad(&second));
}
