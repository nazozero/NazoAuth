use super::*;

fn access() -> CredentialAccess {
    CredentialAccess {
        authorization_id: Some(Uuid::now_v7()),
        mtls_x5t_s256: None,
        proof_origin: nazo_openid4vci::CredentialProofOrigin::RegisteredClient,
        token_id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        subject_id: Uuid::now_v7(),
        client_id: "wallet".into(),
        configuration_ids: vec!["pid".into()],
        credential_identifiers: vec![],
        dpop_jkt: None,
        expires_at: Utc::now() + chrono::Duration::hours(1),
    }
}

fn row(access: &CredentialAccess, id: Uuid, ciphertext: Vec<u8>) -> DeferredRow {
    DeferredRow {
        authorization_id: access.authorization_id,
        credential_selection: None,
        id,
        transaction_hash: "opaque-transaction-hash".into(),
        token_id: access.token_id,
        credential_configuration_id: "pid".into(),
        credential_format: "dc+sd-jwt".into(),
        holder_bindings: serde_json::json!([]),
        payload_ciphertext: ciphertext,
        ready_at: Utc::now(),
        expires_at: access.expires_at,
    }
}

#[test]
fn retained_ciphertext_is_decoded_only_at_adapter_boundary() {
    let access = access();
    let id = Uuid::now_v7();
    let key = [42; 32];
    // Existing persisted JSON shape, encrypted with the unchanged nonce/AAD envelope.
    let legacy = serde_json::json!({
        "dataset": {"given_name":"Ada"}, "status": null,
        "issued_at":"2026-10-09T00:00:00Z", "expires_at":"2026-10-10T00:00:00Z"
    });
    let plaintext = serde_json::to_vec(&legacy).unwrap();
    let ciphertext = protect_payload(&key, id, &plaintext).unwrap();
    assert_ne!(ciphertext, plaintext);
    let actual = row(&access, id, ciphertext.clone())
        .into_domain(access.clone(), &key)
        .unwrap();
    assert_eq!(serde_json::to_value(actual.payload).unwrap(), legacy);
    assert!(
        row(&access, id, ciphertext.clone())
            .into_domain(access.clone(), &[43; 32])
            .is_err()
    );
    assert!(
        row(&access, Uuid::now_v7(), ciphertext)
            .into_domain(access.clone(), &key)
            .is_err()
    );
    let malformed = protect_payload(&key, id, b"{\"dataset\": {}}").unwrap();
    assert!(
        row(&access, id, malformed)
            .into_domain(access, &key)
            .is_err()
    );
}
