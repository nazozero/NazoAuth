use std::path::Path;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_key_management::SigningKeyRepository;

use super::*;

use super::shared::{
    MemoryOperatorPersistence, MemorySigningKeyRepository, temporary_directory, tenant_binding,
};

fn database_config(data_dir: &Path) -> ConfigSource {
    ConfigSource::from_owned_pairs_for_test([
        ("DATA_DIR".to_owned(), data_dir.display().to_string()),
        (
            "SIGNING_KEY_ENCRYPTION_KEY".to_owned(),
            URL_SAFE_NO_PAD.encode([0x42_u8; 32]),
        ),
        (
            "SIGNING_KEY_ENCRYPTION_KEY_ID".to_owned(),
            "keyctl-test-root".to_owned(),
        ),
    ])
}

#[test]
fn parses_the_closed_purpose_scoped_key_operation() {
    let options = parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    assert_eq!(options.alg, jsonwebtoken::Algorithm::ES256);
    assert_eq!(options.purposes.len(), 2);
}

#[test]
fn rejects_empty_duplicate_or_runtime_signing_purposes() {
    assert!(parse_generate_local("ES256", &[]).is_err());
    assert!(
        parse_generate_local("ES256", &["credential".to_owned(), "credential".to_owned()]).is_err()
    );
    assert!(parse_generate_local("ES256", &["access_token".to_owned()]).is_err());
}

#[test]
fn rejects_unsupported_algorithms() {
    assert!(parse_generate_local("none", &["credential".to_owned()]).is_err());
}

#[tokio::test]
async fn database_operator_keyctl_roundtrip_keeps_keys_in_the_repository() {
    let data_dir = temporary_directory("database-roundtrip");
    let config = database_config(&data_dir);
    let binding = tenant_binding("http://127.0.0.1:43123");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let persistence = MemoryOperatorPersistence {
        repository: repository.clone(),
    };

    let (first_kid, first_revision, certificate_chain) =
        operator_generate_local_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "ES256",
            &["credential".to_owned()],
        )
        .await
        .expect("database local key generation");
    assert!(!first_kid.is_empty());
    assert!(
        first_revision
            .parse::<i64>()
            .is_ok_and(|revision| revision > 0)
    );
    assert!(certificate_chain.is_none());

    let (second_kid, second_revision, certificate_chain) =
        operator_generate_local_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "ES256",
            &["credential".to_owned()],
        )
        .await
        .expect("repeated database local key generation");
    assert_eq!(second_kid, first_kid);
    assert_eq!(second_revision, first_revision);
    assert!(certificate_chain.is_none());

    let listed_revision = operator_list_database_for_tenant(&config, &binding, &persistence)
        .await
        .expect("database key listing");
    assert_eq!(listed_revision, first_revision);
    let validated_revision = operator_validate_database_for_tenant(&config, &binding, &persistence)
        .await
        .expect("database key validation");
    assert_eq!(validated_revision, first_revision);

    let external_registration = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "y": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "kid": "external-key",
        "use": "sig",
        "alg": "ES256"
    });
    let external_revision = operator_register_external_database_for_tenant(
        &config,
        &binding,
        &persistence,
        "external-key",
        "ES256",
        "kms://unit/external-key",
        &serde_json::to_vec(&external_registration).unwrap(),
    )
    .await
    .expect("external database key registration");
    assert_ne!(external_revision, first_revision);

    let persisted = repository
        .load()
        .await
        .expect("repository load")
        .expect("persisted database keyset");
    assert!(
        persisted.public_metadata["keys"]
            .as_array()
            .expect("key metadata array")
            .iter()
            .any(|key| {
                key["kid"] == "external-key"
                    && key["backend"] == "external-command"
                    && key["key_ref"] == "kms://unit/external-key"
            })
    );
}
