//! Contract tests for the startup response-key projection.

use nazo_persistence::TokenIssuanceResponseKeyRing;

const REPOSITORY: &str = include_str!("../src/repositories/token_issuance.rs");
const MIGRATION: &str =
    include_str!("../../../migrations/20260906000100_atomic_token_issuance/up.sql");

fn preflight_source() -> &'static str {
    let start = REPOSITORY
        .find("pub async fn validate_response_key_ring")
        .expect("response-key preflight implementation should exist");
    let end = REPOSITORY[start..]
        .find("    async fn connection")
        .map(|offset| start + offset)
        .expect("response-key preflight should end before connection helper");
    &REPOSITORY[start..end]
}

#[test]
fn preflight_reads_only_distinct_response_key_metadata() {
    let source = preflight_source();
    assert!(source.contains(".distinct()"));
    assert!(source.contains("response_key_id"));
    assert!(source.contains("response_envelope_version"));
    assert!(source.contains("response_ciphertext.is_not_null()"));
    assert!(source.contains("access_token_expires_at.gt(Utc::now())"));
    assert!(!source.contains("response_ciphertext,"));
    assert!(!source.contains("into_record"));
    assert!(!source.contains("RESPONSE_MIN_PROTECTED_LEN"));
    assert!(MIGRATION.contains("oauth_token_issuances_response_key_metadata_idx"));
}

#[test]
fn corrupt_response_body_does_not_block_preflight() {
    // The preflight projection never selects ciphertext.  Full envelope and
    // digest checks remain in the row decoder used by the actual recovery path.
    let source = preflight_source();
    assert!(source.contains("response_ciphertext.is_not_null()"));
    assert!(!source.contains("response_ciphertext,"));
    let decoder_start = REPOSITORY
        .find("fn into_record")
        .expect("row decoder should remain for on-demand recovery");
    assert!(REPOSITORY[decoder_start..].contains("unseal_response"));
}

#[test]
fn missing_active_response_key_still_blocks_startup() {
    let ring = TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None)
        .expect("test key ring should be valid");
    assert!(ring.key_for("retired").is_none());
    assert!(REPOSITORY.contains("unavailable encryption key"));
    assert!(REPOSITORY.contains("validate_response_key_metadata"));
    assert!(MIGRATION.contains("WHERE response_ciphertext IS NOT NULL"));
}
