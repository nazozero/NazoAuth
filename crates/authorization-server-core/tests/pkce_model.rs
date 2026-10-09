use nazo_auth::S256Pkce;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize, Serialize)]
struct Envelope {
    id: String,
    #[serde(flatten)]
    pkce: S256Pkce,
}

#[test]
fn pkce_has_one_authority_and_reads_valid_legacy_pairs() {
    for value in [
        json!({"code_challenge":"challenge","code_challenge_method":"S256"}),
        json!({"s256_code_challenge":"challenge"}),
    ] {
        let mut value = value;
        value["id"] = json!("transaction");
        let parsed: Envelope = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.pkce.challenge(), Some("challenge"));
        assert_eq!(
            serde_json::to_value(parsed).unwrap(),
            json!({"id":"transaction","s256_code_challenge":"challenge"})
        );
    }
    assert_eq!(
        serde_json::to_value(S256Pkce::default()).unwrap(),
        json!({})
    );
}

#[test]
fn legacy_missing_plain_or_conflicting_method_cannot_downgrade_pkce() {
    for value in [
        json!({"code_challenge":"challenge"}),
        json!({"code_challenge_method":"S256"}),
        json!({"code_challenge":"challenge","code_challenge_method":"plain"}),
        json!({"s256_code_challenge":"challenge","code_challenge":"challenge","code_challenge_method":"S256"}),
    ] {
        assert!(serde_json::from_value::<S256Pkce>(value).is_err());
    }
}
