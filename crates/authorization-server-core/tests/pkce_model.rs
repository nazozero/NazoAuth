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

#[test]
fn legacy_preparation_timestamps_do_not_create_a_second_lifetime_authority() {
    let legacy = json!({
        "redemption_contract_version": 2, "code_id": "code", "request_id": "request",
        "user_id": "00000000-0000-0000-0000-000000000001", "client_id": "client", "client_name": "Client",
        "redirect_uri": "https://client.example/callback", "redirect_uri_was_supplied": true,
        "scopes": ["openid"], "state": null, "nonce": "nonce", "auth_time": 1700000000, "amr": ["pwd"],
        "issued_at": "2026-10-09T00:00:00Z", "expires_at": "2026-10-09T00:01:00Z",
        "code_challenge": "challenge", "code_challenge_method": "S256"
    });
    let code: nazo_auth::CodePayload = serde_json::from_value(legacy.clone()).unwrap();
    let consent: nazo_auth::ConsentPayload = serde_json::from_value(legacy.clone()).unwrap();
    for wire in [
        serde_json::to_value(code).unwrap(),
        serde_json::to_value(consent).unwrap(),
    ] {
        assert!(wire.get("issued_at").is_none());
        assert_eq!(wire["expires_at"], legacy["expires_at"]);
        assert_eq!(wire["auth_time"], legacy["auth_time"]);
        assert_eq!(wire["s256_code_challenge"], "challenge");
    }
}
