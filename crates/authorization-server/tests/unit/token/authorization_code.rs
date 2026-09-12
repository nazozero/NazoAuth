use super::*;
use uuid::Uuid;

#[test]
fn authorization_code_replay_requires_same_client_and_exact_redemption_binding() {
    let client_id = Uuid::now_v7();
    let binding = "authorization_code:binding";
    let mut marker = ConsumedAuthorizationCode {
        client_id,
        redemption_binding: Some(binding.to_owned()),
        access_token_jti: "access-jti".to_owned(),
        access_token_expires_at: Utc::now().timestamp() + 300,
        refresh_token_family_id: None,
        consumed_at: Utc::now(),
    };

    assert!(replay_matches_original_redemption(
        &marker, client_id, binding
    ));
    assert!(!replay_matches_original_redemption(
        &marker,
        Uuid::now_v7(),
        binding
    ));
    assert!(!replay_matches_original_redemption(
        &marker,
        client_id,
        "authorization_code:different"
    ));

    marker.redemption_binding = None;
    assert!(!replay_matches_original_redemption(
        &marker, client_id, binding
    ));
}
