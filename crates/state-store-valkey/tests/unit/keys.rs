use super::private_key_jwt_replay;

#[test]
fn private_key_jwt_replay_key_is_client_scoped_and_hashed() {
    let first = private_key_jwt_replay("client-1", "assertion-jti");
    let same = private_key_jwt_replay("client-1", "assertion-jti");
    let other_client = private_key_jwt_replay("client-2", "assertion-jti");
    let other_jti = private_key_jwt_replay("client-1", "other-jti");

    assert_eq!(first, same);
    assert!(first.starts_with("oauth:client_assertion:jti:"));
    assert!(!first.contains("client-1"));
    assert!(!first.contains("assertion-jti"));
    assert_ne!(first, other_client);
    assert_ne!(first, other_jti);
}
