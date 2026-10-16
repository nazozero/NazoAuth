use super::*;

#[test]
fn new_wallet_origins_are_sorted_and_unique() {
    assert_eq!(
        validate_new_wallet_origins(&["https://b.example".into(), "https://a.example".into()])
            .unwrap(),
        ["https://a.example", "https://b.example"]
    );
    assert!(
        validate_new_wallet_origins(&["https://a.example".into(), "https://a.example".into()])
            .is_err()
    );
}
