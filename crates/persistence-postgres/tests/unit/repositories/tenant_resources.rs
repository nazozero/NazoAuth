use super::*;
use serde_json::json;

#[test]
fn stored_wallet_origins_require_bounded_strict_order_without_normalizing() {
    assert_eq!(
        validate_stored_wallet_origins(json!(["https://a.example", "https://b.example"])).unwrap(),
        ["https://a.example", "https://b.example"]
    );
    for invalid in [
        json!([]),
        json!(["https://a.example", "https://a.example"]),
        json!(["https://b.example", "https://a.example"]),
        json!(["http://a.example"]),
        json!([" https://a.example"]),
        json!([1]),
        json!(null),
        json!(
            (0..17)
                .map(|i| format!("https://{i:02}.example"))
                .collect::<Vec<_>>()
        ),
    ] {
        assert!(validate_stored_wallet_origins(invalid).is_err());
    }
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
