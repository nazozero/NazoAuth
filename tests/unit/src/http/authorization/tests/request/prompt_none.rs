use super::*;

#[test]
fn stored_grant_covers_prompt_none_request_when_scope_is_subset() {
    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "profile", "email"]),
        &json!([]),
        &parse_scope("openid email"),
        &json!([]),
    ));
}

#[test]
fn stored_grant_does_not_cover_new_or_malformed_scope_sets() {
    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "profile"]),
        &json!([]),
        &parse_scope("openid email"),
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &json!({"scope": "openid"}),
        &json!([]),
        &parse_scope("openid"),
        &json!([]),
    ));
}

#[test]
fn stored_grant_treats_empty_requested_authorization_details_as_already_covered() {
    let stored_high_risk_details = json!([{
        "type": "payment_initiation",
        "actions": ["write"],
        "instructedAmount": {"currency": "USD", "amount": "10.00"}
    }]);

    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "payments"]),
        &stored_high_risk_details,
        &parse_scope("openid"),
        &json!([]),
    ));
}

#[test]
fn stored_grant_requires_exact_authorization_details_binding() {
    let scopes = json!(["openid", "payments"]);
    let read_details = json!([{"type":"account_information","actions":["read"]}]);
    let different_read_details =
        json!([{"type":"account_information","actions":["read"],"locations":["acct-2"]}]);

    assert!(stored_grant_covers_requested_authorization(
        &scopes,
        &read_details,
        &parse_scope("openid payments"),
        &read_details,
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &scopes,
        &read_details,
        &parse_scope("openid payments"),
        &different_read_details,
    ));
}

#[test]
fn stored_grant_never_silently_reuses_high_risk_authorization_details() {
    let payment_details = json!([{
        "type": "payment_initiation",
        "actions": ["write"],
        "instructedAmount": {"currency": "USD", "amount": "10.00"}
    }]);

    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "payments"]),
        &payment_details,
        &parse_scope("openid payments"),
        &payment_details,
    ));
}
