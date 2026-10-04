use super::*;

#[test]
fn credential_view_borrows_secret_and_keeps_source_precedence() {
    let facts = TokenClientAuthTransportFacts::from_parts(
        BasicAuthorizationCredentials::Present {
            client_id: "basic-client".to_owned(), client_secret: "basic-secret".to_owned(),
        }, Some("form-client".to_owned()), Some("form-secret".to_owned()), None, None,
    );
    let view = facts.credential_view(None, Some("form-client"));
    let BasicAuthorizationCredentials::Present { client_secret, .. } = &facts.basic else { panic!("fixture"); };
    assert_eq!(view.client_secret.unwrap().as_ptr(), client_secret.as_ptr());
    assert_eq!(view.client_id, Some("basic-client"));
    assert_eq!(view.method, "client_secret_basic");
    assert!(!format!("{view:?}").contains("basic-secret"));

    let assertion = TokenClientAuthTransportFacts::from_parts(
        facts.basic.clone(), Some("form-client".to_owned()), Some("form-secret".to_owned()),
        Some("assertion-type".to_owned()), Some("assertion".to_owned()),
    );
    let view = assertion.credential_view(None, Some("form-client"));
    assert_eq!(view.method, "private_key_jwt");
    assert!(view.client_id.is_none(), "an absent assertion lookup hint must not use another source");
    assert!(view.client_secret.is_none());
    let malformed = TokenClientAuthTransportFacts::from_parts(
        BasicAuthorizationCredentials::Malformed, None, None,
        Some("assertion-type".to_owned()), Some("assertion".to_owned()),
    );
    assert_eq!(malformed.credential_view(Some("hint"), None).method, "client_secret_basic");
}
