use super::*;

#[tokio::test]
async fn matching_owner_consumes_typed_corruption_before_rejecting_it() {
    let store = crate::test_support::test_state();
    for social in [false, true] {
        let namespace = if social {
            "social-federation"
        } else {
            "oidc-federation"
        };
        let key = store.key(namespace, &[b"corrupt"]);
        let raw = br#"{"browser_binding_hash":"owner-\"browser"}"#;
        store.volatile.with_key(&key, |db| {
            db.set_slice(&key, raw, Some(ttl(60).unwrap()), SetCondition::Always);
        });
        let error = if social {
            store
                .take_social("corrupt", "owner-\"browser")
                .await
                .unwrap_err()
        } else {
            store
                .take_oidc("corrupt", "owner-\"browser")
                .await
                .unwrap_err()
        };
        assert!(matches!(error, RepositoryError::Consistency(_)));
        assert!(
            store
                .volatile
                .with_key(&key, |db| db.get(&key).unwrap().is_none())
        );
    }
}
