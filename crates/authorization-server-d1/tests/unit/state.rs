#![cfg(feature = "local-sqlite")]

use futures_executor::block_on;
use nazo_identity::TenantId;
use nazo_oauth_server::ports::fapi_replay::{
    FapiHttpSignatureReplayConsumption, FapiHttpSignatureReplayStore,
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{D1Provider, Database};

#[test]
fn http_signature_keeps_its_absolute_deadline_and_rejects_expired_inputs() {
    block_on(async {
        let database = Database::in_memory().unwrap();
        database.execute_schema().unwrap();
        let tenant = TenantId::new(Uuid::from_u128(1)).unwrap();
        let provider = D1Provider::new(database.clone(), tenant);
        let fingerprint = [8; 32];
        let now = jiff::Timestamp::now().as_second();
        for expires_at in [-1, 0, now] {
            assert_eq!(
                FapiHttpSignatureReplayStore::consume(&provider, tenant, &fingerprint, expires_at)
                    .await
                    .unwrap(),
                FapiHttpSignatureReplayConsumption::Replay
            );
        }
        assert!(
            database
                .query::<Value>(
                    "SELECT expires_at FROM nazo_state WHERE kind='fapi'",
                    vec![]
                )
                .await
                .unwrap()
                .is_empty()
        );
        let expires_at = now + 61;
        assert_eq!(
            FapiHttpSignatureReplayStore::consume(&provider, tenant, &fingerprint, expires_at)
                .await
                .unwrap(),
            FapiHttpSignatureReplayConsumption::Accepted
        );
        assert_eq!(
            FapiHttpSignatureReplayStore::consume(&provider, tenant, &fingerprint, expires_at + 60)
                .await
                .unwrap(),
            FapiHttpSignatureReplayConsumption::Replay
        );
        assert_eq!(
            database
                .query::<Value>(
                    "SELECT expires_at FROM nazo_state WHERE kind='fapi'",
                    vec![]
                )
                .await
                .unwrap(),
            vec![json!({ "expires_at": expires_at })]
        );
    });
}
