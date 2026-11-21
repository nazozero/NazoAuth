#![cfg(feature = "local-sqlite")]

use std::sync::{Arc, Barrier};

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_identity::TenantId;
use nazo_key_management::{
    MdocCrlNumber, MdocCrlPublication, MdocCrlPublicationStore, Openid4vcPublicMaterial,
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{D1Provider, Database};

fn authority(label: &str) -> Openid4vcPublicMaterial {
    // This adapter consumes an already-verified projection. Certificate and
    // CRL validation is exercised with signed artifacts in the Worker tests.
    Openid4vcPublicMaterial {
        signing_kid: format!("{label}-kid"),
        certificate_chain_pem: format!("{label}-public-chain"),
        trust_anchors_pem: "public-iaca".into(),
        revocation_snapshot: None,
    }
}

async fn set_authority(database: &Database, tenant: Uuid, public: &Openid4vcPublicMaterial) {
    database
        .execute_statement(
            "INSERT INTO nazo_signing_keys(tenant_id,revision,metadata,material,wrapping_key_id)
             VALUES(?1,1,?2,'opaque-private-fixture','wrapping-key')
             ON CONFLICT(tenant_id) DO UPDATE SET metadata=excluded.metadata,revision=revision+1",
            vec![
                json!(tenant),
                json!(json!({"openid4vc":{"public":public}}).to_string()),
            ],
        )
        .await
        .unwrap();
}

async fn fixture() -> (Database, D1Provider, MdocCrlPublication) {
    let tenant = Uuid::new_v4();
    let database = Database::in_memory().unwrap();
    database.execute_schema().unwrap();
    let provider = D1Provider::new(database.clone(), TenantId::new(tenant).unwrap());
    let public = authority("initial");
    set_authority(&database, tenant, &public).await;
    let now = Timestamp::now();
    let publication = MdocCrlPublication {
        tenant_id: tenant,
        issuer_id: rand::random(),
        issuer: "https://issuer.example".into(),
        // The public acceptance fixture uses 2^64 + 4, which cannot fit in a
        // SQLite integer or pass through a JavaScript Number without rounding.
        number: MdocCrlNumber::from_big_endian(&[1, 0, 0, 0, 0, 0, 0, 0, 4]).unwrap(),
        der_sha256: rand::random(),
        authority: public,
        this_update: now - SignedDuration::from_secs(60),
        next_update: now + SignedDuration::from_secs(600),
    };
    (database, provider, publication)
}

async fn receipt(database: &Database, publication: &MdocCrlPublication) -> Option<Value> {
    database
        .query::<Value>(
            "SELECT * FROM nazo_mdoc_crl_publications WHERE tenant_id=?1 AND issuer_id=?2",
            vec![
                json!(publication.tenant_id),
                json!(hex::encode(publication.issuer_id)),
            ],
        )
        .await
        .unwrap()
        .into_iter()
        .next()
}

#[test]
fn number_encoding_is_exact_across_javascript_u64_and_twenty_byte_boundaries() {
    for invalid in [vec![], vec![0], vec![0, 1], vec![1; 21]] {
        assert!(MdocCrlNumber::from_big_endian(&invalid).is_err());
    }
    let values = [
        vec![1],
        vec![0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x20, 0, 0, 0, 0, 0, 1],
        vec![0xff; 8],
        vec![1, 0, 0, 0, 0, 0, 0, 0, 4],
        vec![0xff; 20],
    ];
    block_on(async {
        let (database, provider, mut publication) = fixture().await;
        let mut previous = String::new();
        for bytes in values {
            publication.number = MdocCrlNumber::from_big_endian(&bytes).unwrap();
            let encoded = publication.number.to_fixed_hex();
            assert_eq!(encoded.len(), 40);
            assert!(encoded > previous);
            provider
                .accept_verified_publication(&publication)
                .await
                .unwrap();
            assert_eq!(
                receipt(&database, &publication).await.unwrap()["number_hex"],
                encoded
            );
            previous = encoded;
        }
        assert_eq!(previous, "f".repeat(40));
        let above_u64 = MdocCrlNumber::from_big_endian(&[1, 0, 0, 0, 0, 0, 0, 0, 4]).unwrap();
        assert_eq!(
            above_u64.to_fixed_hex(),
            format!("{:040x}", u128::from(u64::MAX) + 5)
        );
    });
}

#[test]
fn exact_republication_is_idempotent_and_same_number_changes_or_regressions_fail() {
    block_on(async {
        let (database, provider, publication) = fixture().await;
        provider
            .accept_verified_publication(&publication)
            .await
            .unwrap();
        let original = receipt(&database, &publication).await.unwrap();
        provider
            .accept_verified_publication(&publication)
            .await
            .unwrap();
        assert_eq!(receipt(&database, &publication).await.unwrap(), original);

        for changed in 0..5 {
            let mut candidate = publication.clone();
            match changed {
                0 => candidate.number = MdocCrlNumber::from_big_endian(&[0xff; 8]).unwrap(),
                1 => candidate.der_sha256 = rand::random(),
                2 => candidate.issuer = "https://other.example".into(),
                3 => candidate.this_update -= SignedDuration::from_secs(1),
                4 => candidate.next_update -= SignedDuration::from_secs(1),
                _ => unreachable!(),
            }
            assert!(
                provider
                    .accept_verified_publication(&candidate)
                    .await
                    .is_err()
            );
            assert_eq!(receipt(&database, &publication).await.unwrap(), original);
        }
        let mut backwards_time = publication.clone();
        backwards_time.number = MdocCrlNumber::from_big_endian(&[2; 9]).unwrap();
        backwards_time.this_update -= SignedDuration::from_secs(1);
        assert!(
            provider
                .accept_verified_publication(&backwards_time)
                .await
                .is_err()
        );
        assert_eq!(receipt(&database, &publication).await.unwrap(), original);

        assert!(
            database
                .execute_sql("DELETE FROM nazo_mdoc_crl_publications")
                .is_err()
        );
        database.execute_schema().unwrap();
        assert_eq!(receipt(&database, &publication).await.unwrap(), original);
    });
}

#[test]
fn concurrent_same_number_conflicts_have_one_winner_and_exact_retries_remain_valid() {
    let (database, provider, publication) = block_on(fixture());
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(12));
    let attempts = std::thread::scope(|scope| {
        let workers = (0..12)
            .map(|_| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                let mut candidate = publication.clone();
                candidate.der_sha256 = rand::random();
                scope.spawn(move || {
                    barrier.wait();
                    let accepted =
                        block_on(provider.accept_verified_publication(&candidate)).is_ok();
                    (candidate, accepted)
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    let winners = attempts
        .iter()
        .filter(|(_, accepted)| *accepted)
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1);
    let winner = &winners[0].0;
    assert_eq!(
        block_on(receipt(&database, winner)).unwrap()["der_sha256"],
        hex::encode(winner.der_sha256),
    );
    let barrier = Arc::new(Barrier::new(12));
    std::thread::scope(|scope| {
        let workers = (0..12)
            .map(|_| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.accept_verified_publication(winner)).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
    });
}

#[test]
fn concurrent_number_advances_retain_the_highest_publication() {
    let (database, provider, publication) = block_on(fixture());
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(12));
    std::thread::scope(|scope| {
        let workers = (1..=12)
            .map(|number| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                let mut candidate = publication.clone();
                candidate.number = MdocCrlNumber::from_big_endian(&[number]).unwrap();
                scope.spawn(move || {
                    barrier.wait();
                    let result = block_on(provider.accept_verified_publication(&candidate));
                    if number == 12 {
                        result.unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    assert_eq!(
        block_on(receipt(&database, &publication)).unwrap()["number_hex"],
        MdocCrlNumber::from_big_endian(&[12])
            .unwrap()
            .to_fixed_hex(),
    );
}

#[test]
fn stale_authority_cannot_win_a_larger_number_race_and_a_new_iaca_has_its_own_fence() {
    let (database, provider, old) = block_on(fixture());
    block_on(provider.accept_verified_publication(&old)).unwrap();
    let accepted_old = block_on(receipt(&database, &old)).unwrap();
    let mut current = old.clone();
    current.authority = authority("replacement-ds");
    block_on(set_authority(&database, old.tenant_id, &current.authority));
    // An authority change cannot reuse a number even if bytes were unchanged.
    assert!(block_on(provider.accept_verified_publication(&current)).is_err());
    assert_eq!(block_on(receipt(&database, &old)).unwrap(), accepted_old);
    current.number = MdocCrlNumber::from_big_endian(&[2; 9]).unwrap();
    current.der_sha256 = rand::random();
    let mut stale = old.clone();
    stale.number = MdocCrlNumber::from_big_endian(&[0xff; 20]).unwrap();
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(16));
    std::thread::scope(|scope| {
        let workers = (0..16)
            .map(|index| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                let candidate = if index % 2 == 0 { &current } else { &stale };
                scope.spawn(move || {
                    barrier.wait();
                    assert_eq!(
                        block_on(provider.accept_verified_publication(candidate)).is_ok(),
                        index % 2 == 0,
                    );
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
    });
    let accepted_current = block_on(receipt(&database, &current)).unwrap();
    assert_eq!(
        accepted_current["number_hex"],
        current.number.to_fixed_hex()
    );
    assert_eq!(
        accepted_current["authority_hash"],
        blake3::hash(&serde_json::to_vec(&current.authority).unwrap())
            .to_hex()
            .to_string(),
    );
    current.issuer_id = rand::random();
    current.number = MdocCrlNumber::from_big_endian(&[1]).unwrap();
    block_on(provider.accept_verified_publication(&current)).unwrap();
    assert_eq!(
        block_on(receipt(&database, &old)).unwrap(),
        accepted_current
    );
    assert_eq!(
        block_on(receipt(&database, &current)).unwrap()["number_hex"],
        current.number.to_fixed_hex(),
    );
}

#[test]
fn ordinary_keyset_changes_do_not_reset_or_invalidate_the_public_authority_fence() {
    block_on(async {
        let (database, provider, publication) = fixture().await;
        provider
            .accept_verified_publication(&publication)
            .await
            .unwrap();
        let original = receipt(&database, &publication).await.unwrap();
        database.execute_statement(
            "UPDATE nazo_signing_keys SET revision=revision+1,wrapping_key_id='next-wrapping-key',
             metadata=json_set(metadata,'$.active_kid','different-jwt-key') WHERE tenant_id=?1",
            vec![json!(publication.tenant_id)],
        ).await.unwrap();
        provider
            .accept_verified_publication(&publication)
            .await
            .unwrap();
        assert_eq!(receipt(&database, &publication).await.unwrap(), original);
        // The stored Value uses different object field order from the typed
        // struct; semantic comparison must remain independent of that order.
        assert_ne!(
            serde_json::to_string(&publication.authority).unwrap(),
            serde_json::to_value(&publication.authority)
                .unwrap()
                .to_string(),
        );
    });
}

#[test]
fn missing_or_malformed_authority_and_invalid_time_windows_never_publish() {
    block_on(async {
        let (database, provider, publication) = fixture().await;
        for metadata in [
            json!({}),
            json!({"openid4vc":{"public":null}}),
            json!({"openid4vc":{"public":[]}}),
            json!({"openid4vc":{"public":true}}),
        ] {
            database
                .execute_statement(
                    "UPDATE nazo_signing_keys SET metadata=?2 WHERE tenant_id=?1",
                    vec![json!(publication.tenant_id), json!(metadata.to_string())],
                )
                .await
                .unwrap();
            assert!(
                provider
                    .accept_verified_publication(&publication)
                    .await
                    .is_err()
            );
            assert!(receipt(&database, &publication).await.is_none());
        }
        set_authority(&database, publication.tenant_id, &publication.authority).await;
        for future in [false, true] {
            let mut candidate = publication.clone();
            if future {
                candidate.this_update = Timestamp::now() + SignedDuration::from_secs(30);
            } else {
                candidate.next_update = Timestamp::now() - SignedDuration::from_secs(30);
            }
            assert!(
                provider
                    .accept_verified_publication(&candidate)
                    .await
                    .is_err()
            );
            assert!(receipt(&database, &publication).await.is_none());
        }
    });
}

#[test]
fn receipt_scope_is_bound_to_tenant_and_cannot_borrow_another_authority() {
    block_on(async {
        let (database, provider, publication) = fixture().await;
        let other_tenant = Uuid::new_v4();
        let other_provider =
            D1Provider::new(database.clone(), TenantId::new(other_tenant).unwrap());
        assert!(
            other_provider
                .accept_verified_publication(&publication)
                .await
                .is_err()
        );
        let mut other = publication.clone();
        other.tenant_id = other_tenant;
        assert!(
            other_provider
                .accept_verified_publication(&other)
                .await
                .is_err()
        );
        set_authority(&database, other_tenant, &other.authority).await;
        other_provider
            .accept_verified_publication(&other)
            .await
            .unwrap();
        provider
            .accept_verified_publication(&publication)
            .await
            .unwrap();
        assert!(receipt(&database, &other).await.is_some());
        assert!(receipt(&database, &publication).await.is_some());
    });
}

#[test]
fn ignored_receipt_writes_are_not_accepted_and_never_destroy_prior_evidence() {
    block_on(async {
        let (database, provider, mut publication) = fixture().await;
        database.execute_sql("CREATE TRIGGER suppress_crl_insert BEFORE INSERT ON nazo_mdoc_crl_publications BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .accept_verified_publication(&publication)
                .await
                .is_err()
        );
        assert!(receipt(&database, &publication).await.is_none());
        database
            .execute_sql("DROP TRIGGER suppress_crl_insert")
            .unwrap();
        provider
            .accept_verified_publication(&publication)
            .await
            .unwrap();
        let original = receipt(&database, &publication).await.unwrap();
        database.execute_sql("CREATE TRIGGER suppress_crl_update BEFORE UPDATE ON nazo_mdoc_crl_publications BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        publication.number = MdocCrlNumber::from_big_endian(&[2; 9]).unwrap();
        assert!(
            provider
                .accept_verified_publication(&publication)
                .await
                .is_err()
        );
        assert_eq!(receipt(&database, &publication).await.unwrap(), original);
    });
}
