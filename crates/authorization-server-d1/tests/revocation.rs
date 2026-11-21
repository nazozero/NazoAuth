#![cfg(feature = "local-sqlite")]

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{AccessTokenRevocation, TokenRepositoryPort, TokenRevocation};
use nazo_identity::TenantId;
use nazo_oauth_server_d1::{D1Provider, Database};
use uuid::Uuid;

const TENANT: Uuid = Uuid::from_u128(1);
const OWNER: Uuid = Uuid::from_u128(2);
const OTHER_OWNER: Uuid = Uuid::from_u128(3);
const USER: Uuid = Uuid::from_u128(4);
const JTI: &str = "revocation-owner-contract";

fn fixture() -> (D1Provider, rusqlite::Connection) {
    // Independent observation of the real adapter's committed transaction.
    let uri = format!(
        "file:nazo-revocation-{}?mode=memory&cache=shared",
        Uuid::new_v4()
    );
    let database = Database::open(&uri).unwrap();
    database.execute_schema().unwrap();
    let observer = rusqlite::Connection::open(&uri).unwrap();
    let provider = D1Provider::new(database, TenantId::new(TENANT).unwrap());
    (provider, observer)
}

fn retained_revocation(observer: &rusqlite::Connection) -> (String, i64) {
    observer
        .query_row(
            "SELECT client_id,expires_at FROM nazo_revocations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn audited_revocations(observer: &rusqlite::Connection) -> i64 {
    observer
        .query_row(
            "SELECT COUNT(*) FROM nazo_audit WHERE event_type='token_revoked'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn same_owner_retries_extend_but_never_shorten_revocation_retention() {
    block_on(async {
        let (provider, observer) = fixture();
        let expiry = Timestamp::now() + SignedDuration::from_secs(600);
        provider
            .revoke_issued_tokens(TENANT, OWNER, JTI, Some(expiry), None)
            .await
            .unwrap();
        let first = retained_revocation(&observer);
        assert_eq!(first.0, OWNER.to_string());
        assert_eq!(
            first.1,
            expiry.as_microsecond()
                + nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS * 1_000_000
        );

        provider
            .revoke_issued_tokens(
                TENANT,
                OWNER,
                JTI,
                Some(expiry - SignedDuration::from_secs(60)),
                None,
            )
            .await
            .unwrap();
        assert_eq!(retained_revocation(&observer), first);

        assert_eq!(
            provider
                .revoke_token_with_audit(
                    TokenRevocation {
                        tenant_id: TENANT,
                        client_id: OWNER,
                        raw_token: "verified-access-token",
                        access_token: Some(AccessTokenRevocation {
                            jti: JTI.into(),
                            expires_at: expiry + SignedDuration::from_secs(60),
                        }),
                    },
                    "owner",
                    "source-hash",
                )
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            retained_revocation(&observer),
            (first.0, first.1 + 60_000_000)
        );
        assert_eq!(audited_revocations(&observer), 1);
    });
}

#[test]
fn ownership_conflict_rolls_back_retention_family_changes_and_required_audit() {
    block_on(async {
        let (provider, observer) = fixture();
        let expiry = Timestamp::now() + SignedDuration::from_secs(600);
        provider
            .revoke_issued_tokens(TENANT, OWNER, JTI, Some(expiry), None)
            .await
            .unwrap();
        let original = retained_revocation(&observer);
        let family = Uuid::new_v4();
        // A live family owned by the conflicting caller is a rollback sentinel.
        // This test exercises revocation; no refresh token is decoded or issued.
        observer
            .execute(
                "INSERT INTO nazo_refresh_families(tenant_id,id,client_id,user_id,contract,contract_hash,member,member_id,token_hash,created_at,expires_at) VALUES(?1,?2,?3,?4,'{}','fixture','{}',?5,'fixture',0,?6)",
                rusqlite::params![TENANT.to_string(), family.to_string(), OTHER_OWNER.to_string(), USER.to_string(), Uuid::new_v4().to_string(), expiry.as_microsecond()],
            )
            .unwrap();
        assert!(
            provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );

        assert!(
            provider
                .revoke_issued_tokens(
                    TENANT,
                    OTHER_OWNER,
                    JTI,
                    Some(expiry + SignedDuration::from_secs(60)),
                    Some(family),
                )
                .await
                .is_err()
        );
        assert_eq!(retained_revocation(&observer), original);
        assert!(
            provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );

        assert!(
            provider
                .revoke_token_with_audit(
                    TokenRevocation {
                        tenant_id: TENANT,
                        client_id: OTHER_OWNER,
                        raw_token: "verified-access-token",
                        access_token: Some(AccessTokenRevocation {
                            jti: JTI.into(),
                            expires_at: expiry + SignedDuration::from_secs(60),
                        }),
                    },
                    "other-owner",
                    "source-hash",
                )
                .await
                .is_err()
        );
        assert_eq!(retained_revocation(&observer), original);
        assert_eq!(audited_revocations(&observer), 0);
        assert!(
            provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );
    });
}

#[test]
fn ignored_audit_or_revocation_never_acknowledges_a_partial_revocation() {
    block_on(async {
        for table in ["nazo_audit", "nazo_revocations"] {
            let (provider, observer) = fixture();
            observer
                .execute_batch(&format!(
                    "CREATE TRIGGER refuse BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END"
                ))
                .unwrap();
            assert!(
                provider
                    .revoke_token_with_audit(
                        TokenRevocation {
                            tenant_id: TENANT,
                            client_id: OWNER,
                            raw_token: "verified-token",
                            access_token: Some(AccessTokenRevocation {
                                jti: JTI.into(),
                                expires_at: Timestamp::now() + SignedDuration::from_secs(600),
                            }),
                        },
                        "owner",
                        "source-hash",
                    )
                    .await
                    .is_err(),
                "ignored {table} write was acknowledged"
            );
            assert_eq!(audited_revocations(&observer), 0);
            let retained: i64 = observer
                .query_row("SELECT count(*) FROM nazo_revocations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(retained, 0);
        }
    });
}

#[test]
fn ignored_compensation_revocation_is_reported_as_unavailable() {
    block_on(async {
        let (provider, observer) = fixture();
        observer.execute_batch("CREATE TRIGGER refuse BEFORE INSERT ON nazo_revocations BEGIN SELECT RAISE(IGNORE); END").unwrap();
        assert!(
            provider
                .revoke_issued_tokens(
                    TENANT,
                    OWNER,
                    JTI,
                    Some(Timestamp::now() + SignedDuration::from_secs(600)),
                    None,
                )
                .await
                .is_err()
        );
    });
}
