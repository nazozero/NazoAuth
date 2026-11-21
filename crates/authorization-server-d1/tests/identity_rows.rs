#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use nazo_auth::{AuthorizationRepositoryPort, TokenRepositoryPort, UserinfoSubjectRef};
use nazo_identity::{TenantId, UserId, ports::SessionAccountPort};
use support::{TENANT, USER, fixture};
use uuid::Uuid;

#[test]
fn session_account_reads_reject_structurally_valid_but_misbound_principals() {
    block_on(async {
        let foreign = Uuid::from_u128(12);
        for update in [
            format!("principal=json_set(principal,'$.tenant.tenant_id','{foreign}')"),
            format!("principal=json_set(principal,'$.user_id','{foreign}')"),
            format!(
                "principal=json_set(principal,'$.user_id','{foreign}'),claims=json_set(claims,'$.subject','{foreign}')"
            ),
        ] {
            let (database, provider) = fixture().await;
            database
                .execute_sql(&format!("UPDATE nazo_users SET {update}"))
                .unwrap();
            let tenant = TenantId::new(TENANT).unwrap();
            let user = UserId::new(USER).unwrap();
            assert!(provider.principal_by_id(tenant, user).await.is_err());
            assert!(provider.public_account_by_id(tenant, user).await.is_err());
        }
    });
}

#[test]
fn profile_and_token_claims_reject_a_subject_that_does_not_own_the_row() {
    block_on(async {
        let (database, provider) = fixture().await;
        let foreign = Uuid::from_u128(12);
        database
            .execute_sql(&format!(
                "UPDATE nazo_users SET claims=json_set(claims,'$.subject','{foreign}')"
            ))
            .unwrap();
        let tenant = TenantId::new(TENANT).unwrap();
        let user = UserId::new(USER).unwrap();
        // The independent security-only principal projection remains usable.
        assert_eq!(
            provider
                .principal_by_id(tenant, user)
                .await
                .unwrap()
                .unwrap()
                .user_id,
            user
        );
        assert!(provider.public_account_by_id(tenant, user).await.is_err());
        assert!(
            provider
                .active_subject_claims(TENANT, USER, &USER.to_string())
                .await
                .is_err()
        );
        assert!(
            provider
                .userinfo_snapshot(TENANT, UserinfoSubjectRef::UserId(USER), "client")
                .await
                .is_err()
        );
    });
}

#[test]
fn client_reads_reject_registration_identity_that_disagrees_with_its_index() {
    block_on(async {
        let (database, provider) = fixture().await;
        database.execute_sql(
            "UPDATE nazo_clients SET registration=json_set(registration,'$.client_id','different-client')"
        ).unwrap();
        assert!(provider.client_by_id("client").await.is_err());
        assert!(
            provider
                .client_authentication_snapshot("client")
                .await
                .is_err()
        );
        assert!(
            provider
                .userinfo_snapshot(TENANT, UserinfoSubjectRef::UserId(USER), "client")
                .await
                .is_err()
        );
    });
}
