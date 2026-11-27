#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use nazo_auth::{AuthorizationRepositoryPort, TokenRepositoryPort};
use nazo_identity::{TenantId, UserId, ports::SessionAccountPort};
use support::{TENANT, USER, fixture};
use uuid::Uuid;

fn userinfo_claims() -> nazo_auth::Claims {
    serde_json::from_value(serde_json::json!({
        "iss": "https://issuer.example", "sub": USER, "tenant_id": TENANT,
        "user_id": USER, "subject_type": "user", "client_id": "client",
        "client_epoch": 0, "user_epoch": 0, "aud": "https://api.example",
        "scope": "openid profile", "token_use": "access", "jti": "userinfo-jti",
        "iat": 0, "nbf": 0, "exp": 1, "cnf": null
    }))
    .unwrap()
}

#[test]
fn userinfo_snapshot_rechecks_current_revocation_epochs_and_ownership() {
    block_on(async {
        let (database, provider) = fixture().await;
        database.execute_sql(&format!(
            "INSERT INTO nazo_subjects(tenant_id,subject,user_id) VALUES('{TENANT}','pairwise','{USER}')"
        )).unwrap();
        let claims = userinfo_claims();
        let pairwise = nazo_auth::Claims {
            user_id: None,
            sub: "pairwise".into(),
            ..claims.clone()
        };
        let legacy = nazo_auth::Claims {
            client_epoch: None,
            user_epoch: None,
            ..pairwise.clone()
        };
        for value in [&claims, &pairwise, &legacy] {
            let result = provider
                .userinfo_snapshot(TENANT, value)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.subject.subject.as_uuid(), USER);
            let client = result.client.unwrap();
            assert!(client.is_active);
            assert!(client.signed_response_alg.is_none());
            assert!(client.encrypted_response_alg.is_none());
            assert!(client.encrypted_response_enc.is_none());
            assert!(client.jwks_uri.is_none());
            assert!(client.jwks.is_none());
            assert!(!client.require_fapi2);
        }
        for invalid in [
            nazo_auth::Claims {
                client_epoch: Some(1),
                ..claims.clone()
            },
            nazo_auth::Claims {
                user_epoch: Some(1),
                ..claims.clone()
            },
            nazo_auth::Claims {
                client_epoch: None,
                ..claims.clone()
            },
            nazo_auth::Claims {
                user_epoch: None,
                ..claims.clone()
            },
            nazo_auth::Claims {
                client_epoch: Some(-1),
                ..claims.clone()
            },
            nazo_auth::Claims {
                user_epoch: Some(-1),
                ..claims.clone()
            },
            nazo_auth::Claims {
                user_id: Some("bad-user-id".into()),
                ..pairwise.clone()
            },
            nazo_auth::Claims {
                user_id: Some(Uuid::from_u128(100).to_string()),
                ..pairwise.clone()
            },
            nazo_auth::Claims {
                sub: "missing-binding".into(),
                ..pairwise.clone()
            },
            nazo_auth::Claims {
                client_id: "missing-client".into(),
                ..claims.clone()
            },
            nazo_auth::Claims {
                subject_type: "client".into(),
                ..claims.clone()
            },
            nazo_auth::Claims {
                tenant_id: Uuid::from_u128(100).to_string(),
                ..claims.clone()
            },
        ] {
            assert!(
                provider
                    .userinfo_snapshot(TENANT, &invalid)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            provider
                .userinfo_snapshot(Uuid::from_u128(100), &claims)
                .await
                .is_err()
        );
        let missing_client = nazo_auth::Claims {
            client_id: "missing-client".into(),
            ..legacy.clone()
        };
        assert!(
            provider
                .userinfo_snapshot(TENANT, &missing_client)
                .await
                .unwrap()
                .unwrap()
                .client
                .is_none()
        );
        database
            .execute_sql(
                "UPDATE nazo_users SET epoch=1,claims=json_set(claims,'$.name','fresh-profile')",
            )
            .unwrap();
        assert!(
            provider
                .userinfo_snapshot(TENANT, &claims)
                .await
                .unwrap()
                .is_none()
        );
        let current = nazo_auth::Claims {
            user_epoch: Some(1),
            ..claims.clone()
        };
        assert_eq!(
            provider
                .userinfo_snapshot(TENANT, &current)
                .await
                .unwrap()
                .unwrap()
                .subject
                .name
                .as_deref(),
            Some("fresh-profile")
        );
        assert!(
            provider
                .userinfo_snapshot(TENANT, &legacy)
                .await
                .unwrap()
                .is_some()
        );
        database
            .execute_sql("UPDATE nazo_clients SET epoch=1")
            .unwrap();
        assert!(
            provider
                .userinfo_snapshot(TENANT, &current)
                .await
                .unwrap()
                .is_none()
        );
        let current = nazo_auth::Claims {
            client_epoch: Some(1),
            ..current
        };
        assert!(
            provider
                .userinfo_snapshot(TENANT, &current)
                .await
                .unwrap()
                .is_some()
        );
        let jti = blake3::hash(claims.jti.as_bytes()).to_hex();
        database.execute_sql(&format!(
            "INSERT INTO nazo_revocations(tenant_id,jti_hash,client_id,expires_at) VALUES('{TENANT}','{jti}','{}',9007199254740991)", support::CLIENT
        )).unwrap();
        for revoked in [&current, &legacy] {
            assert!(
                provider
                    .userinfo_snapshot(TENANT, revoked)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        database
            .execute_sql("DELETE FROM nazo_revocations; DELETE FROM nazo_subjects")
            .unwrap();
        assert!(
            provider
                .userinfo_snapshot(TENANT, &legacy)
                .await
                .unwrap()
                .is_none()
        );
        database
            .execute_sql("UPDATE nazo_clients SET active=0,epoch=epoch+1")
            .unwrap();
        assert!(
            provider
                .userinfo_snapshot(TENANT, &current)
                .await
                .unwrap()
                .is_none()
        );
        let direct_legacy = nazo_auth::Claims {
            client_epoch: None,
            user_epoch: None,
            ..claims
        };
        assert!(
            !provider
                .userinfo_snapshot(TENANT, &direct_legacy)
                .await
                .unwrap()
                .unwrap()
                .client
                .unwrap()
                .is_active
        );
        database
            .execute_sql("UPDATE nazo_clients SET active=1,epoch=epoch+1")
            .unwrap();
        assert!(
            provider
                .userinfo_snapshot(TENANT, &current)
                .await
                .unwrap()
                .is_none()
        );
        let current = nazo_auth::Claims {
            client_epoch: Some(3),
            ..current
        };
        assert!(
            provider
                .userinfo_snapshot(TENANT, &current)
                .await
                .unwrap()
                .is_some()
        );
        database
            .execute_sql("UPDATE nazo_users SET active=0,epoch=epoch+1")
            .unwrap();
        assert!(
            provider
                .userinfo_snapshot(TENANT, &direct_legacy)
                .await
                .unwrap()
                .is_none()
        );
        database
            .execute_sql("UPDATE nazo_users SET active=1,epoch=epoch+1")
            .unwrap();
        assert!(
            provider
                .userinfo_snapshot(TENANT, &current)
                .await
                .unwrap()
                .is_none()
        );
        let current = nazo_auth::Claims {
            user_epoch: Some(3),
            ..current
        };
        assert!(
            provider
                .userinfo_snapshot(TENANT, &current)
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn userinfo_reads_response_policy_without_unconsumed_registration_fields() {
    block_on(async {
        let (database, provider) = fixture().await;
        let claims = userinfo_claims();
        database.execute_sql("UPDATE nazo_clients SET registration=json_set(registration,'$.scopes',json('[5]'),'$.redirect_uris',json('[false]'))").unwrap();
        assert!(provider.client_by_id("client").await.is_err());
        assert!(
            provider
                .userinfo_snapshot(TENANT, &claims)
                .await
                .unwrap()
                .is_some()
        );
        database.execute_sql("UPDATE nazo_clients SET registration=json_set(registration,'$.userinfo_signed_response_alg','ES256','$.security_policy.assurance','fapi2')").unwrap();
        let client = provider
            .userinfo_snapshot(TENANT, &claims)
            .await
            .unwrap()
            .unwrap()
            .client
            .unwrap();
        assert_eq!(client.signed_response_alg.as_deref(), Some("ES256"));
        assert!(client.require_fapi2);
    });
}

#[test]
fn userinfo_keeps_complete_security_policy_validation() {
    block_on(async {
        for update in [
            "registration=json_set(registration,'$.security_policy.version',2)",
            "registration=json_set(registration,'$.security_policy.unknown_security_rule',json('true'))",
            "registration=json_set(registration,'$.security_policy.assurance','future-assurance')",
            "registration=json_set(registration,'$.security_policy.assurance','fapi2','$.security_policy.authorization_code_profile','oauth21')",
            "registration=json_set(registration,'$.userinfo_signed_response_alg',7)",
        ] {
            let (database, provider) = fixture().await;
            database
                .execute_sql(&format!("UPDATE nazo_clients SET {update}"))
                .unwrap();
            assert!(
                provider
                    .userinfo_snapshot(TENANT, &userinfo_claims())
                    .await
                    .is_err()
            );
        }
    });
}

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
                .userinfo_snapshot(TENANT, &userinfo_claims())
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
                .userinfo_snapshot(TENANT, &userinfo_claims())
                .await
                .is_err()
        );
    });
}

#[test]
fn provisioning_requires_the_client_and_account_rows_to_be_written() {
    block_on(async {
        let (database, provider) = fixture().await;
        let tenant = TenantId::new(TENANT).unwrap();
        let user = UserId::new(USER).unwrap();
        let account = provider
            .public_account_by_id(tenant, user)
            .await
            .unwrap()
            .unwrap();
        let subject = provider
            .active_subject_claims(TENANT, USER, &USER.to_string())
            .await
            .unwrap()
            .unwrap();
        database.execute_sql(
            "DELETE FROM nazo_clients; DELETE FROM nazo_users;
             CREATE TRIGGER ignore_client BEFORE INSERT ON nazo_clients BEGIN SELECT RAISE(IGNORE); END;
             CREATE TRIGGER ignore_user BEFORE INSERT ON nazo_users BEGIN SELECT RAISE(IGNORE); END;"
        ).unwrap();
        assert!(
            provider
                .provision_client(&support::client(), None, 0)
                .await
                .is_err()
        );
        assert!(
            provider
                .provision_user(
                    &account,
                    &subject.claims,
                    nazo_identity::ports::PasswordHashInput::new("$argon2id$fixture").unwrap(),
                )
                .await
                .is_err()
        );
        assert!(provider.client_by_id("client").await.unwrap().is_none());
        assert!(
            provider
                .public_account_by_id(tenant, user)
                .await
                .unwrap()
                .is_none()
        );
    });
}
