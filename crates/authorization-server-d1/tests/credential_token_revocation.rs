#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AccessTokenClaimsInput, AppliedSenderConstraint, Claims, TokenRepositoryPort,
    access_token_claims,
};
use nazo_identity::{
    TenantId,
    ports::{SecretVerifyFuture, SecretVerifyPort},
};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::D1Provider;
use nazo_openid4vci::{CredentialAccess, CredentialProofOrigin};
use nazo_resource_server::{AccessTokenRevocationLookup, RevocationLookupKey};
use serde_json::json;
use std::sync::Arc;
use support::{CLIENT, TENANT, USER, fixture};
use uuid::Uuid;

fn credential_claims(client_id: &str) -> Claims {
    // Match the shared pre-authorized issuer's claims construction. Epochs are
    // intentionally absent; its separate retained authorization is authoritative.
    access_token_claims(
        "https://issuer.example",
        AccessTokenClaimsInput {
            authorization_id: Some(Uuid::new_v4()),
            client_epoch: None,
            user_epoch: None,
            tenant_id: TENANT,
            subject: &USER.to_string(),
            user_id: Some(USER),
            subject_type: "user",
            client_id,
            audiences: &["https://issuer.example".into()],
            scopes: &[],
            authorization_details: &json!([{
                "type": "openid_credential", "credential_configuration_id": "pid",
                "locations": ["https://issuer.example"]
            }]),
            userinfo_claim_requests: &[],
            ttl: 600,
            sender_constraint: AppliedSenderConstraint::Bearer,
            actor: None,
        },
        Timestamp::now().as_second(),
        &Uuid::new_v4().to_string(),
    )
}

async fn assert_both_ports(provider: &D1Provider, tenant: Uuid, claims: &Claims, revoked: bool) {
    assert_eq!(
        provider.access_token_revoked(tenant, claims).await.unwrap(),
        revoked
    );
    assert_eq!(
        provider
            .is_revoked(RevocationLookupKey {
                client_id: &claims.client_id,
                subject: &claims.sub,
                user_id: claims.user_id.as_deref(),
                subject_type: Some(&claims.subject_type),
                client_epoch: claims.client_epoch,
                user_epoch: claims.user_epoch,
                tenant_id: &claims.tenant_id,
                jti: &claims.jti,
            })
            .await
            .unwrap(),
        revoked
    );
}

#[test]
fn registered_and_anonymous_preauthorized_tokens_use_native_individual_revocation() {
    block_on(async {
        let (_, provider) = fixture().await;
        for client in ["client", "pre-authorized-wallet"] {
            let claims = credential_claims(client);
            assert_both_ports(&provider, TENANT, &claims, false).await;
            provider
                .revoke_issued_tokens(
                    TENANT,
                    CLIENT,
                    &claims.jti,
                    Some(Timestamp::from_second(claims.exp).unwrap()),
                    None,
                )
                .await
                .unwrap();
            assert_both_ports(&provider, TENANT, &claims, true).await;
            let mut fresh = claims;
            fresh.jti = Uuid::new_v4().to_string();
            assert_both_ports(&provider, TENANT, &fresh, false).await;
        }
    });
}

#[test]
fn epochless_lookup_remains_tenant_scoped_and_rejects_inconsistent_epochs() {
    block_on(async {
        let (database, provider) = fixture().await;
        let mut claims = credential_claims("client");
        for epoch in [-1, 0, 1] {
            claims.user_epoch = Some(epoch);
            assert_both_ports(&provider, TENANT, &claims, true).await;
        }
        claims.user_epoch = None;
        provider
            .revoke_issued_tokens(
                TENANT,
                CLIENT,
                &claims.jti,
                Some(Timestamp::from_second(claims.exp).unwrap()),
                None,
            )
            .await
            .unwrap();
        assert_both_ports(&provider, TENANT, &claims, true).await;

        let other_tenant = Uuid::new_v4();
        let other = D1Provider::new(database, TenantId::new(other_tenant).unwrap());
        claims.tenant_id = other_tenant.to_string();
        assert_both_ports(&provider, TENANT, &claims, true).await;
        assert_both_ports(&other, other_tenant, &claims, false).await;
    });
}

#[test]
fn epoch_bound_oauth_tokens_keep_principal_state_checks() {
    block_on(async {
        let (database, provider) = fixture().await;
        let mut claims = credential_claims("client");
        claims.client_epoch = Some(0);
        claims.user_epoch = Some(0);
        assert_both_ports(&provider, TENANT, &claims, false).await;
        for (client_epoch, user_epoch) in [
            (Some(-1), Some(0)),
            (Some(0), Some(-1)),
            (Some(0), None),
            (Some(1), Some(0)),
            (Some(0), Some(1)),
        ] {
            claims.client_epoch = client_epoch;
            claims.user_epoch = user_epoch;
            assert_both_ports(&provider, TENANT, &claims, true).await;
        }
        claims.client_epoch = Some(0);
        claims.user_epoch = Some(0);
        database
            .execute_sql("UPDATE nazo_clients SET active=0")
            .unwrap();
        assert_both_ports(&provider, TENANT, &claims, true).await;
        database
            .execute_sql("UPDATE nazo_clients SET active=1")
            .unwrap();
        assert_both_ports(&provider, TENANT, &claims, false).await;
        database
            .execute_sql("UPDATE nazo_users SET epoch=epoch+1")
            .unwrap();
        assert_both_ports(&provider, TENANT, &claims, true).await;
    });
}

struct PasswordVerifier;
impl SecretVerifyPort for PasswordVerifier {
    fn verify_secret(
        &self,
        secret: String,
        hash: nazo_identity::PasswordHash,
    ) -> SecretVerifyFuture<'_> {
        Box::pin(async move { Ok(hash.verify_password(&secret)) })
    }
}

#[test]
fn epochless_credential_access_still_requires_live_retained_authority() {
    block_on(async {
        for mutation in [
            "UPDATE nazo_clients SET active=0",
            "UPDATE nazo_clients SET epoch=epoch+1",
            "UPDATE nazo_users SET active=0",
            "UPDATE nazo_users SET epoch=epoch+1",
        ] {
            let (database, provider) = fixture().await;
            let claims = credential_claims("client");
            let store = provider.openid4vci_store([37; 32], Arc::new(PasswordVerifier));
            assert_both_ports(&provider, TENANT, &claims, false).await;
            assert!(
                store
                    .resolve_access("token-hash", Timestamp::now())
                    .await
                    .unwrap()
                    .is_none()
            );
            let access = CredentialAccess {
                authorization_id: claims.authorization_id,
                mtls_x5t_s256: None,
                proof_origin: CredentialProofOrigin::RegisteredClient,
                token_id: Uuid::parse_str(&claims.jti).unwrap(),
                tenant_id: TENANT,
                subject_id: USER,
                client_id: claims.client_id.clone(),
                configuration_ids: vec!["pid".into()],
                credential_identifiers: Vec::new(),
                dpop_jkt: None,
                expires_at: Timestamp::from_second(claims.exp).unwrap(),
            };
            store.upsert_access("token-hash", &access).await.unwrap();
            assert_eq!(
                store
                    .resolve_access("token-hash", Timestamp::now())
                    .await
                    .unwrap(),
                Some(access.clone())
            );
            database.execute_sql(mutation).unwrap();
            // Individual revocation and credential grant retirement are separate
            // native authorities. The shared endpoint requires both to allow access.
            assert_both_ports(&provider, TENANT, &claims, false).await;
            assert!(
                store
                    .resolve_access("token-hash", Timestamp::now())
                    .await
                    .unwrap()
                    .is_none()
            );
            database
                .execute_sql("UPDATE nazo_users SET active=1; UPDATE nazo_clients SET active=1")
                .unwrap();
            store.upsert_access("token-hash", &access).await.unwrap();
            assert!(
                store
                    .resolve_access("token-hash", Timestamp::now())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .resolve_access(
                        "token-hash",
                        Timestamp::now() + SignedDuration::from_hours(1)
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    });
}
