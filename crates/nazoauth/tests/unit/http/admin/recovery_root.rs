use super::*;
use crate::test_support::admin_mutations::{LiveAdminUsersFixture, admin_user_dependencies};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::{
    sql_query,
    sql_types::{BigInt, Text},
};
use diesel_async::RunQueryDsl;
use nazo_postgres::{RecoveryRootRepository, get_conn};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use uuid::Uuid;

#[actix_web::test]
async fn recovery_root_handlers_commit_approval_rotation_and_registered_audit() {
    let Some(fixture) = LiveAdminUsersFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-recovery-admin"), "admin", 10)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let deployment = Uuid::now_v7().to_string();
    let repository = Arc::new(RecoveryRootRepository::new(fixture.state.diesel_db.clone()));
    let recovery = Data::new(RecoveryRootService::new(repository.clone(), &deployment));
    let control = fixture.state.settings.tenant.context.tenant_id;
    for (generation, seed) in [(1, 21), (2, 22)] {
        let public_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let change = RecoveryRootChangeRequest {
            deployment_id: deployment.clone(),
            recovery_public_key: URL_SAFE_NO_PAD.encode(public_key),
            kid: URL_SAFE_NO_PAD.encode(Sha256::digest(public_key)),
        };
        let (sessions, _, _) = admin_user_dependencies(&fixture.state);
        let response = crate::adapters::audit::REQUEST_TENANT
            .scope(
                control,
                admin_recovery_root_approval(
                    sessions,
                    recovery.clone(),
                    fixture.admin_post_request(
                        &sid,
                        &csrf,
                        "/admin/controller-registry/recovery-root/approvals",
                    ),
                    Json(change.clone()),
                ),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            fixture
                .audit_count(
                    "controller_recovery_root_rotation_approved",
                    "deployment_id",
                    &deployment
                )
                .await,
            generation
        );
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type=BigInt)]
            count: i64,
        }
        let mut conn = get_conn(&fixture.state.diesel_db).await.unwrap();
        let pending=sql_query("SELECT COUNT(*)::bigint AS count FROM controller_identity_approvals WHERE deployment_id=$1 AND consumed_at IS NULL").bind::<Text,_>(&deployment).get_result::<Count>(&mut conn).await.unwrap();
        assert_eq!(pending.count, 1);
        drop(conn);
        let (sessions, _, _) = admin_user_dependencies(&fixture.state);
        let response = crate::adapters::audit::REQUEST_TENANT
            .scope(
                control,
                admin_recovery_root_rotate(
                    sessions,
                    recovery.clone(),
                    fixture.admin_post_request(
                        &sid,
                        &csrf,
                        "/admin/controller-registry/recovery-root/rotate",
                    ),
                    Json(RotateRecoveryRootBody {
                        approval_token: body["approval_token"].as_str().unwrap().to_owned(),
                        deployment_id: deployment.clone(),
                        recovery_public_key: change.recovery_public_key,
                        kid: change.kid.clone(),
                    }),
                ),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let root = repository.current_root(&deployment).await.unwrap().unwrap();
        assert_eq!(i64::from(root.generation), generation);
        assert_eq!(root.recovery_kid, change.kid);
        assert_eq!(root.recovery_public_key, public_key.to_vec());
        assert_eq!(
            fixture
                .audit_count(
                    "controller_recovery_root_rotated",
                    "deployment_id",
                    &deployment
                )
                .await,
            generation
        );
        let mut conn = get_conn(&fixture.state.diesel_db).await.unwrap();
        let pending=sql_query("SELECT COUNT(*)::bigint AS count FROM controller_identity_approvals WHERE deployment_id=$1 AND consumed_at IS NULL").bind::<Text,_>(&deployment).get_result::<Count>(&mut conn).await.unwrap();
        assert_eq!(pending.count, 0);
    }
}
