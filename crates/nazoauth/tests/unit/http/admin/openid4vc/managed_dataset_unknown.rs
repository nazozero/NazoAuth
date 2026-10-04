//! Hide an ACK only after the real PG mutation owner has committed.
use super::*;
use nazo_openid4vci::CredentialStoreError;
use nazo_persistence::{
    ManagedCredentialDataset, ManagedCredentialDatasetWrite, Openid4vciDatasetStore,
};

struct HiddenDatasetCommitAck {
    inner: nazo_postgres::Openid4vciDatasetRepository,
}

impl Openid4vciDatasetStore for HiddenDatasetCommitAck {
    fn dataset<'a>(
        &'a self,
        tenant: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<Value>, CredentialStoreError>> {
        Box::pin(async move { self.inner.dataset(tenant, subject, configuration).await })
    }
    fn managed_dataset<'a>(
        &'a self,
        tenant: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<ManagedCredentialDataset>, CredentialStoreError>,
    > {
        Openid4vciDatasetStore::managed_dataset(&self.inner, tenant, subject, configuration)
    }
    fn upsert_managed_dataset(
        &self,
        write: ManagedCredentialDatasetWrite,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Option<ManagedCredentialDataset>, CredentialStoreError>,
    > {
        Box::pin(async move {
            let committed =
                Openid4vciDatasetStore::upsert_managed_dataset(&self.inner, write).await?;
            if committed.is_some() {
                Err(CredentialStoreError::Unavailable)
            } else {
                Ok(committed)
            }
        })
    }
    fn delete_managed_dataset<'a>(
        &'a self,
        tenant: Uuid,
        actor: Uuid,
        subject: Uuid,
        configuration: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let committed = self
                .inner
                .delete_managed_dataset(tenant, actor, subject, configuration)
                .await?;
            if committed {
                Err(CredentialStoreError::Unavailable)
            } else {
                Ok(false)
            }
        })
    }
}

#[derive(diesel::QueryableByName)]
struct Evidence {
    #[diesel(sql_type=diesel::sql_types::Jsonb)]
    value: Value,
}

async fn evidence(fixture: &LiveOpenid4vcAdminFixture, subject: Uuid) -> Value {
    let mut connection = get_conn(&fixture.state.diesel_db).await.unwrap();
    sql_query("SELECT jsonb_build_object('dataset_count',(SELECT COUNT(*) FROM openid4vci_credential_datasets WHERE tenant_id=$1 AND subject_id=$2 AND credential_configuration_id='unit-config'),'source_events',COALESCE((SELECT jsonb_agg(action ORDER BY created_at,id) FROM openid4vci_credential_dataset_events WHERE tenant_id=$1 AND subject_id=$2 AND credential_configuration_id='unit-config'),'[]'::jsonb),'required_events',COALESCE((SELECT jsonb_agg(payload || jsonb_build_object('event_type',event_type) ORDER BY occurred_at,event_id) FROM security_audit_events WHERE payload->>'tenant_id'=$1::text AND payload->>'subject_id'=$2::text AND payload->>'credential_configuration_id'='unit-config' AND event_type IN ('openid4vci_credential_dataset_updated','openid4vci_credential_dataset_deleted')),'[]'::jsonb)) AS value")
        .bind::<SqlUuid,_>(DEFAULT_TENANT_ID).bind::<SqlUuid,_>(subject)
        .get_result::<Evidence>(&mut connection).await.unwrap().value
}

#[actix_web::test]
async fn hidden_committed_dataset_ack_is_503_with_durable_effect_and_required_evidence() {
    let Some(fixture) = LiveOpenid4vcAdminFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10, true)
        .await;
    let subject = fixture
        .create_user(&format!("{suffix}-subject"), "user", 0, false)
        .await;
    let sid = format!("dataset-unknown-{suffix}");
    let csrf = format!("dataset-csrf-{suffix}");
    fixture.store_session(&admin, &sid, true).await;
    let repository = nazo_postgres::Openid4vciDatasetRepository::new(
        fixture.state.diesel_db.clone(),
        [0x51; 32],
    );
    let endpoint = fixture
        .endpoint_with_dataset_store(
            true,
            Some(Arc::new(HiddenDatasetCommitAck {
                inner: repository.clone(),
            })),
        )
        .await;
    let body = std::panic::AssertUnwindSafe(async {
        let response = admin_put_credential_dataset(
            fixture.sessions(),
            endpoint.clone(),
            fixture.post_request(&sid, Some(&csrf), "/admin/openid4vci/credential-datasets"),
            Path::from((subject.id, "unit-config".to_owned())),
            Json(PutCredentialDatasetRequest {
                claims: json!({"given_name":"committed","age_over_18":true}),
                valid_from: None,
                valid_until: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let response: Value = serde_json::from_slice(
            &actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["error"], "server_error");
        assert!(response.get("claims").is_none());
        assert_eq!(
            repository
                .managed_dataset(DEFAULT_TENANT_ID, subject.id, "unit-config")
                .await
                .unwrap()
                .unwrap()
                .claims["given_name"],
            "committed"
        );
        let after_put = evidence(&fixture, subject.id).await;
        assert_eq!(after_put["dataset_count"], 1);
        assert_eq!(after_put["source_events"], json!([1]));
        assert_eq!(after_put["required_events"].as_array().unwrap().len(), 1);
        assert_eq!(
            after_put["required_events"][0]["admin_user_id"],
            admin.id.to_string()
        );
        assert_eq!(
            after_put["required_events"][0]["event_type"],
            "openid4vci_credential_dataset_updated"
        );
        assert_eq!(
            after_put["required_events"][0]["schema_version"],
            nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION
        );
        assert!(after_put["required_events"][0].get("claims").is_none());
        let response = admin_delete_credential_dataset(
            fixture.sessions(),
            endpoint.clone(),
            fixture.post_request(&sid, Some(&csrf), "/admin/openid4vci/credential-datasets"),
            Path::from((subject.id, "unit-config".to_owned())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            repository
                .managed_dataset(DEFAULT_TENANT_ID, subject.id, "unit-config")
                .await
                .unwrap(),
            None
        );
        let after_delete = evidence(&fixture, subject.id).await;
        assert_eq!(after_delete["dataset_count"], 0);
        assert_eq!(after_delete["source_events"], json!([1, 2]));
        assert_eq!(after_delete["required_events"].as_array().unwrap().len(), 2);
        assert_eq!(
            after_delete["required_events"][1]["event_type"],
            "openid4vci_credential_dataset_deleted"
        );
        // A missing row remains a no-op; no fresh accepting outcome is appended.
        assert!(
            !repository
                .delete_managed_dataset(DEFAULT_TENANT_ID, admin.id, subject.id, "unit-config")
                .await
                .unwrap()
        );
        assert_eq!(evidence(&fixture, subject.id).await, after_delete);
    });
    let result = futures_util::FutureExt::catch_unwind(body).await;
    fixture.cleanup().await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
