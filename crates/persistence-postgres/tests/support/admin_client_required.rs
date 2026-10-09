//! Real client mutation owners: canonical rollback, current actor and hidden ACK.
use super::*;
use diesel_async::SimpleAsyncConnection;
use futures_util::FutureExt as _;
use nazo_auth::{
    AdminClientCryptoPort, AdminClientFuture, AdminClientPolicy, AdminClientPortError,
    AdminClientRepositoryPort, AdminClientService, CreateClientRequest, PatchClientRequest,
    SectorIdentifierFuture, SectorIdentifierResolverPort,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

async fn actor(connection: &mut diesel_async::AsyncPgConnection) -> Uuid {
    let id = Uuid::now_v7();
    sql_query("INSERT INTO users (id, username, email, password_hash, role, admin_level) VALUES ($1,$1::text,$1::text || '@example.test','test-only','admin',10)")
        .bind::<SqlUuid, _>(id).execute(connection).await.unwrap();
    id
}

#[derive(diesel::QueryableByName)]
struct Snapshot {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    value: serde_json::Value,
}

async fn snapshot(
    connection: &mut diesel_async::AsyncPgConnection,
    client: &OAuthClient,
) -> serde_json::Value {
    // A whole-row fingerprint checks verifier and metadata preservation without
    // putting verifier material in a failing assertion's diagnostic output.
    sql_query("SELECT jsonb_build_object('rows',(SELECT count(*) FROM oauth_clients WHERE tenant_id=$1 AND id=$2),'fingerprint',(SELECT md5(to_jsonb(c)::text) FROM oauth_clients c WHERE tenant_id=$1 AND id=$2),'audit',COALESCE((SELECT jsonb_agg(payload ORDER BY event_id) FROM security_audit_events WHERE event_type IN ('client_created','client_updated') AND payload->>'client_pk'=$2::text),'[]'::jsonb)) AS value")
        .bind::<SqlUuid, _>(client.tenant_id).bind::<SqlUuid, _>(client.id)
        .get_result::<Snapshot>(connection).await.unwrap().value
}

async fn install_failure(
    connection: &mut diesel_async::AsyncPgConnection,
    client: &OAuthClient,
) -> String {
    let name = format!("admin_client_required_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture required append failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type IN ('client_created','client_updated') AND NEW.payload->>'client_pk'='{}') EXECUTE FUNCTION {name}();", client.id,
    )).await.unwrap();
    name
}

async fn remove_failure(connection: &mut diesel_async::AsyncPgConnection, name: &str) {
    connection
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();"
        ))
        .await
        .expect("fixture-owned fault cleanup");
}

#[tokio::test]
async fn admin_client_required_ledger_failure_rolls_back_insert_and_exact_cas() {
    let Some(pool) = test_pool() else {
        return;
    };
    let repo = OAuthClientRepository::new(pool.clone());
    let mut connection = get_conn(&pool).await.unwrap();
    let actor_id = actor(&mut connection).await;
    let original = client(TenantContext::default_system());
    let empty = snapshot(&mut connection, &original).await;
    let fault = install_failure(&mut connection, &original).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert!(
            repo.insert_with_required_audit(
                &original,
                Some("client-secret-v1:fixture-salt:fixture-digest"),
                None,
                actor_id,
                "fixture-source"
            )
            .await
            .is_err()
        );
        assert_eq!(snapshot(&mut connection, &original).await, empty);
    })
    .catch_unwind()
    .await;
    remove_failure(&mut connection, &fault).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    let written = repo
        .insert_with_required_audit(
            &original,
            Some("client-secret-v1:fixture-salt:fixture-digest"),
            None,
            actor_id,
            "fixture-source",
        )
        .await
        .unwrap();
    let before = snapshot(&mut connection, &written).await;
    assert_eq!(before["audit"].as_array().unwrap().len(), 1);
    assert_eq!(
        before["audit"][0]["admin_user_id"],
        serde_json::json!(actor_id)
    );
    let mut patched = written.clone();
    patched.client_name = "Required updated client".to_owned();
    let fault = install_failure(&mut connection, &written).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert!(
            repo.update_with_required_audit(&written, &patched, actor_id, "fixture-source")
                .await
                .is_err()
        );
        assert_eq!(snapshot(&mut connection, &written).await, before);
    })
    .catch_unwind()
    .await;
    remove_failure(&mut connection, &fault).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    let returned = repo
        .update_with_required_audit(&written, &patched, actor_id, "fixture-source")
        .await
        .unwrap();
    assert_eq!(returned, patched);
    let after = snapshot(&mut connection, &written).await;
    assert_eq!(after["audit"].as_array().unwrap().len(), 2);
    assert_ne!(after["fingerprint"], before["fingerprint"]);
    assert!(
        repo.update_with_required_audit(&written, &patched, actor_id, "fixture-source")
            .await
            .is_err(),
        "exact stale CAS still denied"
    );
    assert_eq!(snapshot(&mut connection, &written).await, after);
}

#[tokio::test]
async fn admin_client_required_current_actor_denies_inactive_demoted_and_wrong_context() {
    let Some(pool) = test_pool() else {
        return;
    };
    let repo = OAuthClientRepository::new(pool.clone());
    let mut connection = get_conn(&pool).await.unwrap();
    let actor_id = actor(&mut connection).await;
    let existing = repo
        .insert(&client(TenantContext::default_system()), None, None)
        .await
        .unwrap();
    let mut patched = existing.clone();
    patched.client_name = "Denied mutation".to_owned();
    let before = snapshot(&mut connection, &existing).await;
    let new_client = client(TenantContext::default_system());
    let empty = snapshot(&mut connection, &new_client).await;
    for denied in ["inactive", "demoted", "wrong-context"] {
        match denied {
            "inactive" => {
                sql_query("UPDATE users SET is_active=false WHERE id=$1")
                    .bind::<SqlUuid, _>(actor_id)
                    .execute(&mut connection)
                    .await
                    .unwrap();
            }
            "demoted" => {
                sql_query("UPDATE users SET is_active=true,role='user',admin_level=0 WHERE id=$1")
                    .bind::<SqlUuid, _>(actor_id)
                    .execute(&mut connection)
                    .await
                    .unwrap();
            }
            _ => {
                let realm = Uuid::now_v7();
                sql_query("INSERT INTO realms (id,tenant_id,slug,display_name) VALUES ($1,$2,$1::text,'Required actor context')")
                    .bind::<SqlUuid,_>(realm).bind::<SqlUuid,_>(existing.tenant_id).execute(&mut connection).await.unwrap();
                sql_query("UPDATE users SET is_active=true,role='admin',admin_level=10,realm_id=$2 WHERE id=$1")
                    .bind::<SqlUuid,_>(actor_id).bind::<SqlUuid,_>(realm).execute(&mut connection).await.unwrap();
            }
        }
        assert!(
            repo.insert_with_required_audit(&new_client, None, None, actor_id, "fixture-source")
                .await
                .is_err(),
            "{denied} actor must deny insert"
        );
        assert!(
            repo.update_with_required_audit(&existing, &patched, actor_id, "fixture-source")
                .await
                .is_err(),
            "{denied} actor must deny update"
        );
        assert_eq!(snapshot(&mut connection, &existing).await, before);
        assert_eq!(snapshot(&mut connection, &new_client).await, empty);
    }
}

#[derive(Clone)]
struct HiddenCommitAck {
    inner: OAuthClientRepository,
    committed: Arc<Mutex<Vec<Uuid>>>,
}

impl AdminClientRepositoryPort for HiddenCommitAck {
    fn page(
        &self,
        tenant: Uuid,
        offset: i64,
        limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        AdminClientRepositoryPort::page(&self.inner, tenant, offset, limit)
    }
    fn by_client_id<'a>(
        &'a self,
        tenant: Uuid,
        id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        AdminClientRepositoryPort::by_client_id(&self.inner, tenant, id)
    }
    fn insert<'a>(
        &'a self,
        client: &'a OAuthClient,
        secret: Option<&'a str>,
        token: Option<&'a str>,
    ) -> AdminClientFuture<'a, OAuthClient> {
        AdminClientRepositoryPort::insert(&self.inner, client, secret, token)
    }
    fn update<'a>(
        &'a self,
        expected: &'a OAuthClient,
        client: &'a OAuthClient,
    ) -> AdminClientFuture<'a, OAuthClient> {
        AdminClientRepositoryPort::update(&self.inner, expected, client)
    }
    fn insert_with_required_audit<'a>(
        &'a self,
        client: &'a OAuthClient,
        secret: Option<&'a str>,
        token: Option<&'a str>,
        actor: Uuid,
        source: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async move {
            let committed = self
                .inner
                .insert_with_required_audit(client, secret, token, actor, source)
                .await?;
            self.committed.lock().unwrap().push(committed.id);
            Err(AdminClientPortError::Unavailable)
        })
    }
    fn update_with_required_audit<'a>(
        &'a self,
        expected: &'a OAuthClient,
        client: &'a OAuthClient,
        actor: Uuid,
        source: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async move {
            let committed = self
                .inner
                .update_with_required_audit(expected, client, actor, source)
                .await?;
            self.committed.lock().unwrap().push(committed.id);
            Err(AdminClientPortError::Unavailable)
        })
    }
}

struct NoDocuments;
impl SectorIdentifierResolverPort for NoDocuments {
    fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async { Err("unexpected fixture document fetch".to_owned()) })
    }
}
struct FixtureCrypto;
impl AdminClientCryptoPort for FixtureCrypto {
    fn response_signing_algorithms(&self) -> Vec<String> {
        vec!["RS256".to_owned()]
    }
    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        (
            format!("fixture-secret-{}", Uuid::now_v7()),
            "client-secret-v1:fixture-salt:fixture-digest".to_owned(),
        )
    }
    fn validate_jwks(&self, _jwks: &serde_json::Value) -> Result<(), String> {
        Ok(())
    }
    fn validate_rfc4514_dn(&self, _value: &str) -> Result<(), String> {
        Ok(())
    }
    fn matching_encryption_key_count(&self, _jwks: &serde_json::Value, _algorithm: &str) -> usize {
        0
    }
    fn contains_signing_key(&self, _jwks: &serde_json::Value) -> bool {
        false
    }
    fn valid_self_signed_mtls_jwks(&self, _jwks: &serde_json::Value) -> bool {
        false
    }
}

#[tokio::test]
async fn admin_client_required_hidden_committed_ack_withholds_secret_and_updated_receipt() {
    let Some(pool) = test_pool() else {
        return;
    };
    let repo = OAuthClientRepository::new(pool.clone());
    let mut connection = get_conn(&pool).await.unwrap();
    let actor_id = actor(&mut connection).await;
    let committed = Arc::new(Mutex::new(Vec::new()));
    let service = AdminClientService::new(
        HiddenCommitAck {
            inner: repo.clone(),
            committed: committed.clone(),
        },
        NoDocuments,
        FixtureCrypto,
        AdminClientPolicy {
            tenant: TenantContext::default_system(),
            pairwise_subject_secret: None,
            client_secret_pepper: "fixture-only".to_owned(),
        },
    );
    let request: CreateClientRequest = serde_json::from_value(serde_json::json!({
        "client_name":"Required unknown ACK", "client_type":"confidential",
        "redirect_uris":["https://client.example/callback"],"scopes":["openid"],
        "allowed_audiences":[],"grant_types":["authorization_code"],
        "token_endpoint_auth_method":"client_secret_basic","jwks":null,
    }))
    .unwrap();
    let result = service
        .create_with_required_audit(request, actor_id, "fixture-source")
        .await;
    assert!(
        matches!(
            result,
            Err(nazo_auth::AdminClientError::Write(
                AdminClientPortError::Unavailable
            ))
        ),
        "actual committed ACK hidden: no CreatedClient/secret receipt"
    );
    let id = committed.lock().unwrap()[0];
    let accepted = repo
        .by_id(TenantContext::default_system().tenant_id.as_uuid(), id)
        .await
        .unwrap()
        .unwrap();
    let before = snapshot(&mut connection, &accepted).await;
    assert_eq!(before["rows"], serde_json::json!(1));
    assert_eq!(before["audit"].as_array().unwrap().len(), 1);
    let result = service
        .update_with_required_audit(
            &accepted.client_id,
            PatchClientRequest {
                client_name: Some("Committed with hidden update ACK".to_owned()),
                ..Default::default()
            },
            actor_id,
            "fixture-source",
        )
        .await;
    assert!(matches!(
        result,
        Err(nazo_auth::AdminClientError::Write(
            AdminClientPortError::Unavailable
        ))
    ));
    let after = snapshot(&mut connection, &accepted).await;
    assert_eq!(after["audit"].as_array().unwrap().len(), 2);
    assert_eq!(*committed.lock().unwrap(), vec![id, id]);
    assert_ne!(before["fingerprint"], after["fingerprint"]);
}

struct BareOnly {
    calls: AtomicUsize,
}
impl AdminClientRepositoryPort for BareOnly {
    fn page(
        &self,
        _tenant: Uuid,
        _offset: i64,
        _limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        Box::pin(async { Ok((Vec::new(), 0)) })
    }
    fn by_client_id<'a>(
        &'a self,
        _tenant: Uuid,
        _id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        Box::pin(async { Ok(None) })
    }
    fn insert<'a>(
        &'a self,
        client: &'a OAuthClient,
        _secret: Option<&'a str>,
        _token: Option<&'a str>,
    ) -> AdminClientFuture<'a, OAuthClient> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(client.clone()) })
    }
    fn update<'a>(
        &'a self,
        _expected: &'a OAuthClient,
        client: &'a OAuthClient,
    ) -> AdminClientFuture<'a, OAuthClient> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(client.clone()) })
    }
}

#[tokio::test]
async fn admin_client_required_ports_have_no_bare_repository_fallback() {
    let repo = Arc::new(BareOnly {
        calls: AtomicUsize::new(0),
    });
    let client = client(TenantContext::default_system());
    assert!(matches!(
        repo.insert_with_required_audit(&client, None, None, Uuid::now_v7(), "fixture-source")
            .await,
        Err(AdminClientPortError::Unavailable)
    ));
    assert!(matches!(
        repo.update_with_required_audit(&client, &client, Uuid::now_v7(), "fixture-source")
            .await,
        Err(AdminClientPortError::Unavailable)
    ));
    assert_eq!(AtomicUsize::load(&repo.calls, Ordering::SeqCst), 0);
}
