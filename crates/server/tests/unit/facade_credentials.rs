use std::sync::Arc;

use actix_web::{App, test, web};
use bytes::Bytes;
use diesel::sql_types::{BigInt, Integer, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use http::{Method, Request, StatusCode, header};
use nazoauth::{NazoAuthBuilder, integration::conformance};
use serde_json::{Value, json};
use uuid::Uuid;

fn request(
    method: Method,
    path: &str,
    content_type: &str,
    body: impl Into<Bytes>,
) -> Request<Bytes> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, content_type)
        .body(body.into())
        .unwrap()
}

fn json_body(response: &http::Response<Bytes>) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{response:?}");
    serde_json::from_slice(response.body()).unwrap()
}

async fn seed_dataset(
    state: &crate::test_support::TestInfrastructure,
    capabilities: &nazoauth::capabilities::Capabilities,
) -> Uuid {
    let tenant = state.settings.tenant.context;
    let actor_id = Uuid::now_v7();
    let subject_id = Uuid::now_v7();
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    for (id, role, level) in [(actor_id, "admin", 1), (subject_id, "user", 0)] {
        diesel::sql_query(
            "INSERT INTO users
             (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level)
             VALUES ($1,$2,$3,$4,$5,$6,'facade-conformance-fixture',$7,$8)",
        )
        .bind::<SqlUuid, _>(id)
        .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
        .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
        .bind::<Text, _>(format!("facade-vci-{id}"))
        .bind::<Text, _>(format!("facade-vci-{id}@example.test"))
        .bind::<Text, _>(role)
        .bind::<Integer, _>(level)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    drop(connection);
    let stored = capabilities
        .persistence
        .provider()
        .openid4vci_datasets(state.settings.openid4vc.data_encryption_key.unwrap())
        .upsert_managed_dataset(nazo_persistence::ManagedCredentialDatasetWrite {
            tenant_id: tenant.tenant_id.as_uuid(),
            actor_user_id: actor_id,
            subject_id,
            credential_configuration_id: "unit-credential".to_owned(),
            claims: json!({"given_name": "Facade conformance", "sub": subject_id}),
            valid_from: None,
            valid_until: None,
        })
        .await
        .unwrap();
    assert!(stored.is_some());
    subject_id
}

#[actix_web::test]
async fn enabled_credential_issuer_replays_original_json_and_encrypted_bytes_through_actix() {
    let mut state = super::infrastructure(true).await;
    let accepting_modules = crate::test_support::facade::enable_credential_issuer(&mut state).await;
    let capabilities = crate::test_support::facade::capabilities(
        &state,
        crate::test_support::facade::PersistenceOverrides {
            accepting_modules: Some(accepting_modules),
            ..Default::default()
        },
    )
    .unwrap();
    let subject_id = seed_dataset(&state, &capabilities).await;
    let application = Arc::new(
        NazoAuthBuilder::new(
            state.settings.application_configuration(),
            capabilities,
            "credential-conformance",
        )
        .build()
        .await
        .unwrap(),
    );
    let app = test::init_service(
        App::new()
            .app_data(web::Data::from(application.clone()))
            .configure(nazo_http_actix::configure),
    )
    .await;
    conformance::assert_adapter(&application, |request| {
        let app = &app;
        async move {
            super::standard_response(
                test::call_service(app, super::framework_request(&request).to_request())
                    .await
                    .into_parts()
                    .1,
            )
            .await
        }
    })
    .await;

    let metadata = json_body(
        &application
            .handle(request(
                Method::GET,
                "/.well-known/openid-credential-issuer",
                "application/json",
                Bytes::new(),
            ))
            .await,
    );
    assert!(metadata["credential_configurations_supported"]["unit-credential"].is_object());
    let mut offer_request = request(
        Method::POST,
        "/openid4vci/offers",
        "application/json",
        serde_json::to_vec(&json!({
            "subject_id": subject_id,
            "credential_configuration_ids": ["unit-credential"],
            "grant_types": [nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT],
        }))
        .unwrap(),
    );
    offer_request.headers_mut().insert(
        header::AUTHORIZATION,
        format!(
            "Bearer {}",
            state
                .settings
                .openid4vc
                .issuer_management_token
                .as_ref()
                .unwrap()
        )
        .parse()
        .unwrap(),
    );
    let offer = json_body(&application.handle(offer_request).await);
    let code = offer["credential_offer"]["grants"][nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT]
        ["pre-authorized_code"]
        .as_str()
        .unwrap();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
        .append_pair("pre-authorized_code", code)
        .finish();
    let token = json_body(
        &application
            .handle(request(
                Method::POST,
                "/token",
                "application/x-www-form-urlencoded",
                form,
            ))
            .await,
    );
    assert_eq!(token["token_type"], "Bearer");
    let authorization = format!("Bearer {}", token["access_token"].as_str().unwrap());
    let wallet = nazo_digital_credentials::EphemeralEncryptionKey::derive(
        &[23; 32],
        b"facade-conformance-response",
    )
    .unwrap();
    for encrypted in [false, true] {
        let mut body = json!({
            "credential_identifier": token["authorization_details"][0]["credential_identifiers"][0],
        });
        let (content_type, bytes) = if encrypted {
            let mut jwk = wallet.public_jwk();
            jwk["alg"] = json!("ECDH-ES");
            body["credential_response_encryption"] = json!({"jwk": jwk, "enc": "A256GCM"});
            let jwt = nazo_digital_credentials::encrypt_ecdh_es(
                serde_json::to_vec(&body).unwrap(),
                &metadata["credential_request_encryption"]["jwks"]["keys"][0],
                Some("application/json"),
            )
            .unwrap();
            ("application/jwt", Bytes::from(jwt))
        } else {
            (
                "application/json",
                Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
        };
        let mut credential_request =
            request(Method::POST, "/openid4vci/credential", content_type, bytes);
        credential_request
            .headers_mut()
            .insert(header::AUTHORIZATION, authorization.parse().unwrap());
        let issued = application.handle(credential_request.clone()).await;
        assert_eq!(issued.status(), StatusCode::OK, "{issued:?}");
        assert_eq!(issued.headers()[header::CONTENT_TYPE], content_type);
        assert_eq!(issued.headers()[header::CACHE_CONTROL], "no-store");
        let credential = if encrypted {
            wallet
                .decrypt(std::str::from_utf8(issued.body()).unwrap())
                .unwrap()
        } else {
            issued.body().to_vec()
        };
        let credential: Value = serde_json::from_slice(&credential).unwrap();
        assert!(credential["credentials"][0]["credential"].is_string());
        let replay = application.handle(credential_request.clone()).await;
        conformance::assert_response(&issued, &replay);
        for _ in 0..2 {
            let replay = super::standard_response(
                test::call_service(
                    &app,
                    super::framework_request(&credential_request).to_request(),
                )
                .await
                .into_parts()
                .1,
            )
            .await;
            conformance::assert_response(&issued, &replay);
        }
    }
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        total: i64,
    }
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    let retained = diesel::sql_query(
        "SELECT COUNT(*) AS total FROM openid4vci_issuance_responses
         WHERE token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1)",
    )
    .bind::<SqlUuid, _>(subject_id)
    .get_result::<Count>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        retained.total, 2,
        "replays must reuse the two durable responses"
    );
}
