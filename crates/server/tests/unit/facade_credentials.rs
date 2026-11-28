use std::sync::Arc;

use actix_web::{App, test};
use bytes::Bytes;
use diesel::sql_types::{BigInt, Integer, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use http::{Method, Request, StatusCode, header};
use nazoauth::{NazoAuthBuilder, integration::conformance};
use serde_json::{Value, json};
use tower::ServiceExt;
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
    assert_eq!(response.status(), StatusCode::OK);
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
async fn enabled_credential_replays_preserve_bytes_through_actix_and_axum() {
    for prefix in ["/", "/testauth"] {
        credential_replay(prefix).await;
    }
}

async fn credential_replay(prefix: &str) {
    let mut state = super::infrastructure(true).await;
    let accepting_modules = crate::test_support::facade::enable_credential_issuer(&mut state).await;
    let suffix = prefix.trim_end_matches('/');
    let settings = Arc::make_mut(&mut state.settings);
    settings.endpoint.issuer = format!("https://issuer.example{suffix}");
    settings.endpoint.mtls_endpoint_base_url = format!("https://mtls.example{suffix}");
    settings.protocol.protected_resource_identifier =
        format!("https://issuer.example{suffix}/fapi/resource");
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
        .mount_path(prefix)
        .build()
        .await
        .unwrap(),
    );
    let app = test::init_service(
        App::new().configure(nazo_http_actix::mount(application.clone(), &[]).unwrap()),
    )
    .await;
    let axum = super::axum_embedding::mounted_host(application.clone()).await;
    let send = |request: Request<Bytes>| {
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
    };
    conformance::assert_adapter(&application, &send).await;
    conformance::assert_adapter(&application, |request| {
        let axum = axum.clone();
        async move {
            super::axum_embedding::standard_response(
                axum.oneshot(request.map(axum::body::Body::from))
                    .await
                    .unwrap(),
            )
            .await
        }
    })
    .await;

    let metadata_request = request(
        Method::GET,
        &format!("/.well-known/openid-credential-issuer{suffix}"),
        "application/json",
        Bytes::new(),
    );
    let metadata_response = send(metadata_request.clone()).await;
    let axum_metadata = super::axum_embedding::standard_response(
        axum.clone()
            .oneshot(metadata_request.map(axum::body::Body::from))
            .await
            .unwrap(),
    )
    .await;
    let mut metadata = json_body(&metadata_response);
    let mut axum_metadata_body = json_body(&axum_metadata);
    conformance::assert_response(
        &metadata_response.map(|_| Bytes::new()),
        &axum_metadata.map(|_| Bytes::new()),
    );
    // Independent metadata GETs produce fresh ES256 signatures. Compare all
    // stable fields and transport headers; durable credential retries below
    // must still preserve the entire original body byte for byte.
    for body in [&mut metadata, &mut axum_metadata_body] {
        assert!(
            body.as_object_mut()
                .unwrap()
                .remove("signed_metadata")
                .unwrap()
                .as_str()
                .is_some_and(|jwt| !jwt.is_empty())
        );
    }
    assert_eq!(metadata, axum_metadata_body);
    assert_eq!(
        metadata["credential_issuer"],
        format!("https://issuer.example{suffix}")
    );
    assert_eq!(
        metadata["credential_endpoint"],
        format!("https://issuer.example{suffix}/openid4vci/credential"),
    );
    assert!(metadata["credential_configurations_supported"]["unit-credential"].is_object());
    let mut offer_request = request(
        Method::POST,
        &format!("{suffix}/openid4vci/offers"),
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
    let offer = json_body(&send(offer_request).await);
    let code = offer["credential_offer"]["grants"][nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT]
        ["pre-authorized_code"]
        .as_str()
        .unwrap();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
        .append_pair("pre-authorized_code", code)
        .finish();
    let token = json_body(
        &send(request(
            Method::POST,
            &format!("{suffix}/token"),
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
        let mut credential_request = request(
            Method::POST,
            &format!("{suffix}/openid4vci/credential"),
            content_type,
            bytes,
        );
        credential_request
            .headers_mut()
            .insert(header::AUTHORIZATION, authorization.parse().unwrap());
        let issued = send(credential_request.clone()).await;
        assert_eq!(issued.status(), StatusCode::OK);
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
            let replay = send(credential_request.clone()).await;
            conformance::assert_response(&issued, &replay);
        }
        let replay = super::axum_embedding::standard_response(
            axum.clone()
                .oneshot(credential_request.map(axum::body::Body::from))
                .await
                .unwrap(),
        )
        .await;
        conformance::assert_response(&issued, &replay);
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
