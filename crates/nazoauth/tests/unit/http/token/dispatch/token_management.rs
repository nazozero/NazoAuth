use super::*;

#[actix_web::test]
async fn token_management_refreshes_only_requested_encryption_keys() {
    use nazo_http_actix::{TokenClientAuthForm, token_client_auth_transport_facts};
    use nazo_oauth_server::contracts::token_forms::TokenOnlyForm;
    use nazo_oauth_server::contracts::token_management::{
        TokenIntrospectionRepresentation, TokenManagementError, TokenManagementOperations,
        TokenManagementRequestFacts,
    };
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("management-jwks-{}", Uuid::now_v7());
    let secret = Uuid::now_v7().to_string();
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "client_secret_post",
        Some(hash_client_secret(
            &secret,
            &state.settings.protocol.client_secret_pepper,
        )),
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;
    let operations =
        nazo_oauth_server::domain::token_management::ServerTokenManagementOperations::new(
            token_service(&state).into_inner(),
            authorization_service(&state).into_inner(),
            Arc::new(crate::http::authorization::authorization_config(
                state.settings.as_ref(),
            )),
            Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .unwrap(),
            ),
            crate::http::authorization::test_support::test_security_audit_arc(),
        );
    let mut connection = get_conn(&state.diesel_db).await.unwrap();
    sql_query("UPDATE oauth_clients SET jwks_uri = 'https://invalid.example/jwks.json', jwks = '{\"keys\":[]}'::jsonb, introspection_encrypted_response_alg = 'RSA-OAEP-256', introspection_encrypted_response_enc = 'A256GCM' WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID).bind::<Text, _>(&client_id)
        .execute(&mut connection).await.unwrap();
    drop(connection);
    for signed in [false, true] {
        let request = actix_web::test::TestRequest::default().to_http_request();
        let auth = token_client_auth_transport_facts(
            &request,
            TokenClientAuthForm {
                client_id: Some(&client_id),
                client_secret: Some(&secret),
                ..Default::default()
            },
        );
        let facts = TokenManagementRequestFacts {
            source_ip: "127.0.0.1".into(),
            endpoint_path: "/oauth/introspect".into(),
            client_certificate: None,
        };
        let form = TokenOnlyForm {
            token: Uuid::now_v7().to_string(),
            token_type_hint: None,
            client_id: Some(client_id.clone()),
            client_secret: Some(secret.clone()),
            client_assertion_type: None,
            client_assertion: None,
        };
        let result = operations.introspect(facts, auth, form, signed).await;
        if signed {
            assert!(matches!(
                result,
                Err(TokenManagementError::ResponseProtectionFailed)
            ));
        } else {
            assert!(matches!(
                result,
                Ok(TokenIntrospectionRepresentation::Inspection(_))
            ));
        }
    }
    let request = actix_web::test::TestRequest::default().to_http_request();
    let auth = token_client_auth_transport_facts(
        &request,
        TokenClientAuthForm {
            client_id: Some(&client_id),
            client_secret: Some(&secret),
            ..Default::default()
        },
    );
    assert!(
        operations
            .revoke(
                TokenManagementRequestFacts {
                    source_ip: "127.0.0.1".into(),
                    endpoint_path: "/oauth/revoke".into(),
                    client_certificate: None,
                },
                auth,
                TokenOnlyForm {
                    token: Uuid::now_v7().to_string(),
                    token_type_hint: None,
                    client_id: Some(client_id),
                    client_secret: Some(secret),
                    client_assertion_type: None,
                    client_assertion: None,
                }
            )
            .await
            .is_ok(),
        "revocation must not depend on response encryption keys"
    );
}

#[actix_web::test]
async fn inactive_token_management_requesters_are_rejected_before_keys_or_token_side_effects() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use nazo_http_actix::{TokenClientAuthForm, token_client_auth_transport_facts};
    use nazo_oauth_server::contracts::{
        token_forms::TokenOnlyForm,
        token_management::{
            TokenManagementError, TokenManagementOperations, TokenManagementRequestFacts,
        },
    };
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let issuer_id = format!("management-active-issuer-{}", Uuid::now_v7());
    let issuer_secret = fixture_secret(&issuer_id);
    insert_token_client(
        &state,
        &issuer_id,
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &issuer_secret)),
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;
    let response=token(state.clone(),token_request("application/x-www-form-urlencoded"),Bytes::from(format!("grant_type=client_credentials&client_id={issuer_id}&client_secret={issuer_secret}&scope=accounts"))).await;
    let (status, body) = token_json_body(response).await;
    assert_eq!(status, StatusCode::OK);
    let access_token = body["access_token"].as_str().unwrap().to_owned();
    let issuer = authorization_service(&state)
        .client_authentication_snapshot(&issuer_id)
        .await
        .unwrap()
        .unwrap()
        .client;
    let key = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let resolver = crate::test_support::CountingJwksResolver::with_document(
        "https://client.example/management-keys",
        json!({"keys":[key.public_jwk("management-kid")]}),
    );
    let operations =
        nazo_oauth_server::domain::token_management::ServerTokenManagementOperations::new(
            token_service(&state).into_inner(),
            authorization_service(&state).into_inner(),
            Arc::new(crate::http::authorization::authorization_config(
                state.settings.as_ref(),
            )),
            Arc::new(resolver.clone()),
            crate::http::authorization::test_support::test_security_audit_arc(),
        );
    let certificate = crate::test_support::rfc9440_certificate_fixture("inactive-management");
    let certificate_request = actix_web::test::TestRequest::default()
        .insert_header(("client-cert", certificate.header.as_str()))
        .to_http_request();
    let mut certificate_facts = crate::http::mtls::request_mtls_client_certificate_from_rfc9440(
        certificate_request.headers(),
    )
    .unwrap();
    certificate_facts.deployment_trusted_chain = true;
    for method in [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
        "self_signed_tls_client_auth",
        "tls_client_auth",
        "none",
    ] {
        let id = format!("inactive-management-{method}-{}", Uuid::now_v7());
        let secret = fixture_secret(&id);
        insert_token_client(
            &state,
            &id,
            if method == "none" {
                "public"
            } else {
                "confidential"
            },
            method,
            Some(fixture_secret_hash(&state, &secret)),
            vec!["client_credentials"],
            false,
            false,
            false,
        )
        .await;
        let mut conn = get_conn(&state.diesel_db).await.unwrap();
        sql_query("UPDATE oauth_clients SET jwks=$1, jwks_uri='https://client.example/management-keys', tls_client_auth_cert_sha256=$2, tls_client_auth_subject_dn=$3 WHERE tenant_id=$4 AND client_id=$5")
            .bind::<Jsonb,_>(json!({"keys":[key.public_jwk("management-kid")]})).bind::<Text,_>(&certificate.thumbprint).bind::<Nullable<Text>,_>(certificate_facts.subject_dn.as_deref()).bind::<SqlUuid,_>(DEFAULT_TENANT_ID).bind::<Text,_>(&id).execute(&mut conn).await.unwrap();
        drop(conn);
        let assertion=key.encode_jwt(&{let mut h=jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);h.kid=Some("management-kid".to_owned());h},&json!({"iss":id,"sub":id,"aud":format!("{}/oauth/introspect",state.settings.endpoint.issuer.trim_end_matches('/')),"iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+60,"jti":Uuid::now_v7().to_string()}));
        for revoke in [false, true] {
            let mut request = actix_web::test::TestRequest::post();
            if method == "client_secret_basic" {
                request = request.insert_header((
                    header::AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
                ));
            }
            let request = request.to_http_request();
            let auth = token_client_auth_transport_facts(
                &request,
                TokenClientAuthForm {
                    client_id: Some(&id),
                    client_secret: if method == "client_secret_post" {
                        Some(&secret)
                    } else {
                        None
                    },
                    client_assertion_type: if method == "private_key_jwt" {
                        Some(nazo_auth::CLIENT_ASSERTION_TYPE_JWT_BEARER)
                    } else {
                        None
                    },
                    client_assertion: if method == "private_key_jwt" {
                        Some(&assertion)
                    } else {
                        None
                    },
                },
            );
            let facts = TokenManagementRequestFacts {
                source_ip: "127.0.0.1".to_owned(),
                endpoint_path: if revoke {
                    "/oauth/revoke"
                } else {
                    "/oauth/introspect"
                }
                .to_owned(),
                client_certificate: if method.ends_with("tls_client_auth") {
                    Some(certificate_facts.clone())
                } else {
                    None
                },
            };
            let form = TokenOnlyForm {
                token: access_token.clone(),
                token_type_hint: None,
                client_id: Some(id.clone()),
                client_secret: None,
                client_assertion_type: None,
                client_assertion: None,
            };
            let result = if revoke {
                operations.revoke(facts, auth, form).await
            } else {
                operations
                    .introspect(facts, auth, form, false)
                    .await
                    .map(|_| ())
            };
            assert!(
                matches!(result,Err(TokenManagementError::InvalidClient {basic_challenge}) if basic_challenge==(method=="client_secret_basic")),
                "inactive {method} requester must reject before token operation: {result:?}"
            );
            assert_eq!(
                resolver.calls(),
                0,
                "inactive requester must not fetch JWKS"
            );
        }
    }
    assert!(matches!(
        token_service(&state)
            .inspect_token(
                &state.settings.endpoint.issuer,
                &access_token,
                &issuer,
                Utc::now()
            )
            .await
            .unwrap(),
        nazo_auth::TokenInspection::ActiveAccess { .. }
    ));
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = get_conn(&state.diesel_db).await.unwrap();
    let revoked=sql_query("SELECT COUNT(*)::bigint AS count FROM access_token_revocations WHERE tenant_id=$1 AND client_id=$2").bind::<SqlUuid,_>(issuer.tenant_id).bind::<SqlUuid,_>(issuer.id).get_result::<Count>(&mut conn).await.unwrap();
    assert_eq!(revoked.count, 0);
}
