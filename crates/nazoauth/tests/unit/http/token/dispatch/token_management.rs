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
