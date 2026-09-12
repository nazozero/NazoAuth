use super::*;
use nazo_openid4vci::{
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest, DeferredCredentialRequest,
    NotificationRequest, application::*,
};
use std::sync::Mutex;
#[derive(Default)]
struct Issuer {
    requests: Mutex<Vec<PreAuthorizedTokenRequest>>,
}
impl CredentialIssuerOperations for Issuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        panic!("unexpected metadata")
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        panic!("unexpected offer")
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        panic!("unexpected nonce")
    }
    fn credential<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        panic!("unexpected credential")
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        panic!("unexpected deferred")
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        panic!("unexpected notify")
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        panic!("unexpected create offer")
    }
    fn pre_authorized_token<'a>(
        &'a self,
        request: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        let fail = request.pre_authorized_code == "rejected-code";
        self.requests.lock().unwrap().push(request);
        Box::pin(async move {
            if fail {
                Err(CredentialHttpError {
                    status: 400,
                    error: "invalid_grant",
                    description: "consumed code",
                    dpop_nonce: None,
                })
            } else {
                Ok(PreAuthorizedTokenResponse {
                    access_token: "test-issued-token".into(),
                    token_type: "Bearer".into(),
                    expires_in: 60,
                    authorization_details: vec![],
                })
            }
        })
    }
}
#[actix_web::test]
async fn preauthorized_dispatch_binds_authenticated_identity_and_preserves_issuer_results() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("preauth-{}", Uuid::now_v7());
    let secret = Uuid::now_v7().to_string();
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &secret)),
        vec!["authorization_code"],
        false,
        false,
        true,
    )
    .await;
    let issuer = Arc::new(Issuer::default());
    for authenticated in [false, true] {
        for fail in [false, true] {
            let code = if fail {
                "rejected-code"
            } else {
                "accepted-code"
            };
            let mut body = format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code={code}&tx_code=123456"
            );
            if authenticated {
                body.push_str(&format!("&client_id={client_id}&client_secret={secret}"));
            }
            let response = token_with_credential_issuer(state.clone(), token_request("application/x-www-form-urlencoded"), Bytes::from(body), Arc::new(crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[]).unwrap()), Openid4vcTokenHandles { credential_issuer: Some(issuer.clone()), client_attestation: None }).await;
            if fail {
                assert_token_error(response, StatusCode::BAD_REQUEST, "invalid_grant", false).await;
            } else {
                assert_eq!(response.status(), StatusCode::OK);
            }
            let requests = issuer.requests.lock().unwrap();
            let request = requests.last().unwrap();
            assert_eq!(request.pre_authorized_code, code);
            assert_eq!(request.tx_code.as_deref(), Some("123456"));
            assert_eq!(
                request.client_id.as_deref(),
                authenticated.then_some(client_id.as_str())
            );
            assert_eq!(request.request_url, "https://issuer.example/token");
        }
    }
    assert_eq!(issuer.requests.lock().unwrap().len(), 4);
}

#[actix_web::test]
async fn attested_token_dispatch_checks_identity_and_consumes_proof_once() {
    use nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator;
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("attested-dispatch-{}", Uuid::now_v7());
    insert_token_client(
        &state,
        &client_id,
        "public",
        "attest_jwt_client_auth",
        None,
        vec!["authorization_code"],
        false,
        false,
        true,
    )
    .await;
    let attester = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let instance = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let validator = Arc::new(
        Openid4vcClientAttestationValidator::new(
            "https://attester.example",
            json!({"keys": [attester.public_jwk("attester-key")]}),
        )
        .unwrap(),
    );
    let now = Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("oauth-client-attestation+jwt".into());
    header.kid = Some("attester-key".into());
    let attestation = attester.encode_jwt(&header, &json!({"iss": "https://attester.example", "sub": client_id, "exp": now+600, "cnf": {"jwk": instance.public_jwk("instance-key")}}));
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("oauth-client-attestation-pop+jwt".into());
    let proof = instance.encode_jwt(&header, &json!({"iss": client_id, "aud": "https://issuer.example", "iat": now, "jti": Uuid::now_v7().to_string()}));
    let issuer = Arc::new(Issuer::default());
    for case in 0..7 {
        if case == 6 {
            let mut connection = get_conn(&state.diesel_db).await.unwrap();
            sql_query("UPDATE oauth_clients SET token_endpoint_auth_method = 'none' WHERE tenant_id = $1 AND client_id = $2").bind::<SqlUuid,_>(DEFAULT_TENANT_ID).bind::<Text,_>(&client_id).execute(&mut connection).await.unwrap();
        }
        let request = actix_web::test::TestRequest::post()
            .uri("/token")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .insert_header(("OAuth-Client-Attestation", attestation.as_str()))
            .insert_header((
                "OAuth-Client-Attestation-PoP",
                if case == 1 {
                    "invalid-proof"
                } else {
                    proof.as_str()
                },
            ))
            .to_http_request();
        let mut body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=accepted-code".to_owned();
        if case == 2 {
            body.push_str("&client_id=wrong-client");
        }
        if case == 3 {
            body.push_str("&client_secret=conflicting-secret");
        }
        let response = token_with_credential_issuer(
            state.clone(),
            request,
            Bytes::from(body),
            Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .unwrap(),
            ),
            Openid4vcTokenHandles {
                credential_issuer: Some(issuer.clone()),
                client_attestation: if case == 0 {
                    None
                } else {
                    Some(validator.clone())
                },
            },
        )
        .await;
        match case {
            0 | 1 | 5 | 6 => {
                assert_token_error(
                    response,
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    false,
                )
                .await
            }
            2 => {
                assert_token_error(response, StatusCode::UNAUTHORIZED, "invalid_client", false)
                    .await
            }
            3 => {
                assert_token_error(response, StatusCode::BAD_REQUEST, "invalid_request", false)
                    .await
            }
            _ => assert_eq!(response.status(), StatusCode::OK),
        }
    }
    let requests = issuer.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "only the verified, first-use proof may reach issuance"
    );
    assert_eq!(requests[0].client_id.as_deref(), Some(client_id.as_str()));
    assert_eq!(
        requests[0].client_attestation.as_deref(),
        Some(attestation.as_str())
    );
}
