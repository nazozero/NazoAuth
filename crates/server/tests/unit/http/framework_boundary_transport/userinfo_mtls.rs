use std::sync::{Arc, Mutex};

use crate::test_support::http::{IpCidr, UserinfoEndpoint};
use actix_web::{
    http::{StatusCode, header},
    test::TestRequest,
    web::{Bytes, Data},
};
use nazo_oauth_server::contracts::userinfo::{
    AccessTokenAuthScheme, PreparedUserinfo, UserinfoError, UserinfoFuture, UserinfoOperations,
    UserinfoPreparationFuture, UserinfoRequestFacts,
};

use super::{NoFapiMtls, live_transport_state, ready_body_bytes};
use crate::http;

struct RecordingUserinfo {
    calls: Arc<Mutex<Vec<(AccessTokenAuthScheme, String)>>>,
    result: UserinfoError,
}

impl UserinfoOperations for RecordingUserinfo {
    fn prepare<'a>(
        &'a self,
        scheme: AccessTokenAuthScheme,
        token: String,
    ) -> UserinfoPreparationFuture<'a> {
        Box::pin(async move {
            self.calls.lock().unwrap().push((scheme, token));
            Err(self.result.clone())
        })
    }
    fn userinfo<'a>(
        &'a self,
        _prepared: PreparedUserinfo,
        _facts: UserinfoRequestFacts<'a>,
    ) -> UserinfoFuture<'a> {
        panic!("rejected preparation must not reach binding")
    }
}

#[actix_web::test]
async fn framework_boundary_transport_userinfo_rejects_conflicting_auth_sources_before_port() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(UserinfoEndpoint::new(
        Arc::new(RecordingUserinfo {
            calls: calls.clone(),
            result: UserinfoError::InvalidAccessToken,
        }),
        Arc::new(NoFapiMtls),
    ));
    let req = TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer token-in-header"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .app_data(Data::new(
            crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
        ))
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .insert_header(("client-cert", ":not-base64!:"))
        .to_http_request();
    let response = crate::test_support::http::userinfo(
        endpoint,
        req,
        Bytes::from_static(b"access_token=token-in-body"),
    )
    .await;
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_request", error_description="Only one access token transport method may be used.""#
    );
    assert_eq!(ready_body_bytes(response).await, br#"{"error":"invalid_request","error_description":"Only one access token transport method may be used."}"#);
}

#[actix_web::test]
async fn framework_boundary_transport_userinfo_missing_token_challenge_skips_port() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(UserinfoEndpoint::new(
        Arc::new(RecordingUserinfo {
            calls: calls.clone(),
            result: UserinfoError::InvalidAccessToken,
        }),
        Arc::new(NoFapiMtls),
    ));
    let req = TestRequest::default().to_http_request();
    let response = crate::test_support::http::userinfo(endpoint, req, Bytes::new()).await;
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_token", error_description="Request failed.""#
    );
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"invalid_token","error_description":"Request failed."}"#
    );
}

#[actix_web::test]
async fn framework_boundary_transport_userinfo_invalid_token_challenge_follows_port() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(UserinfoEndpoint::new(
        Arc::new(RecordingUserinfo {
            calls: calls.clone(),
            result: UserinfoError::InvalidAccessToken,
        }),
        Arc::new(NoFapiMtls),
    ));
    let req = TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer invalid-access-token"))
        .to_http_request();
    let response = crate::test_support::http::userinfo(endpoint, req, Bytes::new()).await;
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(calls.lock().unwrap()[0].1, "invalid-access-token");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_token", error_description="Request failed.""#
    );
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"invalid_token","error_description":"Request failed."}"#
    );
}

#[test]
fn framework_boundary_transport_untrusted_rfc9440_peer_cannot_supply_mtls_facts() {
    let trusted = [IpCidr::parse("192.0.2.0/24").unwrap()];
    let req = TestRequest::default()
        .app_data(Data::new(http::mtls::MtlsCertificateSourceMode::Rfc9440))
        .peer_addr("198.51.100.10:443".parse().unwrap())
        .insert_header(("client-cert", ":AA==:"))
        .to_http_request();
    let req = crate::test_support::transport::request_with_policy(
        &req,
        &trusted,
        http::mtls::MtlsCertificateSourceMode::Rfc9440,
    );
    assert!(
        nazoauth::test_support::endpoints::mtls::request_mtls_client_certificate(&req).is_none()
    );
    assert!(nazoauth::test_support::endpoints::mtls::request_mtls_thumbprint(&req).is_none());
}

#[test]
fn framework_boundary_transport_direct_tls_does_not_fallback_to_certificate_headers() {
    let req = TestRequest::default()
        .app_data(Data::new(http::mtls::MtlsCertificateSourceMode::DirectTls))
        .insert_header(("client-cert", ":AA==:"))
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .to_http_request();
    let req = crate::test_support::transport::request_with_policy(
        &req,
        &[],
        http::mtls::MtlsCertificateSourceMode::DirectTls,
    );
    assert!(
        nazoauth::test_support::endpoints::mtls::request_mtls_client_certificate(&req).is_none()
    );
}

mod real_userinfo_contract {
    use crate::test_support::{DatabaseUserFixture, TestInfrastructure};
    use actix_web::{
        HttpRequest, HttpResponse,
        http::{StatusCode, header},
        web::{Bytes, Data},
    };
    use diesel::{
        sql_query,
        sql_types::{Bool, Text, Uuid as SqlUuid},
    };
    use diesel_async::RunQueryDsl;
    use jiff::Timestamp;
    use nazo_auth::PreparedTokenSubject;
    use nazo_auth::*;
    use nazo_identity::DEFAULT_ORGANIZATION_ID;
    use nazo_identity::DEFAULT_REALM_ID;
    use nazo_identity::DEFAULT_TENANT_ID;
    use nazo_oauth_server::domain::userinfo::{
        ServerUserinfoOperations, UserinfoConfig, UserinfoHandles,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    // Observe existing semantic ports; the production handler and business service are unchanged.
    struct ObservedRepository {
        inner: nazo_postgres::TokenIssuanceRepository,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }
    impl TokenRepositoryPort for ObservedRepository {
        fn machine_client_active(
            &self,
            tenant_id: Uuid,
            client_id: Uuid,
            epoch: i64,
        ) -> TokenFuture<'_, bool> {
            self.inner
                .machine_client_active(tenant_id, client_id, epoch)
        }

        fn token_principal_state<'a>(
            &'a self,
            tenant_id: Uuid,
            client_epoch: i64,
            user_id: Option<Uuid>,
            subject: &'a str,
        ) -> TokenFuture<'a, nazo_auth::TokenPrincipalState> {
            self.inner
                .token_principal_state(tenant_id, client_epoch, user_id, subject)
        }

        fn access_token_revoked<'a>(
            &'a self,
            tenant: Uuid,
            claims: &'a nazo_auth::Claims,
        ) -> TokenFuture<'a, bool> {
            self.calls.lock().unwrap().push("revocation");
            self.inner.access_token_revoked(tenant, claims)
        }
        fn active_subject_claims<'a>(
            &'a self,
            tenant: Uuid,
            user: Uuid,
            token_subject: &'a str,
        ) -> TokenFuture<'a, Option<PreparedTokenSubject>> {
            self.calls.lock().unwrap().push("subject");
            self.inner
                .active_subject_claims(tenant, user, token_subject)
        }
        fn single_use_redemption<'a>(
            &'a self,
            tenant_id: Uuid,
            client_id: Uuid,
            grant_key: &'a str,
        ) -> TokenFuture<'a, Option<SingleUseRedemption>> {
            self.inner
                .single_use_redemption(tenant_id, client_id, grant_key)
        }
        fn userinfo_snapshot<'a>(
            &'a self,
            tenant: Uuid,
            verified_claims: &'a Claims,
        ) -> TokenFuture<'a, Option<UserinfoSnapshot>> {
            self.calls.lock().unwrap().push("userinfo_snapshot");
            TokenRepositoryPort::userinfo_snapshot(&self.inner, tenant, verified_claims)
        }
        fn active_subject_id<'a>(
            &'a self,
            tenant: Uuid,
            user: Uuid,
        ) -> TokenFuture<'a, Option<Uuid>> {
            self.calls.lock().unwrap().push("subject");
            TokenRepositoryPort::active_subject_id(&self.inner, tenant, user)
        }
        fn active_subject_id_by_access_token<'a>(
            &'a self,
            tenant: Uuid,
            jti: &'a str,
            subject: &'a str,
        ) -> TokenFuture<'a, Option<Uuid>> {
            self.calls.lock().unwrap().push("subject");
            TokenRepositoryPort::active_subject_id_by_access_token(
                &self.inner,
                tenant,
                jti,
                subject,
            )
        }
        fn commit_token_issuance<'a>(
            &'a self,
            _: CommitTokenIssuance,
        ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
            panic!("unexpected issuance")
        }
        fn refresh_token<'a>(
            &'a self,
            _: Uuid,
            _: &'a str,
        ) -> TokenFuture<'a, Option<RefreshToken>> {
            panic!("unexpected refresh lookup")
        }
        fn refresh_token_snapshot<'a>(
            &'a self,
            _tenant_id: Uuid,
            _raw_token: &'a str,
            _client_id: Uuid,
            _retry_started_at: jiff::Timestamp,
            _prepare_oidc_subject: bool,
        ) -> nazo_auth::TokenFuture<'a, Option<nazo_auth::RefreshTokenSnapshot>> {
            panic!("unexpected refresh snapshot lookup")
        }
        fn revoke_issued_tokens<'a>(
            &'a self,
            _: Uuid,
            _: Uuid,
            _: &'a str,
            _: Option<Timestamp>,
            _: Option<Uuid>,
        ) -> TokenFuture<'a, ()> {
            panic!("unexpected token revocation")
        }
        fn refresh_family_active(&self, _: Uuid, _: Uuid, _: Uuid) -> TokenFuture<'_, bool> {
            panic!("unexpected refresh family lookup")
        }
        fn revoke_token_with_audit<'a>(
            &'a self,
            _: TokenRevocation<'a>,
            _: &'a str,
            _: &'a str,
        ) -> TokenFuture<'a, usize> {
            panic!("unexpected revoke_token_with_audit")
        }
    }

    struct NoDpopState;
    impl DpopStateStorePort for NoDpopState {
        fn consume_replay<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: u64,
        ) -> DpopStateFuture<'a, bool> {
            panic!("Bearer must not consume DPoP replay state")
        }
        fn issue_nonce<'a>(&'a self, _: &'a str, _: u64) -> DpopStateFuture<'a, ()> {
            panic!("Bearer must not issue a DPoP nonce")
        }
        fn validate_nonce<'a>(&'a self, _: &'a str) -> DpopStateFuture<'a, bool> {
            panic!("Bearer must not validate a DPoP nonce")
        }
    }

    async fn state() -> TestInfrastructure {
        let mut state = super::live_transport_state().await;
        let mut settings = (*state.settings).clone();
        settings.endpoint.trusted_proxy_cidrs =
            vec![crate::test_support::http::IpCidr::parse("127.0.0.1/32").unwrap()];
        state.settings = Arc::new(settings);
        state
    }

    fn endpoint(
        state: &TestInfrastructure,
        calls: Arc<Mutex<Vec<&'static str>>>,
    ) -> Data<crate::test_support::http::UserinfoEndpoint> {
        let token_state: Arc<dyn TokenStateStorePort> = Arc::new(
            nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        );
        let service = nazo_oauth_server::services::ServerTokenService::new(
            ObservedRepository {
                inner: nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
                calls,
            },
            token_state,
            state.keyset.clone(),
        );
        let handles = UserinfoHandles::new(
            Arc::new(NoDpopState),
            crate::http::authorization::test_support::test_security_audit_arc(),
            state.keyset.clone(),
            UserinfoConfig::new(
                state.settings.endpoint.issuer.as_str(),
                state.settings.protocol.default_audience.as_str(),
                state.settings.endpoint.mtls_endpoint_base_url.as_str(),
                state.settings.protocol.dpop_nonce_policy,
                state
                    .settings
                    .protocol
                    .authorization_server_profile
                    .requires_fapi2_security(),
            ),
            Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .unwrap(),
            ),
        );
        Data::new(crate::test_support::http::UserinfoEndpoint::new(
            Arc::new(ServerUserinfoOperations::new(Arc::new(service), handles)),
            Arc::new(crate::http::mtls::ServerMtlsThumbprintExtractor),
        ))
    }

    async fn userinfo(
        state: &TestInfrastructure,
        endpoint: Data<crate::test_support::http::UserinfoEndpoint>,
        request: HttpRequest,
        body: Bytes,
    ) -> HttpResponse {
        let request = crate::test_support::transport::request(&request, &state.settings);
        nazo_http_actix::forward_response(
            nazoauth::test_support::http::userinfo(endpoint.get_ref(), &request, &body).await,
        )
    }

    fn request(token: &str, dpop: &str) -> HttpRequest {
        let mut request = actix_web::test::TestRequest::get()
            .uri("/userinfo")
            .app_data(Data::new(
                crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
            ))
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .insert_header(("client-cert", ":not-base64!:"))
            .insert_header((header::AUTHORIZATION, format!("Bearer {token}")));
        if !dpop.is_empty() {
            request = request.insert_header(("dpop", dpop));
        }
        request.to_http_request()
    }

    async fn signed_token(
        state: &TestInfrastructure,
        user: Uuid,
        client: &str,
        bound: bool,
    ) -> String {
        signed_token_with_bindings(
            state,
            user,
            client,
            None,
            bound.then_some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
            "openid",
        )
        .await
    }

    async fn signed_token_with_bindings(
        state: &TestInfrastructure,
        user: Uuid,
        client: &str,
        jkt: Option<&str>,
        x5t: Option<&str>,
        scope: &str,
    ) -> String {
        use crate::adapters::security::tokens::{AccessTokenJwtInput, make_jwt};
        let token = make_jwt(
            &state.keyset,
            &state.settings.endpoint.issuer,
            AccessTokenJwtInput {
                tenant_id: DEFAULT_TENANT_ID,
                subject: &user.to_string(),
                user_id: Some(user),
                subject_type: "user",
                client_id: client,
                audiences: &["resource://default".to_owned()],
                scopes: &[scope.to_owned()],
                authorization_details: &json!([]),
                userinfo_claim_requests: &[],
                ttl: 300,
                dpop_jkt: None,
                mtls_x5t_s256: x5t,
                actor: None,
            },
        )
        .await
        .expect("real access token must sign")
        .token;
        let Some(jkt) = jkt else {
            return token;
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let mut parts = token.split('.');
        let header = parts.next().unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap())
                .unwrap();
        payload["cnf"]["jkt"] = json!(jkt);
        let signing_input = format!(
            "{header}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let header_value: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        let signature = nazo_auth::Signer::sign(
            &state.keyset,
            nazo_auth::SignRequest {
                purpose: nazo_auth::SigningPurpose::AccessToken,
                algorithm: header_value["alg"].as_str().unwrap(),
                signing_input: signing_input.as_bytes(),
            },
        )
        .await
        .unwrap();
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_bytes())
        )
    }

    async fn assert_error(response: HttpResponse, description: &str) {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenges: Vec<_> = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .map(|h| h.to_str().unwrap())
            .collect();
        assert_eq!(
            challenges,
            vec![format!(
                "Bearer error=\"invalid_token\", error_description=\"{description}\""
            )]
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert!(response.headers().get(header::LOCATION).is_none());
        assert!(response.headers().get("dpop-nonce").is_none());
        let bytes = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let golden =
            format!("{{\"error\":\"invalid_token\",\"error_description\":\"{description}\"}}");
        assert_eq!(bytes.as_ref(), golden.as_bytes());
    }

    #[actix_web::test]
    async fn invalid_token_precedes_malformed_certificate_without_repository_or_dpop_calls() {
        let state = state().await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let response = userinfo(
            &state,
            endpoint(&state, calls.clone()),
            request("not-a-jwt", "not-a-jwt"),
            Bytes::new(),
        )
        .await;
        assert_error(response, "Request failed.").await;
        assert!(
            calls.lock().unwrap().is_empty(),
            "invalid token must stop before revocation, subject and client ports"
        );
    }

    #[actix_web::test]
    async fn mtls_bound_token_rejects_malformed_certificate_before_releasing_snapshot() {
        let state = state().await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let client = format!("t00-userinfo-mtls-{}", Uuid::now_v7().simple());
        let user = insert_subject_and_client(&state, &client).await;
        let token = signed_token(&state, user, &client, true).await;
        let response = userinfo(
            &state,
            endpoint(&state, calls.clone()),
            request(&token, "not-a-jwt"),
            Bytes::new(),
        )
        .await;
        assert_error(
            response,
            "mTLS-bound access token requires a verified client certificate.",
        )
        .await;
        assert_eq!(*calls.lock().unwrap(), ["userinfo_snapshot"]);
    }

    #[actix_web::test]
    async fn insufficient_scope_follows_sender_constraints_without_loading_response_facts() {
        let state = state().await;
        let user = Uuid::now_v7();
        let client = format!("userinfo-scope-{}", Uuid::now_v7().simple());
        let calls = Arc::new(Mutex::new(Vec::new()));
        for (jkt, x5t, status, error) in [
            (None, None, StatusCode::FORBIDDEN, "insufficient_scope"),
            (
                Some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ"),
                None,
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
            ),
            (
                None,
                Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
                StatusCode::UNAUTHORIZED,
                "invalid_token",
            ),
        ] {
            calls.lock().unwrap().clear();
            let token =
                signed_token_with_bindings(&state, user, &client, jkt, x5t, "profile").await;
            let response = userinfo(
                &state,
                endpoint(&state, calls.clone()),
                request(&token, "not-a-proof"),
                Bytes::new(),
            )
            .await;
            assert_eq!(response.status(), status);
            assert!(response.headers().get("dpop-nonce").is_none());
            assert!(response.headers().get(header::SET_COOKIE).is_none());
            let challenge = response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .unwrap()
                .to_str()
                .unwrap();
            assert!(challenge.contains(error));
            let body = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"], error);
            assert!(body.get("sub").is_none());
            assert_eq!(*calls.lock().unwrap(), ["revocation"]);
        }
    }

    #[actix_web::test]
    async fn revoked_token_stops_before_dpop_validation_or_nonce_state() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let state = state().await;
        let client = format!("t00-userinfo-revoked-{}", Uuid::now_v7().simple());
        let user = insert_subject_and_client(&state, &client).await;
        let token = signed_token_with_bindings(
            &state,
            user,
            &client,
            Some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ"),
            None,
            "openid",
        )
        .await;
        let claims: Claims = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        sql_query("INSERT INTO access_token_revocations(tenant_id,access_token_jti_blake3,client_id,expires_at) SELECT tenant_id,$3,id,CURRENT_TIMESTAMP+INTERVAL '1 hour' FROM oauth_clients WHERE tenant_id=$1 AND client_id=$2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID).bind::<Text, _>(&client)
            .bind::<Text, _>(blake3::hash(claims.jti.as_bytes()).to_hex().as_str())
            .execute(&mut connection).await.unwrap();
        drop(connection);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let request = actix_web::test::TestRequest::get()
            .uri("/userinfo")
            .insert_header((header::AUTHORIZATION, format!("DPoP {token}")))
            .insert_header(("dpop", "not-a-proof"))
            .to_http_request();
        let response = userinfo(
            &state,
            endpoint(&state, calls.clone()),
            request,
            Bytes::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("dpop-nonce").is_none());
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "invalid_token");
        assert!(body.get("sub").is_none());
        assert_eq!(*calls.lock().unwrap(), ["userinfo_snapshot"]);
        let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        sql_query("DELETE FROM access_token_revocations WHERE tenant_id=$1 AND access_token_jti_blake3=$2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(blake3::hash(claims.jti.as_bytes()).to_hex().as_str())
            .execute(&mut connection).await.unwrap();
        sql_query("DELETE FROM oauth_clients WHERE tenant_id=$1 AND client_id=$2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(&client)
            .execute(&mut connection)
            .await
            .unwrap();
        sql_query("DELETE FROM users WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(user)
            .execute(&mut connection)
            .await
            .unwrap();
    }

    async fn insert_subject_and_client(state: &TestInfrastructure, client: &str) -> Uuid {
        let mut conn = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        let user = sql_query(
            r#"
            INSERT INTO users (tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level)
            VALUES ($1, $2, $3, $4, $5, 'unused-t00-userinfo-hash', $6, false, true, 'user', 0)
            RETURNING *
        "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(client)
        .bind::<Text, _>(format!("{client}@example.com"))
        .bind::<Bool, _>(true)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .unwrap();
        sql_query(r#"
            INSERT INTO oauth_clients (
                tenant_id, realm_id, organization_id, client_id, client_name, client_type,
                client_secret_hash, redirect_uris, scopes, allowed_audiences,
                grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
                require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
                tls_client_auth_san_ip, tls_client_auth_san_email,
                allow_client_assertion_audience_array, allow_client_assertion_endpoint_audience,
                require_par_request_object, is_active, security_policy,
                post_logout_redirect_uris, backchannel_logout_session_required)
            VALUES ($1, $2, $3, $4, 'T00 UserInfo Client', 'confidential',
                NULL, '["https://client.example/callback"]'::jsonb, '["openid"]'::jsonb,
                '["resource://default"]'::jsonb, '["authorization_code"]'::jsonb,
                'client_secret_post', false, false, '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, '[]'::jsonb, false, false, false, true,
                '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}'::jsonb,
                '[]'::jsonb, true)
        "#).bind::<SqlUuid, _>(DEFAULT_TENANT_ID).bind::<SqlUuid, _>(DEFAULT_REALM_ID)
            .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID).bind::<Text, _>(client)
            .execute(&mut conn).await.unwrap();
        user.id
    }

    #[actix_web::test]
    async fn unbound_bearer_ignores_malformed_dpop_and_certificate_and_returns_exact_claims() {
        let state = state().await;
        let client = format!("t00-userinfo-{}", Uuid::now_v7().simple());
        let user = insert_subject_and_client(&state, &client).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let token = signed_token(&state, user, &client, false).await;
        for dpop in ["not-a-jwt", "   "] {
            calls.lock().unwrap().clear();
            let response = userinfo(
                &state,
                endpoint(&state, calls.clone()),
                request(&token, dpop),
                Bytes::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
            assert_eq!(
                response.headers().get_all(header::WWW_AUTHENTICATE).count(),
                0
            );
            assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 0);
            assert!(response.headers().get(header::LOCATION).is_none());
            assert!(response.headers().get("dpop-nonce").is_none());
            let bytes = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            // The random subject remains in the comparison; it is not deleted or normalized away.
            assert_eq!(bytes.as_ref(), format!("{{\"sub\":\"{user}\"}}").as_bytes());
            assert_eq!(*calls.lock().unwrap(), ["userinfo_snapshot"]);
        }
        let mut conn = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(&client)
            .execute(&mut conn)
            .await
            .unwrap();
        sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(user)
            .execute(&mut conn)
            .await
            .unwrap();
    }

    #[actix_web::test]
    async fn dual_bound_userinfo_bearer_rejects_missing_dpop_even_with_matching_verified_certificate()
     {
        let state = state().await;
        let client = format!("userinfo-dual-{}", Uuid::now_v7().simple());
        let user = insert_subject_and_client(&state, &client).await;
        let certificate = crate::test_support::rfc9440_certificate_fixture("userinfo-dual");
        let calls = Arc::new(Mutex::new(Vec::new()));
        for dual in [true, false] {
            calls.lock().unwrap().clear();
            let token = signed_token_with_bindings(
                &state,
                user,
                &client,
                dual.then_some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ"),
                Some(&certificate.thumbprint),
                "openid",
            )
            .await;
            let request = actix_web::test::TestRequest::get()
                .uri("/userinfo")
                .app_data(Data::new(
                    crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
                ))
                .peer_addr("127.0.0.1:12345".parse().unwrap())
                .insert_header(("client-cert", certificate.header.as_str()))
                .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
                .to_http_request();
            assert_eq!(
                nazoauth::test_support::endpoints::mtls::request_mtls_thumbprint(
                    &crate::test_support::transport::request(&request, &state.settings)
                )
                .as_deref(),
                Some(certificate.thumbprint.as_str())
            );
            let response = userinfo(
                &state,
                endpoint(&state, calls.clone()),
                request,
                Bytes::new(),
            )
            .await;
            if dual {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                let challenge = response
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .unwrap()
                    .to_str()
                    .unwrap();
                assert!(challenge.contains("invalid_dpop_proof"));
                assert!(response.headers().get(header::SET_COOKIE).is_none());
                let body = actix_web::body::to_bytes(response.into_body())
                    .await
                    .unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["error"], "invalid_dpop_proof");
                assert!(body.get("sub").is_none());
                assert_eq!(*calls.lock().unwrap(), ["userinfo_snapshot"]);
            } else {
                assert_eq!(response.status(), StatusCode::OK);
                let body = actix_web::body::to_bytes(response.into_body())
                    .await
                    .unwrap();
                assert_eq!(body.as_ref(), format!("{{\"sub\":\"{user}\"}}").as_bytes());
                assert_eq!(*calls.lock().unwrap(), ["userinfo_snapshot"]);
            }
        }
        let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        sql_query("DELETE FROM oauth_clients WHERE tenant_id=$1 AND client_id=$2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(&client)
            .execute(&mut connection)
            .await
            .unwrap();
        sql_query("DELETE FROM users WHERE tenant_id=$1 AND id=$2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(user)
            .execute(&mut connection)
            .await
            .unwrap();
    }
}
