use super::*;
use bytes::Bytes;
use nazoauth::config::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, FederationProviderRegistry,
    SocialProviderKind,
};
use nazoauth::test_support::endpoints::{
    auth::federation as rp_http, profile::federation_links as profile_http,
};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct Upstream(Mutex<BTreeMap<&'static str, Value>>);

impl rp_http::FederationHttpClient for Upstream {
    fn send(&self, request: http::Request<Bytes>, _: usize) -> rp_http::FederationHttpFuture<'_> {
        let reply = self
            .0
            .lock()
            .unwrap()
            .remove(request.uri().path())
            .expect("only configured proof endpoints are requested");
        Box::pin(async move { Ok(http::Response::new(Bytes::from(reply.to_string()))) })
    }
}

struct LinkFixture {
    inner: LiveFederationFixture,
    config: FederationHttpConfig,
    upstream: Arc<Upstream>,
}

impl LinkFixture {
    async fn new() -> Option<Self> {
        let inner = LiveFederationFixture::new(Some(oidc_provider()), None).await?;
        let mut config = crate::test_support::federation_http_config(&inner.state)
            .get_ref()
            .clone();
        let mut providers = config
            .providers
            .configured_providers()
            .cloned()
            .collect::<Vec<_>>();
        providers.push(ExternalLoginProvider {
            provider_id: "social".into(),
            enabled: true,
            display_name: "Social".into(),
            icon: None,
            display_order: 1,
            adapter: ExternalLoginProviderAdapter::Social(SocialProviderSettings {
                kind: SocialProviderKind::Custom,
                authorization_endpoint: "https://social.example/authorize".into(),
                token_endpoint: "https://social.example/token".into(),
                openid_endpoint: None,
                userinfo_endpoint: "https://social.example/userinfo".into(),
                client_id: "social-client".into(),
                client_secret: "social-secret".into(),
                redirect_uri: "https://auth.example/auth/federation/social/callback".into(),
                scopes: "profile".into(),
                subject_claim: "sub".into(),
                email_claim: None,
                email_verified_claim: None,
                name_claim: None,
                union_id_claim: None,
            }),
        });
        config.providers = FederationProviderRegistry::new(providers).unwrap();
        let upstream = Arc::new(Upstream::default());
        config.client = upstream.clone();
        Some(Self {
            inner,
            config,
            upstream,
        })
    }

    async fn session(&self, user: &DatabaseUserFixture, age: i64) -> String {
        let id = random_urlsafe_token();
        self.store_session(user, &id, age).await;
        id
    }

    async fn store_session(&self, user: &DatabaseUserFixture, id: &str, age: i64) {
        let record = nazo_identity::session::SessionRecord::new(
            nazo_identity::UserId::new(user.id).unwrap(),
            0,
            jiff::Timestamp::now().as_second() - age,
            vec!["pwd".into()],
            false,
            Some(random_urlsafe_token()),
        );
        nazo_valkey::SessionStore::new(&self.inner.state.valkey_connection())
            .store(id, &record, 600)
            .await
            .unwrap();
    }

    fn browser(&self, session: Option<&str>, csrf: bool) -> http::Request<Bytes> {
        let mut cookies = format!(
            "__Host-nazo_federation_binding={}",
            URL_SAFE_NO_PAD.encode(test_browser_binding_seed())
        );
        if let Some(session) = session {
            cookies.push_str(&format!(
                "; {}={session}; {}=fixture-csrf",
                self.config.session_cookie_name, self.config.csrf_cookie_name
            ));
        }
        let mut request = http::Request::builder().header(http::header::COOKIE, cookies);
        if csrf {
            request = request.header("x-csrf-token", "fixture-csrf");
        }
        request.body(Bytes::new()).unwrap()
    }

    async fn start(
        &self,
        provider: &str,
        request: &http::Request<Bytes>,
        link: bool,
    ) -> http::Response<Bytes> {
        let state = &self.inner.state;
        let limiter = crate::test_support::auth_request_limiter(state);
        let client_ip = crate::test_support::client_ip_config(state);
        let service = crate::test_support::federation_service(state);
        if link {
            rp_http::federation_provider_link_start(
                &limiter,
                &client_ip,
                &service,
                &crate::test_support::profile_sessions(state),
                &self.config,
                request,
                provider.into(),
            )
            .await
        } else {
            rp_http::federation_provider_start(
                &limiter,
                &client_ip,
                &service,
                &self.config,
                request,
                provider.into(),
            )
            .await
        }
    }

    fn proof(&self, provider: &str, query: &BTreeMap<String, String>, subject: &str, valid: bool) {
        let mut replies = self.upstream.0.lock().unwrap();
        replies.clear();
        if provider == "social" {
            replies.insert("/token", json!({"access_token":"upstream-token"}));
            replies.insert(
                "/userinfo",
                if valid {
                    json!({"sub":subject})
                } else {
                    json!({})
                },
            );
        } else {
            let key = client_signing_fixture(Algorithm::RS256);
            let nonce = if valid {
                query["nonce"].as_str()
            } else {
                "wrong-nonce"
            };
            let token = signed_oidc_token(
                &oidc_provider(),
                "link-kid",
                &key,
                nonce,
                json!({"sub":subject,"email":null,"email_verified":null}),
            );
            replies.insert(
                "/token",
                json!({"id_token":token,"access_token":"upstream-token","token_type":"Bearer"}),
            );
            replies.insert("/jwks", json!({"keys":[key.public_jwk("link-kid")]}));
        }
    }

    async fn callback(
        &self,
        provider: &str,
        browser: &http::Request<Bytes>,
        query: &BTreeMap<String, String>,
    ) -> http::Response<Bytes> {
        let state = &self.inner.state;
        rp_http::federation_provider_callback(
            &crate::test_support::auth_request_limiter(state),
            &crate::test_support::client_ip_config(state),
            &crate::test_support::federation_service(state),
            &self.config,
            &crate::test_support::profile_sessions(state),
            browser,
            provider.into(),
            OidcCallbackQuery {
                code: Some("code".into()),
                state: Some(query["state"].clone()),
                error: None,
            },
        )
        .await
    }

    fn profile(&self) -> nazo_identity::FederationLinksService {
        nazo_identity::FederationLinksService::new(nazo_postgres::FederationRepository::new(
            self.inner.state.diesel_db.clone(),
        ))
    }
}

fn authorization_query(response: http::Response<Bytes>) -> BTreeMap<String, String> {
    assert_eq!(
        response.status(),
        http::StatusCode::FOUND,
        "{:?}",
        response.body()
    );
    url::Url::parse(response.headers()[http::header::LOCATION].to_str().unwrap())
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

#[actix_web::test]
async fn oidc_and_social_link_without_email_keep_the_session_and_support_login_then_unlink() {
    let Some(fixture) = LinkFixture::new().await else {
        return;
    };
    for provider in [TEST_OIDC_PROVIDER_ID, "social"] {
        let user = fixture
            .inner
            .create_user(&format!("linked-{}@example.com", Uuid::now_v7()), true)
            .await;
        let sid = fixture.session(&user, 0).await;
        let session_store =
            nazo_valkey::SessionStore::new(&fixture.inner.state.valkey_connection());
        let original_session = session_store
            .load(&sid)
            .await
            .unwrap()
            .unwrap()
            .value()
            .clone();
        let browser = fixture.browser(Some(&sid), true);
        let subject = Uuid::now_v7().to_string();
        let query = authorization_query(fixture.start(provider, &browser, true).await);
        fixture.proof(provider, &query, &subject, true);
        let response = fixture.callback(provider, &browser, &query).await;
        assert_eq!(
            response.status(),
            http::StatusCode::OK,
            "{:?}",
            response.body()
        );
        assert!(response.headers().get(http::header::SET_COOKIE).is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap()["linked"],
            true
        );
        assert_eq!(fixture.inner.session_payload(&sid).await.user_id, user.id);
        assert_eq!(
            session_store.load(&sid).await.unwrap().unwrap().value(),
            &original_session
        );
        assert_eq!(
            fixture.callback(provider, &browser, &query).await.status(),
            http::StatusCode::BAD_REQUEST
        );

        let sessions = crate::test_support::profile_sessions(&fixture.inner.state);
        let profile = fixture.profile();
        let listed = profile_http::my_federation_links(&sessions, &profile, &browser).await;
        assert_eq!(listed.status(), http::StatusCode::OK);
        let listed: Value = serde_json::from_slice(listed.body()).unwrap();
        assert_eq!(listed["total"], 1);
        assert_eq!(listed["items"][0]["subject"], subject);
        assert_eq!(listed["items"][0]["last_login_at"], Value::Null);
        let id = Uuid::parse_str(listed["items"][0]["id"].as_str().unwrap()).unwrap();

        let anonymous = fixture.browser(None, false);
        let login = authorization_query(fixture.start(provider, &anonymous, false).await);
        fixture.proof(provider, &login, &subject, true);
        let response = fixture.callback(provider, &anonymous, &login).await;
        assert_eq!(
            response.status(),
            http::StatusCode::OK,
            "{:?}",
            response.body()
        );
        let response = nazo_http_actix::forward_response(response);
        let federated_sid =
            cookie_value_from_response(&response, &fixture.config.session_cookie_name).unwrap();
        assert_eq!(
            fixture.inner.session_payload(&federated_sid).await.user_id,
            user.id
        );
        let denied = profile_http::unlink_my_federation_link(
            &sessions,
            &profile,
            &fixture.browser(Some(&federated_sid), true),
            id,
        )
        .await;
        assert_eq!(denied.status(), http::StatusCode::PRECONDITION_REQUIRED);
        let unlinked =
            profile_http::unlink_my_federation_link(&sessions, &profile, &browser, id).await;
        assert_eq!(unlinked.status(), http::StatusCode::NO_CONTENT);
        let listed = profile_http::my_federation_links(&sessions, &profile, &browser).await;
        assert_eq!(
            serde_json::from_slice::<Value>(listed.body()).unwrap()["total"],
            0
        );

        let login = authorization_query(fixture.start(provider, &anonymous, false).await);
        fixture.proof(provider, &login, &subject, true);
        assert_eq!(
            fixture
                .callback(provider, &anonymous, &login)
                .await
                .status(),
            http::StatusCode::UNAUTHORIZED
        );
    }
}

#[actix_web::test]
async fn linking_start_requires_csrf_and_recent_active_authentication() {
    let Some(fixture) = LinkFixture::new().await else {
        return;
    };
    let user = fixture
        .inner
        .create_user(&format!("link-start-{}@example.com", Uuid::now_v7()), true)
        .await;
    let fresh = fixture.session(&user, 0).await;
    let stale = fixture.session(&user, 301).await;
    for provider in [TEST_OIDC_PROVIDER_ID, "social"] {
        for (sid, csrf, expected) in [
            (Some(fresh.as_str()), false, http::StatusCode::BAD_REQUEST),
            (
                Some(stale.as_str()),
                true,
                http::StatusCode::PRECONDITION_REQUIRED,
            ),
            (None, true, http::StatusCode::UNAUTHORIZED),
        ] {
            let response = fixture
                .start(provider, &fixture.browser(sid, csrf), true)
                .await;
            assert_eq!(response.status(), expected, "{:?}", response.body());
            assert!(response.headers().get(http::header::LOCATION).is_none());
        }
    }
}

#[actix_web::test]
async fn link_callback_rejects_session_switch_revocation_and_invalid_proof() {
    let Some(fixture) = LinkFixture::new().await else {
        return;
    };
    let user = fixture
        .inner
        .create_user(&format!("link-owner-{}@example.com", Uuid::now_v7()), true)
        .await;
    let other = fixture
        .inner
        .create_user(&format!("link-other-{}@example.com", Uuid::now_v7()), true)
        .await;
    for provider in [TEST_OIDC_PROVIDER_ID, "social"] {
        for scenario in [
            "rotation",
            "other-user",
            "revoked",
            "expired-auth",
            "invalid-proof",
        ] {
            let sid = fixture.session(&user, 0).await;
            let owner_browser = fixture.browser(Some(&sid), true);
            let query = authorization_query(fixture.start(provider, &owner_browser, true).await);
            let subject = Uuid::now_v7().to_string();
            fixture.proof(provider, &query, &subject, scenario != "invalid-proof");
            let callback_sid = match scenario {
                "rotation" => fixture.session(&user, 0).await,
                "other-user" => fixture.session(&other, 0).await,
                "revoked" => {
                    nazo_valkey::SessionStore::new(&fixture.inner.state.valkey_connection())
                        .delete(&sid)
                        .await
                        .unwrap();
                    sid.clone()
                }
                "expired-auth" => {
                    fixture.store_session(&user, &sid, 301).await;
                    sid.clone()
                }
                _ => sid.clone(),
            };
            let response = fixture
                .callback(
                    provider,
                    &fixture.browser(Some(&callback_sid), true),
                    &query,
                )
                .await;
            let expected = match scenario {
                "rotation" | "other-user" => http::StatusCode::BAD_REQUEST,
                "expired-auth" => http::StatusCode::PRECONDITION_REQUIRED,
                _ => http::StatusCode::UNAUTHORIZED,
            };
            assert_eq!(
                response.status(),
                expected,
                "{provider}/{scenario}: {:?}",
                response.body()
            );
            let provider_type = if provider == "social" {
                "oauth2_social"
            } else {
                "oidc"
            };
            assert!(
                fixture
                    .inner
                    .external_identity_link(provider_type, provider, &subject)
                    .await
                    .is_none()
            );
            assert_eq!(
                fixture
                    .callback(provider, &owner_browser, &query)
                    .await
                    .status(),
                http::StatusCode::BAD_REQUEST
            );
        }
    }
}
