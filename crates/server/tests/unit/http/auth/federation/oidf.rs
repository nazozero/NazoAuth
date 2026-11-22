//! HTTP fixture for the unmodified OpenID Foundation RP test server.

use super::*;
use actix_web::web;
use bytes::Bytes;
use nazo_identity::{SessionService, session::SessionResolution};
use nazoauth::config::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, FederationProviderRegistry,
};
use nazoauth::test_support::endpoints::auth::federation as rp;
use nazoauth::test_support::http::{ClientIpConfig, SessionCookieConfig};

// The isolated Suite uses a private address and a test CA. Admission here is
// confined to its exact origin. Request execution still uses native TLS,
// no-redirect and response-size policy.
struct SuiteTransport {
    client: Arc<dyn rp::FederationHttpClient>,
    authority: String,
}

impl rp::FederationHttpClient for SuiteTransport {
    fn send(&self, request: http::Request<Bytes>, limit: usize) -> rp::FederationHttpFuture<'_> {
        if request.uri().scheme_str() != Some("https")
            || request.uri().authority().map(http::uri::Authority::as_str)
                != Some(self.authority.as_str())
        {
            return Box::pin(async {
                anyhow::bail!("destination is outside the isolated OIDF suite")
            });
        }
        self.client.send(request, limit)
    }

    fn send_discovered(
        &self,
        request: http::Request<Bytes>,
        limit: usize,
    ) -> rp::FederationHttpFuture<'_> {
        self.send(request, limit)
    }
}

struct Bridge {
    config: rp::FederationHttpConfig,
    sessions: SessionService,
    service: Data<nazo_oauth_server::services::LocalFederationService>,
    limiter: Data<nazo_oauth_server::rate_limit::AuthRequestLimiter>,
    client_ip: Data<ClientIpConfig>,
}

impl Bridge {
    fn request(&self, request: &HttpRequest, body: Bytes) -> http::Request<Bytes> {
        let mut request =
            crate::test_support::transport::request_with_client_ip(request, &self.client_ip);
        *request.body_mut() = body;
        request
    }
}

#[actix_web::test]
#[ignore = "requires an isolated OIDF suite, PostgreSQL and Valkey"]
async fn oidf_rp_http_bridge() {
    let database_url = std::env::var("DATABASE_URL").expect("isolated DATABASE_URL");
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrate isolated conformance database");
    let origin =
        std::env::var("OIDF_RP_ORIGIN").unwrap_or_else(|_| "https://localhost:8443".into());
    let authority = origin
        .parse::<http::Uri>()
        .unwrap()
        .authority()
        .unwrap()
        .to_string();
    let fixture = LiveFederationFixture::new(None, None)
        .await
        .expect("PostgreSQL and Valkey must be configured");
    // The Suite sends an unverified UserInfo email, so use the existing-link path.
    let email = format!("oidf-rp-{}@example.com", Uuid::now_v7().simple());
    let user = fixture.create_user(&email, true).await;
    let mut providers = Vec::new();
    for (id, alias, discovery, logout, scopes) in [
        (
            "oidf-rp-test",
            "nazo-issue202",
            false,
            false,
            "openid email profile",
        ),
        (
            "oidf-config",
            "nazo-config",
            true,
            false,
            "openid email profile",
        ),
        ("oidf-config-keys", "nazo-config", true, false, "openid"),
        (
            "oidf-logout",
            "nazo-logout",
            true,
            true,
            "openid email profile",
        ),
    ] {
        let issuer = format!("{origin}/test/a/{alias}/");
        let endpoint = |name| {
            if discovery {
                String::new()
            } else {
                format!("{issuer}{name}")
            }
        };
        let adapter = OidcFederationSettings {
            discovery,
            backchannel_logout: logout,
            id_token_signed_response_alg: logout.then_some(Algorithm::RS256),
            post_logout_redirect_uri: logout.then(|| format!("{origin}/rp/signed-out")),
            provider_id: id.into(),
            authorization_endpoint: endpoint("authorize"),
            token_endpoint: endpoint("token"),
            jwks_url: endpoint("jwks"),
            userinfo_endpoint: (!discovery).then(|| endpoint("userinfo")),
            client_id: "nazoauth-issue202".into(),
            client_secret: "nazoauth-issue202-test-secret".into(),
            redirect_uri: format!("{origin}/rp/auth/federation/{id}/callback"),
            issuer,
            scopes: scopes.into(),
        };
        fixture
            .insert_external_identity_link(&user, "oidc", id, "user-subject-1234531", &email)
            .await;
        providers.push(ExternalLoginProvider {
            provider_id: id.into(),
            enabled: true,
            display_name: id.into(),
            icon: None,
            display_order: 0,
            adapter: ExternalLoginProviderAdapter::Oidc(adapter),
        });
    }
    let state = fixture.state;
    let mut config = crate::test_support::federation_http_config(&state)
        .get_ref()
        .clone();
    config.providers = FederationProviderRegistry::new(providers).unwrap();
    config.client = Arc::new(SuiteTransport {
        client: config.client,
        authority,
    });
    let bridge = Data::new(Bridge {
        config,
        sessions: SessionService::new(
            Arc::new(nazo_valkey::SessionStore::new(&state.valkey_connection())),
            Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
            state.settings.tenant.context.tenant_id,
        ),
        service: crate::test_support::federation_service(&state),
        limiter: crate::test_support::auth_request_limiter(&state),
        client_ip: crate::test_support::client_ip_config(&state),
    });
    let bind = std::env::var("OIDF_RP_BIND").unwrap_or_else(|_| "127.0.0.1:18080".into());
    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(bridge.clone())
            .route(
                "/health",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            )
            .route(
                "/signed-out",
                web::get().to(|| async { HttpResponse::Ok().body("Signed out") }),
            )
            .route("/session-status", web::get().to(session_status))
            .route("/auth/federation/{provider_id}/start", web::get().to(start))
            .route(
                "/auth/federation/{provider_id}/callback",
                web::get().to(callback),
            )
            .route(
                "/auth/federation/{provider_id}/logout",
                web::post().to(logout),
            )
            .route(
                "/auth/federation/{provider_id}/backchannel-logout",
                web::post().to(backchannel),
            )
    })
    .workers(1)
    .bind(bind)
    .expect("bind isolated RP fixture")
    .run()
    .await
    .expect("RP fixture server");
}

async fn start(bridge: Data<Bridge>, req: HttpRequest, provider: Path<String>) -> HttpResponse {
    let request = bridge.request(&req, Bytes::new());
    nazo_http_actix::forward_response(
        rp::federation_provider_start(
            &bridge.limiter,
            &bridge.client_ip,
            &bridge.service,
            &bridge.config,
            &request,
            provider.into_inner(),
        )
        .await,
    )
}

async fn callback(
    bridge: Data<Bridge>,
    req: HttpRequest,
    provider: Path<String>,
    query: Query<OidcCallbackQuery>,
) -> HttpResponse {
    let request = bridge.request(&req, Bytes::new());
    nazo_http_actix::forward_response(
        rp::federation_provider_callback(
            &bridge.limiter,
            &bridge.client_ip,
            &bridge.service,
            &bridge.config,
            &request,
            provider.into_inner(),
            query.into_inner(),
        )
        .await,
    )
}

async fn logout(
    bridge: Data<Bridge>,
    req: HttpRequest,
    provider: Path<String>,
    body: Bytes,
) -> HttpResponse {
    let request = bridge.request(&req, body);
    nazo_http_actix::forward_response(
        rp::federation_provider_logout(
            &bridge.sessions,
            &bridge.config,
            &request,
            provider.into_inner(),
        )
        .await,
    )
}

async fn backchannel(
    bridge: Data<Bridge>,
    req: HttpRequest,
    provider: Path<String>,
    body: Bytes,
) -> HttpResponse {
    let request = bridge.request(&req, body);
    nazo_http_actix::forward_response(
        rp::federation_provider_backchannel_logout(
            &bridge.limiter,
            &bridge.client_ip,
            &bridge.service,
            &bridge.config,
            &request,
            provider.into_inner(),
        )
        .await,
    )
}

async fn session_status(bridge: Data<Bridge>, req: HttpRequest) -> HttpResponse {
    let cookies = SessionCookieConfig::new(
        &bridge.config.session_cookie_name,
        &bridge.config.csrf_cookie_name,
        bridge.config.cookie_secure,
    );
    let request = bridge.request(&req, Bytes::new());
    let Some(session_id) = cookies.session_id(&request) else {
        return HttpResponse::Unauthorized().finish();
    };
    match bridge
        .sessions
        .current(&session_id, jiff::Timestamp::now().as_second())
        .await
    {
        Ok(SessionResolution::Present(_)) => HttpResponse::Ok().finish(),
        Ok(_) => HttpResponse::Unauthorized().finish(),
        Err(_) => HttpResponse::ServiceUnavailable().finish(),
    }
}
