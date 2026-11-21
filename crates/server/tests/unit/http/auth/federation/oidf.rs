//! HTTP fixture for the unmodified OpenID Foundation RP test server.

use super::*;

#[actix_web::test]
#[ignore = "requires an isolated OIDF suite, PostgreSQL and Valkey"]
async fn oidf_rp_http_bridge() {
    let database_url = std::env::var("DATABASE_URL").expect("isolated DATABASE_URL");
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrate isolated conformance database");
    let issuer = "https://localhost:8443/test/a/nazo-issue202/";
    let provider = OidcFederationSettings {
        provider_id: "oidf-rp-test".into(),
        issuer: issuer.into(),
        authorization_endpoint: format!("{issuer}authorize"),
        token_endpoint: format!("{issuer}token"),
        jwks_url: format!("{issuer}jwks"),
        client_id: "nazoauth-issue202".into(),
        client_secret: "nazoauth-issue202-test-secret".into(),
        redirect_uri: "https://localhost:8443/rp/auth/federation/oidf-rp-test/callback".into(),
        scopes: "openid email profile".into(),
    };
    let fixture = LiveFederationFixture::new(Some(provider), None)
        .await
        .expect("PostgreSQL and Valkey must be configured");
    // This link belongs to the suite's fixed subject. Its unverified UserInfo
    // email must never provision or relink an account.
    let user = fixture
        .create_user("oidf-rp-linked@example.com", true)
        .await;
    fixture
        .insert_external_identity_link(
            &user,
            "oidc",
            "oidf-rp-test",
            "user-subject-1234531",
            "oidf-rp-linked@example.com",
        )
        .await;
    let state = fixture.state;
    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .app_data(state.clone())
            .route(
                "/health",
                actix_web::web::get().to(|| async { HttpResponse::Ok().finish() }),
            )
            .route(
                "/auth/federation/{provider_id}/start",
                actix_web::web::get().to(federation_provider_start),
            )
            .route(
                "/auth/federation/{provider_id}/callback",
                actix_web::web::get().to(federation_provider_callback),
            )
    })
    .workers(1)
    .bind("127.0.0.1:18080")
    .expect("bind isolated RP fixture")
    .run()
    .await
    .expect("RP fixture server");
}
