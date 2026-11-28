use std::sync::Arc;

use actix_web::{
    App,
    http::{StatusCode, header},
    test,
};
use diesel::sql_types::{Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    UserId,
    ports::LoginSessionPort,
    session::{SessionId, SessionRecord},
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::test_support::{DatabaseUserFixture, passkey_authenticator::FakeAuthenticator};

#[actix_web::test]
async fn mounted_passkey_registration_login_and_replay_keep_cookie_scope() {
    let mut state = super::infrastructure(false).await;
    let settings = Arc::make_mut(&mut state.settings);
    settings.endpoint.issuer = "https://example.com/testauth".into();
    settings.endpoint.mtls_endpoint_base_url = "https://mtls.example.com/testauth".into();
    settings.endpoint.frontend_base_url = "https://example.com/testauth/ui/".into();
    settings.endpoint.cors_allowed_origins = vec!["https://example.com".into()];
    settings.protocol.protected_resource_identifier =
        "https://example.com/testauth/fapi/resource".into();
    settings.identity.passkey.rp_id = "example.com".into();
    settings.identity.passkey.origin = "https://example.com".into();
    settings.identity.passkey.require_user_verification = true;
    settings.identity.passkey.require_user_handle = true;
    settings.session.session_cookie_name = "__Host-mount_passkey_session".into();
    settings.session.csrf_cookie_name = "__Host-mount_passkey_csrf".into();

    let tenant = settings.tenant.context;
    let email = format!("mount-passkey-{}@example.com", Uuid::now_v7());
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    let user = diesel::sql_query(
        "INSERT INTO users
         (tenant_id,realm_id,organization_id,username,email,password_hash,
          is_active,mfa_enabled,email_verified,role,admin_level)
         VALUES ($1,$2,$3,$4,$5,'unused-passkey-fixture',true,false,true,'user',0)
         RETURNING *",
    )
    .bind::<SqlUuid, _>(tenant.tenant_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.realm_id.as_uuid())
    .bind::<SqlUuid, _>(tenant.organization_id.as_uuid())
    .bind::<Text, _>(format!("mount-passkey-{}", Uuid::now_v7()))
    .bind::<Text, _>(&email)
    .get_result::<DatabaseUserFixture>(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let user_id = UserId::new(user.id).unwrap();
    let session_id = SessionId::generate();
    nazo_valkey::SessionStore::new(&state.valkey_connection())
        .create(
            session_id.as_str(),
            &SessionRecord::new(
                user_id,
                0,
                jiff::Timestamp::now().as_second(),
                vec!["pwd".into()],
                false,
                Some(Uuid::now_v7().to_string()),
            ),
            900,
        )
        .await
        .unwrap();
    let application = Arc::new(
        crate::test_support::facade::builder(&state, Default::default())
            .unwrap()
            .mount_path("/testauth")
            .build()
            .await
            .unwrap(),
    );
    let app =
        test::init_service(App::new().configure(nazo_http_actix::mount(application, &[]).unwrap()))
            .await;
    let send = |request: test::TestRequest| {
        let app = &app;
        async move { test::call_service(app, request.to_request()).await }
    };
    let csrf = "mounted-passkey-csrf";
    let browser_cookies = format!(
        "__Host-mount_passkey_session={}; __Host-mount_passkey_csrf={csrf}",
        session_id.as_str(),
    );
    let authenticated = |path: &str, body: Value| {
        test::TestRequest::post()
            .uri(path)
            .insert_header((header::ORIGIN, "https://example.com"))
            .insert_header((header::COOKIE, browser_cookies.as_str()))
            .insert_header(("x-csrf-token", csrf))
            .set_json(body)
    };
    let begin = send(authenticated(
        "/testauth/auth/me/passkeys/registration/begin",
        json!({"label": "Mounted authenticator"}),
    ))
    .await;
    assert_eq!(begin.status(), StatusCode::OK);
    let begin: Value = test::read_body_json(begin).await;
    let mut authenticator = FakeAuthenticator::new(Uuid::now_v7().as_bytes());
    let registration = json!({
        "ceremony_id": begin["ceremony_id"],
        "response": authenticator.registration_response_json(
            begin["publicKey"]["challenge"].as_str().unwrap(),
            "https://example.com",
        ),
    });
    let registered = send(authenticated(
        "/testauth/auth/me/passkeys/registration/finish",
        registration.clone(),
    ))
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let registered: Value = test::read_body_json(registered).await;
    assert_eq!(registered["label"], "Mounted authenticator");
    let replay = send(authenticated(
        "/testauth/auth/me/passkeys/registration/finish",
        registration,
    ))
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    let begin = send(
        test::TestRequest::post()
            .uri("/testauth/auth/passkey/begin")
            .set_json(json!({"email": email})),
    )
    .await;
    assert_eq!(begin.status(), StatusCode::OK);
    let begin: Value = test::read_body_json(begin).await;
    let user_handle = nazo_identity::passkey::passkey_user_handle(tenant.tenant_id, user_id);
    let assertion = json!({
        "ceremony_id": begin["ceremony_id"],
        "response": authenticator.authentication_response_json(
            begin["publicKey"]["challenge"].as_str().unwrap(),
            "https://example.com",
            Some(&user_handle),
        ),
    });
    let logged_in = send(
        test::TestRequest::post()
            .uri("/testauth/auth/passkey/finish")
            .set_json(&assertion),
    )
    .await;
    assert_eq!(logged_in.status(), StatusCode::OK);
    let cookies = logged_in
        .headers()
        .get_all(header::SET_COOKIE)
        .map(|value| {
            cookie::Cookie::parse(value.to_str().unwrap())
                .unwrap()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    for cookie in &cookies {
        assert!(cookie.name().starts_with("__Host-mount_passkey_"));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(true));
        assert!(cookie.domain().is_none());
    }
    let cookie_header = cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
        .collect::<Vec<_>>()
        .join("; ");
    let profile = send(
        test::TestRequest::get()
            .uri("/testauth/auth/me")
            .insert_header((header::COOKIE, cookie_header)),
    )
    .await;
    assert_eq!(profile.status(), StatusCode::OK);
    let replay = send(
        test::TestRequest::post()
            .uri("/testauth/auth/passkey/finish")
            .set_json(assertion),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(!replay.headers().contains_key(header::SET_COOKIE));
}
