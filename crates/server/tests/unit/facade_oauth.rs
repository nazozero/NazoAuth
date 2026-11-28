use std::sync::Arc;

use actix_web::{App, test};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use diesel::sql_types::{Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn request(method: Method, path: &str, body: impl Into<Bytes>) -> Request<Bytes> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "issuer.example")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.into())
        .unwrap()
}

fn authenticated(mut request: Request<Bytes>, cookies: &str) -> Request<Bytes> {
    request
        .headers_mut()
        .insert(header::COOKIE, cookies.parse().unwrap());
    request
}

fn location(response: &Response<Bytes>) -> &str {
    assert!(
        response.status().is_redirection(),
        "{} {:?}",
        response.status(),
        response.body()
    );
    response.headers()[header::LOCATION].to_str().unwrap()
}

fn query_parameter(uri: &str, name: &str) -> String {
    url::Url::parse(uri)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == name)
        .unwrap()
        .1
        .into_owned()
}

fn proof(
    mut request: Request<Bytes>,
    key: &crate::test_support::ClientSigningFixture,
    target: &str,
    access_token: Option<&str>,
) -> Request<Bytes> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.typ = Some("dpop+jwt".to_owned());
    header.jwk = Some(serde_json::from_value(key.public_jwk("mounted-proof")).unwrap());
    let mut claims = json!({"jti": Uuid::now_v7(), "htm": request.method().as_str(),
        "htu": target, "iat": jiff::Timestamp::now().as_second()});
    if let Some(token) = access_token {
        claims["ath"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
    }
    request
        .headers_mut()
        .insert("dpop", key.encode_jwt(&header, &claims).parse().unwrap());
    request
}

fn json_response(response: Response<Bytes>) -> Value {
    assert_eq!(response.status(), StatusCode::OK, "{:?}", response.body());
    serde_json::from_slice(response.body()).unwrap()
}

#[actix_web::test]
async fn mounted_login_pkce_dpop_rotation_and_logout_use_external_paths() {
    mounted_oauth_flow(false, false).await;
}

#[actix_web::test]
async fn dynamic_actix_login_pkce_dpop_rotation_and_logout_use_external_paths() {
    mounted_oauth_flow(true, false).await;
}

#[actix_web::test]
async fn fixed_tower_login_pkce_dpop_rotation_and_logout_use_external_paths() {
    mounted_oauth_flow(false, true).await;
}

#[actix_web::test]
async fn dynamic_tower_login_pkce_dpop_rotation_and_logout_use_external_paths() {
    mounted_oauth_flow(true, true).await;
}

async fn mounted_oauth_flow(dynamic: bool, tower_transport: bool) {
    let prefix = "/team/auth";
    let issuer = format!("https://issuer.example{prefix}");
    let mut state = super::infrastructure(false).await;
    let settings = Arc::make_mut(&mut state.settings);
    settings.endpoint.issuer = issuer.clone();
    settings.endpoint.mtls_endpoint_base_url = if dynamic {
        format!("https://issuer.example:8443{prefix}")
    } else {
        format!("https://mtls.example{prefix}")
    };
    settings.endpoint.frontend_base_url = format!("{issuer}/ui/");
    settings.protocol.protected_resource_identifier = format!("{issuer}/fapi/resource");
    settings.protocol.dpop_nonce_policy = nazo_auth::DpopNoncePolicy::Optional;
    settings.session.session_cookie_name = "__Host-mounted_oauth_session".into();
    settings.session.csrf_cookie_name = "__Host-mounted_oauth_csrf".into();
    let capabilities =
        crate::test_support::facade::capabilities(&state, Default::default()).unwrap();
    let password = "mounted-flow-fixture-password";
    let password_hash = capabilities
        .passwords
        .hasher
        .hash_secret(password.to_owned())
        .await
        .unwrap()
        .into_persistence_value();
    let user_id = Uuid::now_v7();
    let email = format!("mount-{user_id}@example.test");
    let client_id = format!("mount-{user_id}");
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    diesel::sql_query("INSERT INTO users (id,username,email,password_hash,email_verified) VALUES ($1,$2,$2,$3,true)")
        .bind::<SqlUuid, _>(user_id).bind::<Text, _>(&email).bind::<Text, _>(password_hash)
        .execute(&mut connection).await.unwrap();
    diesel::sql_query(r#"INSERT INTO oauth_clients
        (client_id,client_name,client_type,redirect_uris,scopes,grant_types,
         token_endpoint_auth_method,require_dpop_bound_tokens,security_policy)
        VALUES ($1,'Mounted client','public','["https://client.example/callback"]',
          '["openid","profile","offline_access"]','["authorization_code","refresh_token"]',
          'none',true,
          '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,
            "require_signed_authorization_response":false,"require_signed_introspection_response":false,
            "session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}')"#)
        .bind::<Text, _>(&client_id).execute(&mut connection).await.unwrap();
    drop(connection);
    let application = Arc::new(
        nazoauth::NazoAuthBuilder::new(
            state.settings.application_configuration(),
            capabilities,
            format!("mount-{user_id}"),
        )
        .mount_path(prefix)
        .build()
        .await
        .unwrap(),
    );
    let binding = nazo_identity::TenantDirectoryBinding {
        tenant: state.settings.tenant.context,
        runtime_revision: 1,
        issuer: issuer.clone(),
        external_host: "issuer.example".into(),
    };
    let (registry, runtime) = if dynamic {
        let (registry, runtime) =
            super::runtime::registered_application(binding, application.clone()).await;
        (registry, Some(runtime))
    } else {
        (nazoauth::runtime::TenantRuntimeRegistry::empty(), None)
    };
    let app = test::init_service(
        App::new()
            .configure(nazo_http_actix::mount(application.clone(), &[]).unwrap())
            .wrap(actix_web::middleware::Condition::new(
                dynamic,
                nazo_http_actix::DynamicMount::new(registry.clone(), &[]).unwrap(),
            )),
    )
    .await;
    let existing = tower::service_fn(|_: Request<Full<Bytes>>| async {
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
    });
    let fixed_tower = nazo_http_tower::mount(existing, application, &[]).unwrap();
    let dynamic_tower = nazo_http_tower::mount_dynamic(existing, registry, &[]).unwrap();
    let send = |request: Request<Bytes>| {
        let app = &app;
        let fixed_tower = fixed_tower.clone();
        let dynamic_tower = dynamic_tower.clone();
        async move {
            if tower_transport {
                let response = if dynamic {
                    dynamic_tower.oneshot(request.map(Full::new)).await.unwrap()
                } else {
                    fixed_tower.oneshot(request.map(Full::new)).await.unwrap()
                };
                let (head, body) = response.into_parts();
                Response::from_parts(head, body.collect().await.unwrap().to_bytes())
            } else {
                super::standard_response(
                    test::call_service(app, super::framework_request(&request).to_request())
                        .await
                        .into_parts()
                        .1
                        .map_into_boxed_body(),
                )
                .await
            }
        }
    };
    let verifier = "01234567890123456789012345678901234567890123456789";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let authorization = form(&[
        ("client_id", client_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", "https://client.example/callback"),
        ("scope", "openid profile offline_access"),
        ("prompt", "consent"),
        ("state", "mounted-state"),
        ("nonce", "mounted-nonce"),
        ("code_challenge_method", "S256"),
        ("code_challenge", challenge.as_str()),
    ]);
    let response = send(request(
        Method::GET,
        &format!("{prefix}/authorize?{authorization}"),
        Bytes::new(),
    ))
    .await;
    let login_location = location(&response);
    assert!(login_location.starts_with(&format!("{issuer}/ui/auth?next=")));
    let next = query_parameter(login_location, "next");
    assert!(next.starts_with(&format!("{prefix}/authorize?")));
    let mut login = request(
        Method::POST,
        &format!("{prefix}/auth/login"),
        form(&[
            ("email", email.as_str()),
            ("password", password),
            ("next", next.as_str()),
        ]),
    );
    login
        .headers_mut()
        .insert(header::ORIGIN, "https://issuer.example".parse().unwrap());
    let response = send(login).await;
    assert_eq!(location(&response), next);
    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            cookie::Cookie::parse(value.to_str().unwrap())
                .unwrap()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(set_cookies.len(), 2);
    for cookie in &set_cookies {
        assert!(cookie.name().starts_with("__Host-"));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(true));
        assert!(cookie.domain().is_none());
    }
    let cookies = set_cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
        .collect::<Vec<_>>()
        .join("; ");
    let csrf = set_cookies
        .iter()
        .find(|cookie| cookie.name() == state.settings.session.csrf_cookie_name)
        .unwrap()
        .value();
    let response = send(authenticated(
        request(Method::GET, &next, Bytes::new()),
        &cookies,
    ))
    .await;
    let consent_location = location(&response);
    assert!(consent_location.starts_with(&format!("{issuer}/ui/consent?")));
    let request_id = query_parameter(consent_location, "request_id");
    let consent = json_response(
        send(authenticated(
            request(
                Method::GET,
                &format!("{prefix}/authorize/consent?request_id={request_id}"),
                Bytes::new(),
            ),
            &cookies,
        ))
        .await,
    );
    assert_eq!(consent["client_id"], client_id);
    let response = send(authenticated(
        request(
            Method::POST,
            &format!("{prefix}/authorize/decision"),
            form(&[
                ("request_id", request_id.as_str()),
                ("decision", "approve"),
                ("csrf_token", csrf),
            ]),
        ),
        &cookies,
    ))
    .await;
    let callback = location(&response);
    assert_eq!(query_parameter(callback, "state"), "mounted-state");
    let code = query_parameter(callback, "code");
    let key = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let token_url = format!("{issuer}/token");
    let token_body = form(&[
        ("grant_type", "authorization_code"),
        ("client_id", client_id.as_str()),
        ("code", code.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("code_verifier", verifier),
    ]);
    let mut exchange = request(Method::POST, &format!("{prefix}/token"), token_body.clone());
    if tower_transport {
        // Absolute-form selects the original URI authority for both tenant
        // routing and DPoP, regardless of a contradictory Host field.
        *exchange.uri_mut() = token_url.parse().unwrap();
        exchange
            .headers_mut()
            .insert(header::HOST, "unrelated.example".parse().unwrap());
    }
    let token = json_response(send(proof(exchange, &key, &token_url, None)).await);
    assert_eq!(token["token_type"], "DPoP");
    let access = token["access_token"].as_str().unwrap();
    let id_claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                token["id_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(id_claims["iss"], issuer);
    assert_eq!(id_claims["nonce"], "mounted-nonce");
    let mut userinfo = request(Method::GET, &format!("{prefix}/userinfo"), Bytes::new());
    userinfo.headers_mut().insert(
        header::AUTHORIZATION,
        format!("DPoP {access}").parse().unwrap(),
    );
    let userinfo = json_response(
        send(proof(
            userinfo,
            &key,
            &format!("{issuer}/userinfo"),
            Some(access),
        ))
        .await,
    );
    assert_eq!(userinfo["sub"], user_id.to_string());
    let refresh = token["refresh_token"].as_str().unwrap();
    let refresh_body = form(&[
        ("grant_type", "refresh_token"),
        ("client_id", client_id.as_str()),
        ("refresh_token", refresh),
    ]);
    let wrong_target = send(proof(
        request(
            Method::POST,
            &format!("{prefix}/token"),
            refresh_body.clone(),
        ),
        &key,
        "https://issuer.example/token",
        None,
    ))
    .await;
    assert_eq!(wrong_target.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(wrong_target.body()).unwrap()["error"],
        "invalid_dpop_proof"
    );
    let rotated = json_response(
        send(proof(
            request(Method::POST, &format!("{prefix}/token"), refresh_body),
            &key,
            &token_url,
            None,
        ))
        .await,
    );
    assert_ne!(rotated["refresh_token"], refresh);
    let replay = send(proof(
        request(Method::POST, &format!("{prefix}/token"), token_body),
        &key,
        &token_url,
        None,
    ))
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(replay.body()).unwrap()["error"],
        "invalid_grant"
    );
    let me = send(authenticated(
        request(Method::GET, &format!("{prefix}/auth/me"), Bytes::new()),
        &cookies,
    ))
    .await;
    assert_eq!(me.status(), StatusCode::OK);
    let confirmation = send(authenticated(
        request(Method::GET, &format!("{prefix}/logout"), Bytes::new()),
        &cookies,
    ))
    .await;
    assert_eq!(confirmation.status(), StatusCode::OK);
    assert!(
        std::str::from_utf8(confirmation.body())
            .unwrap()
            .contains(&format!("action=\"{prefix}/logout\""))
    );
    let mut logout = authenticated(
        request(Method::POST, &format!("{prefix}/auth/logout"), Bytes::new()),
        &cookies,
    );
    logout
        .headers_mut()
        .insert("x-csrf-token", csrf.parse().unwrap());
    let logout = send(logout).await;
    assert_eq!(logout.status(), StatusCode::OK, "{:?}", logout.body());
    assert_eq!(
        logout.headers().get_all(header::SET_COOKIE).iter().count(),
        2
    );
    for value in logout.headers().get_all(header::SET_COOKIE) {
        let cookie = cookie::Cookie::parse(value.to_str().unwrap()).unwrap();
        assert!(
            set_cookies
                .iter()
                .any(|login| login.name() == cookie.name())
        );
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(true));
        assert!(cookie.domain().is_none());
        assert_eq!(cookie.max_age(), Some(time::Duration::ZERO));
    }
    let me = send(authenticated(
        request(Method::GET, &format!("{prefix}/auth/me"), Bytes::new()),
        &cookies,
    ))
    .await;
    assert_eq!(me.status(), StatusCode::UNAUTHORIZED);
    if let Some(runtime) = runtime {
        runtime.shutdown().await;
    }
}
