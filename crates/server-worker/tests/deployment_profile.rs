#![cfg(feature = "provisioning")]

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use http::{Request, StatusCode};
use nazo_auth::{AuthorizationCodeState, AuthorizationStateStorePort, TokenStateStorePort};
use nazo_oauth_server::crypto::{blake3_hex, random_urlsafe_token};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::{D1Provider, Database};
use nazo_runtime_modules::{
    CasOutcome, DesiredMode, DesiredStateChange, DesiredStateRecord, ModuleId, ModuleRevision,
};
use nazo_server_worker::{WorkerApplication, WorkerConfiguration, WorkerSecrets, provisioning};
use serde_json::{Value, json};

struct TestDirectory(std::path::PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn token(application: &WorkerApplication, body: String) -> (StatusCode, Value) {
    let response = application
        .application
        .handle(
            Request::post("https://auth.example.com/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Bytes::from(body))
                .unwrap(),
        )
        .await;
    (
        response.status(),
        serde_json::from_slice(response.body()).unwrap(),
    )
}

#[test]
fn machine_profile_rejects_retained_user_grants_before_authentication_or_consumption() {
    futures_executor::block_on(async {
        let directory = TestDirectory(
            std::env::temp_dir().join(format!("nazo-profile-{}", uuid::Uuid::new_v4())),
        );
        std::fs::create_dir(&directory.0).unwrap();
        let path = directory.0.join("state.sqlite");
        let configuration = json!({
            "tenant": nazo_identity::TenantContext::default_system(),
            "issuer": "https://auth.example.com", "frontend_base_url": "https://auth.example.com/ui",
            "ingress": "direct_cloudflare", "modules": []
        });
        let pepper = random_urlsafe_token();
        let wrapping_key = STANDARD.encode(URL_SAFE_NO_PAD.decode(random_urlsafe_token()).unwrap());
        let input = serde_json::from_value(json!({
            "configuration": configuration, "client_secret_pepper": pepper,
            "signing_key_id": "test", "signing_key_base64": wrapping_key,
            "clients": [{
                "client_name": "Existing public client", "client_type": "public",
                "redirect_uris": ["https://app.example.com/callback"],
                "scopes": ["openid", "offline_access"], "allowed_audiences": ["resource://default"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "none", "security_policy": {"version": 1}
            }],
            "users": [{"email": "profile@example.com", "username": "profile-test", "password": random_urlsafe_token()}]
        })).unwrap();
        let provisioned = provisioning::provision(&path, input).await.unwrap();
        let client = provisioned["clients"][0]["client_id"].as_str().unwrap();
        let database = Database::open(&path).unwrap();
        let full_configuration: WorkerConfiguration =
            serde_json::from_value(configuration).unwrap();
        let provider = D1Provider::new(database.clone(), full_configuration.tenant.tenant_id);
        let code = random_urlsafe_token();
        let code_hash = blake3_hex(&code);
        let payload = serde_json::from_value(json!({
            "redemption_contract_version": nazo_auth::AUTHORIZATION_CODE_REDEMPTION_VERSION,
            "code_id": uuid::Uuid::new_v4(), "user_id": provisioned["user_ids"][0],
            "client_id": client, "redirect_uri": "https://app.example.com/callback",
            "redirect_uri_was_supplied": true, "scopes": ["openid", "offline_access"],
            "resource_indicators": [], "authorization_details": [], "nonce": null,
            "auth_time": jiff::Timestamp::now().as_second(), "amr": ["pwd"],
            "s256_code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "expires_at": jiff::Timestamp::now() + jiff::SignedDuration::from_secs(300)
        }))
        .unwrap();
        provider
            .store_authorization_code(
                &code_hash,
                &AuthorizationCodeState::Pending { payload },
                300,
            )
            .await
            .unwrap();
        let mut machine_configuration = full_configuration.clone();
        machine_configuration.machine_only = true;
        let build = |configuration| {
            WorkerApplication::build(
                configuration,
                database.clone(),
                pepper.clone(),
                WorkerSecrets::default()
                    .take_signing_wrapping_keys("test".into(), wrapping_key.clone(), None)
                    .unwrap(),
                provisioned["dummy_password_hash"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                None,
                WorkerSecrets::default(),
            )
        };
        let machine = build(machine_configuration).await.unwrap();
        let full = build(full_configuration.clone()).await.unwrap();
        let code_body = format!(
            "grant_type=authorization_code&client_id={client}&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        for body in [
            "grant_type=authorization_code&client_id=missing&code=missing".to_owned(),
            code_body.clone(),
        ] {
            let (status, response) = token(&machine, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(response["error"], "unsupported_grant_type");
            assert!(matches!(
                provider.load_authorization_code(&code_hash).await.unwrap(),
                Some(AuthorizationCodeState::Pending { .. })
            ));
        }
        let (status, issued) = token(&full, code_body).await;
        assert_eq!(status, StatusCode::OK);
        let refresh = issued["refresh_token"]
            .as_str()
            .expect("user grant issued refresh token");
        let refresh_body =
            format!("grant_type=refresh_token&client_id={client}&refresh_token={refresh}");
        let (status, response) = token(&machine, refresh_body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"], "unsupported_grant_type");
        let (status, response) = token(&full, refresh_body).await;
        assert_eq!(status, StatusCode::OK);
        assert!(response["access_token"].is_string());

        let mut passkey_configuration = full_configuration;
        passkey_configuration.passkey_only = true;
        let passkey = build(passkey_configuration).await.unwrap();
        for application in [&machine, &passkey] {
            for path in [
                "/auth/login",
                "/auth/%6cogin",
                "/admin/users",
                "/bc-authorize",
            ] {
                let response = application
                    .application
                    .handle(
                        Request::post(path)
                            .body(Bytes::from_static(b"invalid-body"))
                            .unwrap(),
                    )
                    .await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            }
        }
    });
}

#[test]
fn unconstructed_module_routes_reject_before_dispatch_while_device_drain_remains_available() {
    futures_executor::block_on(async {
        let directory = TestDirectory(
            std::env::temp_dir().join(format!("nazo-module-routes-{}", uuid::Uuid::new_v4())),
        );
        std::fs::create_dir(&directory.0).unwrap();
        let path = directory.0.join("state.sqlite");
        let configuration = json!({
            "tenant": nazo_identity::TenantContext::default_system(),
            "issuer": "https://auth.example.com", "frontend_base_url": "https://auth.example.com/ui",
            "ingress": "direct_cloudflare",
            "modules": ["device_authorization", "dynamic_client_registration"]
        });
        let pepper = random_urlsafe_token();
        let wrapping_key = STANDARD.encode(URL_SAFE_NO_PAD.decode(random_urlsafe_token()).unwrap());
        let initial_access_token = random_urlsafe_token();
        let input = serde_json::from_value(json!({
            "configuration": configuration, "client_secret_pepper": pepper,
            "signing_key_id": "test", "signing_key_base64": wrapping_key,
            "clients": [{
                "client_name": "Device client", "client_type": "public",
                "redirect_uris": [], "scopes": ["openid"],
                "allowed_audiences": ["resource://default"],
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                "token_endpoint_auth_method": "none",
                "security_policy": {"version": 1, "allow_cross_device_flows": true}
            }]
        }))
        .unwrap();
        let provisioned = provisioning::provision(&path, input).await.unwrap();
        let database = Database::open(&path).unwrap();
        let configuration: WorkerConfiguration = serde_json::from_value(configuration).unwrap();
        let provider = D1Provider::new(database.clone(), configuration.tenant.tenant_id);
        let modules = provider.runtime_modules(configuration.tenant.tenant_id.as_uuid());
        let build = |configuration| {
            WorkerApplication::build(
                configuration,
                database.clone(),
                pepper.clone(),
                WorkerSecrets::default()
                    .take_signing_wrapping_keys("test".into(), wrapping_key.clone(), None)
                    .unwrap(),
                provisioned["dummy_password_hash"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                Some(initial_access_token.clone()),
                WorkerSecrets::default(),
            )
        };
        let device_request = || {
            Request::post("https://auth.example.com/device_authorization")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Bytes::from(format!(
                    "client_id={}",
                    provisioned["clients"][0]["client_id"].as_str().unwrap()
                )))
                .unwrap()
        };
        let enabled = build(configuration.clone()).await.unwrap();
        let response = enabled.application.handle(device_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let issued: Value = serde_json::from_slice(response.body()).unwrap();
        let user_code = issued["user_code"].as_str().unwrap();

        let desired_before = modules.read_all_desired().await.unwrap();
        let mut absent_configuration = configuration.clone();
        absent_configuration.modules.clear();
        let absent = build(absent_configuration).await.unwrap();
        for (method, path) in [
            ("POST", "/device_authorization"),
            ("POST", "/%64evice_authorization"),
            ("GET", "/device"),
            ("GET", "/device/verification"),
            ("POST", "/device/decision"),
            ("POST", "/register"),
            ("GET", "/register/client"),
            ("PUT", "/register/client"),
            ("DELETE", "/register/client"),
            ("GET", "/register"),
            ("OPTIONS", "/device_authorization"),
            ("OPTIONS", "/device"),
            ("OPTIONS", "/device/verification"),
            ("OPTIONS", "/device/decision"),
            ("OPTIONS", "/register"),
            ("OPTIONS", "/register/client"),
        ] {
            let body = futures_util::stream::poll_fn(
                |_| -> std::task::Poll<Option<Result<Bytes, std::io::Error>>> {
                    panic!("unconstructed module must not poll a request body")
                },
            );
            let response = absent
                .application
                .handle_stream(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "text/plain")
                        .header("origin", "https://auth.example.com")
                        .header("access-control-request-method", "POST")
                        .body(body)
                        .unwrap(),
                )
                .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
            assert!(!response.headers().contains_key("allow"));
            assert!(
                !response
                    .headers()
                    .contains_key("access-control-allow-origin")
            );
        }
        assert_eq!(
            absent.application.handle(device_request()).await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(modules.read_all_desired().await.unwrap(), desired_before);

        let current = modules
            .read_desired(ModuleId::DeviceAuthorization)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.mode, DesiredMode::Enabled);
        assert!(matches!(
            modules
                .compare_and_set_desired(DesiredStateChange {
                    expected_revision: Some(current.revision),
                    next: DesiredStateRecord {
                        mode: DesiredMode::Disabled,
                        revision: ModuleRevision::new(current.revision.get() + 1),
                        updated_at: std::time::SystemTime::now(),
                        ..current
                    },
                })
                .await
                .unwrap(),
            CasOutcome::Applied(_)
        ));
        let draining = build(configuration).await.unwrap();
        let snapshot = draining.application.runtime_module_snapshot();
        assert!(!snapshot.accepting.contains(&ModuleId::DeviceAuthorization));
        assert!(snapshot.draining.contains(&ModuleId::DeviceAuthorization));
        let response = draining.application.handle(device_request()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(error["error"], "invalid_request");
        assert_eq!(
            error["error_description"],
            "Device Authorization Grant is not enabled."
        );
        for (path, expected) in [
            ("/device", StatusCode::FOUND),
            ("/device/verification", StatusCode::OK),
        ] {
            let response = draining
                .application
                .handle(
                    Request::get(format!("{path}?user_code={user_code}"))
                        .body(Bytes::new())
                        .unwrap(),
                )
                .await;
            assert_eq!(response.status(), expected, "{path}");
        }
    });
}
