#![cfg(feature = "provisioning")]

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use http::{Request, StatusCode};
use nazo_auth::{AuthorizationCodeState, AuthorizationStateStorePort, TokenStateStorePort};
use nazo_oauth_server::crypto::{blake3_hex, random_urlsafe_token};
use nazo_oauth_server_d1::{D1Provider, Database};
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
