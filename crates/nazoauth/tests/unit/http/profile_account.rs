use crate::http::Response;
use bytes::Bytes;
use cookie::Cookie;
use http::{StatusCode, header};
use std::sync::Mutex;

use jiff::Timestamp;
use nazo_identity::{AuthorizedApplicationsView, SessionId};
use nazo_oauth_server::contracts::profile_account::ProfileAccountFuture;
use serde_json::{Value, json};

use super::*;

async fn response_json(response: Response) -> Value {
    serde_json::from_slice(&response.into_body()).unwrap()
}

struct FakeOperations {
    me: Mutex<Result<ProfileMe, ProfileAccountError>>,
    update: Mutex<Result<AccountProfileView, ProfileAccountError>>,
    applications: Mutex<Result<AuthorizedApplicationsView, ProfileAccountError>>,
    update_calls: Mutex<usize>,
}

impl ProfileAccountOperations for FakeOperations {
    fn me(&self, _session_id: SessionId) -> ProfileAccountFuture<'_, ProfileMe> {
        let result = self.me.lock().unwrap().clone();
        Box::pin(async move { result })
    }

    fn update(
        &self,
        _session_id: SessionId,
        _patch: ProfilePatch,
    ) -> ProfileAccountFuture<'_, AccountProfileView> {
        *self.update_calls.lock().unwrap() += 1;
        let result = self.update.lock().unwrap().clone();
        Box::pin(async move { result })
    }

    fn applications(
        &self,
        _session_id: SessionId,
    ) -> ProfileAccountFuture<'_, AuthorizedApplicationsView> {
        let result = self.applications.lock().unwrap().clone();
        Box::pin(async move { result })
    }
}

fn profile() -> AccountProfileView {
    AccountProfileView {
        id: uuid::Uuid::from_u128(1),
        email: "alice@example.test".to_owned(),
        display_name: Some("Alice".to_owned()),
        avatar_url: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile_url: None,
        website_url: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
        mfa_enabled: true,
        role: "user",
        admin_level: 0,
        authorized_app_count: 2,
    }
}

fn fake(
    me: Result<ProfileMe, ProfileAccountError>,
) -> (ProfileAccountEndpoint, Arc<FakeOperations>) {
    let operations = Arc::new(FakeOperations {
        me: Mutex::new(me),
        update: Mutex::new(Ok(profile())),
        applications: Mutex::new(Ok(AuthorizedApplicationsView {
            total: 1,
            items: vec![nazo_identity::AuthorizedApplicationView {
                client_id: "client".to_owned(),
                client_name: "Client".to_owned(),
                last_scopes: vec!["openid".to_owned()],
                last_authorized_at: Timestamp::new(1_700_000_000, 0).unwrap(),
                authorization_count: 3,
            }],
        })),
        update_calls: Mutex::new(0),
    });
    (
        ProfileAccountEndpoint::new(
            operations.clone(),
            SessionCookieConfig::new("session", "csrf", true),
        ),
        operations,
    )
}

#[test]
fn missing_session_keeps_login_required_body_and_cookie_clearing() {
    futures_executor::block_on(async {
        let (endpoint, _) = fake(Ok(ProfileMe::Active(Box::new(profile()))));
        let response = profile_me(
            &endpoint,
            &http::Request::builder().body(Bytes::new()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert!(response.headers().get(header::CACHE_CONTROL).is_none());
        assert!(response.headers().get(header::PRAGMA).is_none());
        let body = response_json(response).await;
        assert_eq!(body["error"], "login_required");
    });
}

#[test]
fn active_me_keeps_exact_profile_shape_without_csrf_token() {
    futures_executor::block_on(async {
        let (endpoint, _) = fake(Ok(ProfileMe::Active(Box::new(profile()))));
        let response = profile_me(
            &endpoint,
            &http::Request::builder()
                .header(header::COOKIE, (Cookie::new("session", "sid")).to_string())
                .header(
                    header::COOKIE,
                    (Cookie::new("csrf", "csrf-token")).to_string(),
                )
                .body(Bytes::new())
                .unwrap(),
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
        let body = response_json(response).await;
        assert_eq!(body["id"], uuid::Uuid::from_u128(1).to_string());
        assert_eq!(body["mfa_required"], false);
        assert_eq!(body["authorized_app_count"], 2);
        assert!(body.get("csrf_token").is_none());
    });
}

#[test]
fn pending_mfa_me_returns_cookie_csrf_token_and_reduced_profile() {
    futures_executor::block_on(async {
        let (endpoint, _) = fake(Ok(ProfileMe::PendingMfa(PendingMfaProfileView {
            id: uuid::Uuid::from_u128(2),
            email: "pending@example.test".to_owned(),
        })));
        let response = profile_me(
            &endpoint,
            &http::Request::builder()
                .header(header::COOKIE, (Cookie::new("session", "sid")).to_string())
                .header(
                    header::COOKIE,
                    (Cookie::new("csrf", "csrf-token")).to_string(),
                )
                .body(Bytes::new())
                .unwrap(),
        )
        .await;
        let body = response_json(response).await;
        assert_eq!(
            body,
            json!({
                "id": uuid::Uuid::from_u128(2),
                "email": "pending@example.test",
                "mfa_required": true,
                "csrf_token": "csrf-token"
            })
        );
    });
}

#[test]
fn update_rejects_missing_csrf_before_calling_operations() {
    futures_executor::block_on(async {
        let (endpoint, operations) = fake(Ok(ProfileMe::Active(Box::new(profile()))));
        let response = profile_update(
            &endpoint,
            &http::Request::builder()
                .method("PATCH")
                .header(header::COOKIE, (Cookie::new("session", "sid")).to_string())
                .body(Bytes::new())
                .unwrap(),
            UpdateProfileRequest {
                display_name: Some("Alice".to_owned()),
                given_name: None,
                family_name: None,
                middle_name: None,
                nickname: None,
                profile_url: None,
                website_url: None,
                gender: None,
                birthdate: None,
                zoneinfo: None,
                locale: None,
                address_formatted: None,
                address_street_address: None,
                address_locality: None,
                address_region: None,
                address_postal_code: None,
                address_country: None,
                phone_number: None,
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(*operations.update_calls.lock().unwrap(), 0);
    });
}

#[test]
fn update_and_applications_keep_success_contracts() {
    futures_executor::block_on(async {
        let (endpoint, _) = fake(Ok(ProfileMe::Active(Box::new(profile()))));
        let endpoint = endpoint;
        let update = profile_update(
            &endpoint.clone(),
            &http::Request::builder()
                .method("PATCH")
                .header(header::COOKIE, (Cookie::new("session", "sid")).to_string())
                .header(
                    header::COOKIE,
                    (Cookie::new("csrf", "csrf-token")).to_string(),
                )
                .header("x-csrf-token", "csrf-token")
                .body(Bytes::new())
                .unwrap(),
            UpdateProfileRequest {
                display_name: Some("Alice".to_owned()),
                given_name: None,
                family_name: None,
                middle_name: None,
                nickname: None,
                profile_url: None,
                website_url: None,
                gender: None,
                birthdate: None,
                zoneinfo: None,
                locale: None,
                address_formatted: None,
                address_street_address: None,
                address_locality: None,
                address_region: None,
                address_postal_code: None,
                address_country: None,
                phone_number: None,
            },
        )
        .await;
        assert_eq!(
            update.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let update_body = response_json(update).await;
        assert_eq!(update_body["display_name"], "Alice");
        assert!(update_body.get("mfa_required").is_none());

        let applications = profile_applications(
            &endpoint,
            &http::Request::builder()
                .header(header::COOKIE, (Cookie::new("session", "sid")).to_string())
                .body(Bytes::new())
                .unwrap(),
        )
        .await;
        assert_eq!(
            applications.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let applications_body = response_json(applications).await;
        assert_eq!(applications_body["total"], 1);
        assert_eq!(
            applications_body["items"][0]["last_scopes"],
            json!(["openid"])
        );
    });
}

#[test]
fn validation_and_dependency_errors_keep_status_and_oauth_codes() {
    futures_executor::block_on(async {
        let cases = [
            (
                ProfileAccountError::Validation(ProfileValidationError::FieldTooLong(
                    "display_name",
                )),
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                ProfileAccountError::SessionLookupUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
            ),
            (
                ProfileAccountError::ApplicationsUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
            ),
        ];
        for (error, status, code) in cases {
            let response = profile_account_error_response(
                error,
                &SessionCookieConfig::new("session", "csrf", true),
            );
            assert_eq!(response.status(), status);
            assert!(response.headers().get(header::CACHE_CONTROL).is_none());
            assert!(response.headers().get(header::PRAGMA).is_none());
            let body = response_json(response).await;
            assert_eq!(body["error"], code);
        }
    });
}
