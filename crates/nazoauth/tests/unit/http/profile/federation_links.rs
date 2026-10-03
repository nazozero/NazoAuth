use crate::test_support::DatabaseExternalIdentityFixture;

use nazo_identity::{DEFAULT_TENANT_ID, ports::FederationLink};

use chrono::Utc;

use super::*;

#[test]
fn federation_link_json_excludes_raw_provider_claims() {
    let link = DatabaseExternalIdentityFixture {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        user_id: Uuid::now_v7(),
        provider_type: "oidc".to_owned(),
        provider_id: "google".to_owned(),
        subject: "provider-subject".to_owned(),
        email: "user@example.com".to_owned(),
        claims: json!({
            "access_token": "must-not-leak",
            "raw": "provider response"
        }),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: None,
    };

    // 列表视图只返回绑定索引和展示字段；原始 claims 不进入前端响应。
    let value = federation_link_json(link.federation_link().into());
    assert_eq!(value["provider_id"], "google");
    assert_eq!(value["subject"], "provider-subject");
    assert!(value.get("claims").is_none());
    assert!(value.get("access_token").is_none());
}

#[derive(Clone, Copy)]
struct UnreachableProfileDependencies;

impl nazo_identity::ports::SessionStorePort for UnreachableProfileDependencies {
    fn load<'a>(
        &'a self,
        _id: &'a nazo_identity::SessionId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::session::SessionSnapshot>>
    {
        panic!("invalid CSRF must not load session")
    }
    fn delete<'a>(
        &'a self,
        _id: &'a nazo_identity::SessionId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        panic!("invalid CSRF must not delete session")
    }
    fn rotate<'a>(
        &'a self,
        _old: &'a nazo_identity::SessionId,
        _expected: &'a nazo_identity::session::SessionSnapshot,
        _new: &'a nazo_identity::SessionId,
        _record: &'a nazo_identity::session::SessionRecord,
        _ttl: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::session::SessionRotationOutcome>
    {
        panic!("invalid CSRF must not rotate session")
    }
    fn compare_and_set<'a>(
        &'a self,
        _id: &'a nazo_identity::SessionId,
        _expected: &'a nazo_identity::session::SessionSnapshot,
        _record: &'a nazo_identity::session::SessionRecord,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::SessionUpdateOutcome> {
        panic!("invalid CSRF must not mutate session")
    }
}

impl nazo_identity::ports::SessionAccountPort for UnreachableProfileDependencies {
    fn public_account_by_id(
        &self,
        _tenant: nazo_identity::TenantId,
        _user: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        panic!("invalid CSRF must not load account")
    }
}

impl nazo_identity::ports::FederationLinkRepositoryPort for UnreachableProfileDependencies {
    fn list(
        &self,
        _tenant: nazo_identity::TenantId,
        _user: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<FederationLink>> {
        panic!("invalid CSRF must not list links")
    }
    fn delete(
        &self,
        _tenant: nazo_identity::TenantId,
        _user: nazo_identity::UserId,
        _link: Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<FederationLink>> {
        panic!("invalid CSRF must not delete links")
    }
}

#[actix_web::test]
async fn unlink_rejects_missing_or_mismatched_csrf_before_session_account_or_link_io() {
    use crate::http::sessions::SessionHttpConfig;
    use nazo_oauth_server::sessions::SessionResolver;
    let sessions = Data::new(SessionProfileHandles::new(
        std::sync::Arc::new(SessionResolver::new(
            std::sync::Arc::new(UnreachableProfileDependencies),
            std::sync::Arc::new(UnreachableProfileDependencies),
            nazo_identity::TenantContext::default_system().tenant_id,
        )),
        SessionHttpConfig::new("session", "csrf", false),
    ));
    let federation = Data::new(nazo_oauth_server::services::FederationProfileService::new(
        UnreachableProfileDependencies,
    ));
    for (cookies, header) in [
        ("session=present", None),
        ("session=present; csrf=expected", Some("mismatched")),
        ("session=present", Some("expected")),
    ] {
        let mut request = actix_web::test::TestRequest::delete().insert_header(("cookie", cookies));
        if let Some(header) = header {
            request = request.insert_header(("x-csrf-token", header));
        }
        let response = unlink_my_federation_link(
            sessions.clone(),
            federation.clone(),
            request.to_http_request(),
            Path::from(Uuid::now_v7()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
