use nazo_auth::{OAuthClient, ValidatedClientRegistration};
use nazo_identity::{
    AccountIdentity, OrganizationId, Principal, PublicAccount, RealmId, SubjectClaims,
    TenantContext, TenantId, UserId, UserProfile, UserRole,
};
use nazo_oauth_server_d1::{D1Provider, Database};
use serde_json::json;
use uuid::Uuid;
pub const TENANT: Uuid = Uuid::from_u128(1);
pub const CLIENT: Uuid = Uuid::from_u128(2);
pub const USER: Uuid = Uuid::from_u128(3);
pub async fn fixture() -> (Database, D1Provider) {
    let database = Database::in_memory().unwrap();
    database.execute_schema().unwrap();
    let provider = D1Provider::new(database.clone(), TenantId::new(TENANT).unwrap());
    provider.provision_client(&client(), None, 0).await.unwrap();
    let now = jiff::Timestamp::now();
    let claims:SubjectClaims=serde_json::from_value(json!({"subject":USER,"preferred_username":"test","email":"test@example.com","email_verified":false,"phone_number_verified":false,"updated_at":now.as_second()})).unwrap();
    let account = PublicAccount {
        principal: Principal {
            authorization_epoch: 0,
            user_id: UserId::new(USER).unwrap(),
            tenant: TenantContext {
                tenant_id: TenantId::new(TENANT).unwrap(),
                realm_id: RealmId::new(TENANT).unwrap(),
                organization_id: OrganizationId::new(TENANT).unwrap(),
            },
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "test".into(),
            email: "test@example.com".into(),
            email_verified: false,
            mfa_enabled: false,
        },
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
    };
    provider
        .provision_user(
            &account,
            &claims,
            nazo_identity::ports::PasswordHashInput::new("$argon2id$fixture").unwrap(),
        )
        .await
        .unwrap();
    (database, provider)
}
pub fn client() -> OAuthClient {
    OAuthClient {
        id: CLIENT,
        tenant_id: TENANT,
        realm_id: TENANT,
        organization_id: TENANT,
        require_mtls_bound_tokens: false,
        is_active: true,
        registration: ValidatedClientRegistration {
            client_id: "client".into(),
            client_name: "test".into(),
            client_type: "public".into(),
            redirect_uris: vec!["https://client.example/callback".into()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".into(), "profile".into(), "offline_access".into()],
            allowed_audiences: vec!["https://api.example".into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            token_endpoint_auth_method: "none".into(),
            subject_type: "public".into(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            backchannel_token_delivery_mode: "poll".into(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks_uri: None,
            jwks: None,
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: Default::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            security_policy: Default::default(),
        },
    }
}
