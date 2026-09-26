use chrono::{DateTime, TimeZone, Utc};
use nazo_auth::*;
use nazo_identity::SubjectClaims;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

type AccessRevocationCall = (Uuid, Uuid, String, Option<DateTime<Utc>>, Option<Uuid>);

#[derive(Default)]
struct Calls {
    access: Vec<AccessRevocationCall>,
    mixed: usize,
    revocation_reads: usize,
}
#[derive(Clone)]
struct Ports {
    claims: Option<Claims>,
    calls: Arc<Mutex<Calls>>,
    unavailable: bool,
}

#[allow(unused_variables)]
impl TokenRepositoryPort for Ports {
    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
        panic!("unexpected commit_token_issuance call")
    }
    fn single_use_redemption<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        grant_key: &'a str,
    ) -> TokenFuture<'a, Option<SingleUseRedemption>> {
        panic!("unexpected single_use_redemption call")
    }
    fn userinfo_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        subject: UserinfoSubjectRef<'a>,
        client_id: &'a str,
    ) -> TokenFuture<'a, Option<UserinfoSnapshot>> {
        panic!("unexpected userinfo_snapshot call")
    }
    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        panic!("unexpected refresh_token call")
    }
    fn inspect_lost_response_successor<'a>(
        &'a self,
        token: &'a RefreshToken,
        client_id: Uuid,
        retry_started_at: DateTime<Utc>,
    ) -> TokenFuture<'a, Option<RefreshToken>> {
        panic!("unexpected inspect_lost_response_successor call")
    }
    fn active_subject_claims(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, Option<SubjectClaims>> {
        panic!("unexpected active_subject_claims call")
    }
    fn active_subject_id(&self, tenant_id: Uuid, user_id: Uuid) -> TokenFuture<'_, Option<Uuid>> {
        panic!("unexpected active_subject_id call")
    }
    fn active_subject_id_by_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
    ) -> TokenFuture<'a, Option<Uuid>> {
        panic!("unexpected active_subject_id_by_access_token call")
    }
    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.calls.lock().unwrap().access.push((
                tenant_id,
                client_id,
                access_token_jti.to_owned(),
                access_token_expires_at,
                refresh_token_family_id,
            ));
            if self.unavailable {
                Err(TokenPortError::Unavailable)
            } else {
                Ok(())
            }
        })
    }
    fn access_token_revoked<'a>(&'a self, tenant_id: Uuid, jti: &'a str) -> TokenFuture<'a, bool> {
        Box::pin(async move {
            self.calls.lock().unwrap().revocation_reads += 1;
            if self.unavailable {
                Err(TokenPortError::Unavailable)
            } else {
                Ok(false)
            }
        })
    }
    fn refresh_family_active(
        &self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> TokenFuture<'_, bool> {
        panic!("unexpected refresh_family_active call")
    }
    fn revoke_token<'a>(&'a self, input: TokenRevocation<'a>) -> TokenFuture<'a, usize> {
        Box::pin(async move {
            assert!(input.access_token.is_none());
            self.calls.lock().unwrap().mixed += 1;
            Ok(3)
        })
    }
}

#[allow(unused_variables)]
impl TokenStateStorePort for Ports {
    fn load_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
    ) -> TokenFuture<'a, Option<AuthorizationCodeState>> {
        panic!("unexpected load_authorization_code call")
    }
    fn begin_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        consuming_at: DateTime<Utc>,
    ) -> TokenFuture<'a, AuthorizationCodeBeginResult> {
        panic!("unexpected begin_authorization_code call")
    }
    fn mark_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        replacement: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, AuthorizationCodeTransitionResult> {
        panic!("unexpected mark_authorization_code call")
    }
    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> TokenFuture<'a, ()> {
        panic!("unexpected delete_authorization_code call")
    }
    fn increment_token_management_rate<'a>(
        &'a self,
        subject: &'a str,
        window_seconds: u64,
    ) -> TokenFuture<'a, u64> {
        panic!("unexpected increment_token_management_rate call")
    }
    fn store_native_sso<'a>(
        &'a self,
        secret: &'a str,
        value: &'a Value,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()> {
        panic!("unexpected store_native_sso call")
    }
    fn load_native_sso<'a>(&'a self, secret: &'a str) -> TokenFuture<'a, Option<Value>> {
        panic!("unexpected load_native_sso call")
    }
}

#[allow(unused_variables)]
impl TokenSignerPort for Ports {
    fn sign_access_token<'a>(
        &'a self,
        input: AccessTokenSignInput<'a>,
    ) -> TokenFuture<'a, IssuedAccessToken> {
        panic!("unexpected sign_access_token call")
    }
    fn sign_id_token<'a>(&'a self, input: IdTokenSignInput<'a>) -> TokenFuture<'a, String> {
        panic!("unexpected sign_id_token call")
    }
    fn decode_access_token<'a>(
        &'a self,
        issuer: &'a str,
        token: &'a str,
    ) -> TokenFuture<'a, Option<Claims>> {
        Box::pin(async move { Ok(self.claims.clone()) })
    }
    fn decode_id_token<'a>(
        &'a self,
        issuer: &'a str,
        token: &'a str,
    ) -> TokenFuture<'a, Option<Value>> {
        panic!("unexpected decode_id_token call")
    }
    fn sign_introspection_response<'a>(
        &'a self,
        input: IntrospectionSignInput<'a>,
    ) -> TokenFuture<'a, String> {
        panic!("unexpected sign_introspection_response call")
    }
}

fn registration(client_id: &str) -> ValidatedClientRegistration {
    ValidatedClientRegistration {
        client_id: client_id.to_owned(),
        client_name: "Test client".to_owned(),
        client_type: "confidential".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: Vec::new(),
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "client_secret_post".to_owned(),
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        backchannel_token_delivery_mode: "poll".to_owned(),
        backchannel_client_notification_endpoint: None,
        backchannel_authentication_request_signing_alg: None,
        backchannel_user_code_parameter: false,
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
        presentation: nazo_auth::ClientPresentationMetadata::default(),
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
        security_policy: nazo_auth::ClientSecurityPolicy::default(),
    }
}

fn client(tenant_id: Uuid) -> OAuthClient {
    OAuthClient {
        id: Uuid::from_u128(20),
        tenant_id,
        realm_id: Uuid::from_u128(2),
        organization_id: Uuid::from_u128(3),
        registration: registration("client-1"),
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

fn fixture(
    claims: Option<Claims>,
    unavailable: bool,
) -> (TokenService<Ports, Ports>, Arc<Mutex<Calls>>) {
    let ports = Ports {
        claims,
        calls: Arc::new(Mutex::new(Calls::default())),
        unavailable,
    };
    (
        TokenService::new(ports.clone(), ports.clone(), ports.clone()),
        ports.calls,
    )
}
fn claims(client: &OAuthClient, expires_at: i64) -> Claims {
    serde_json::from_value(serde_json::json!({
        "iss": "https://issuer.example", "sub": "user", "tenant_id": client.tenant_id.to_string(),
        "subject_type": "public", "aud": client.client_id, "client_id": client.client_id,
        "scope": "openid", "token_use": "access", "jti": "verified-jti", "iat": expires_at - 60,
        "nbf": expires_at - 60, "exp": expires_at,
    }))
    .unwrap()
}
#[test]
fn verified_owned_access_revokes_directly_and_retains_audit_count_and_expiry() {
    let client = client(Uuid::now_v7());
    let expiry = 1_800_000_000;
    let (service, calls) = fixture(Some(claims(&client, expiry)), false);
    assert_eq!(
        futures_executor::block_on(service.revoke_token("https://issuer.example", "jwt", &client)),
        Ok(0)
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.mixed, 0);
    assert_eq!(
        calls.access,
        vec![(
            client.tenant_id,
            client.id,
            "verified-jti".into(),
            Some(Utc.timestamp_opt(expiry, 0).unwrap()),
            None
        )]
    );
}
#[test]
fn unknown_or_foreign_access_uses_raw_refresh_lookup_without_a_jti() {
    let client = client(Uuid::now_v7());
    let owned = claims(&client, 1_800_000_000);
    let mut foreign_tenant = owned.clone();
    foreign_tenant.tenant_id = Uuid::now_v7().to_string();
    let mut foreign_client = owned;
    foreign_client.client_id = "other-client".into();
    for candidate in [None, Some(foreign_tenant), Some(foreign_client)] {
        let (service, calls) = fixture(candidate, false);
        assert_eq!(
            futures_executor::block_on(service.revoke_token(
                "https://issuer.example",
                "raw",
                &client
            )),
            Ok(3)
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.mixed, 1);
        assert!(calls.access.is_empty());
    }
}
#[test]
fn access_revocation_storage_failure_is_propagated() {
    let client = client(Uuid::now_v7());
    let (service, calls) = fixture(Some(claims(&client, 1_800_000_000)), true);
    assert_eq!(
        futures_executor::block_on(service.revoke_token("https://issuer.example", "jwt", &client)),
        Err(TokenPortError::Unavailable)
    );
    assert_eq!(calls.lock().unwrap().mixed, 0);
}
#[test]
fn expired_introspection_avoids_storage_but_live_token_fails_closed_on_storage_error() {
    let client = client(Uuid::now_v7());
    let expiry = 1_800_000_000;
    let (service, calls) = fixture(Some(claims(&client, expiry)), true);
    assert!(matches!(
        futures_executor::block_on(service.inspect_token(
            "https://issuer.example",
            "jwt",
            &client,
            Utc.timestamp_opt(expiry, 0).unwrap(),
        )),
        Ok(TokenInspection::Inactive)
    ));
    assert_eq!(calls.lock().unwrap().revocation_reads, 0);
    assert!(matches!(
        futures_executor::block_on(service.inspect_token(
            "https://issuer.example",
            "jwt",
            &client,
            Utc.timestamp_opt(expiry - 1, 0).unwrap(),
        )),
        Err(TokenPortError::Unavailable)
    ));
    assert_eq!(calls.lock().unwrap().revocation_reads, 1);
}
