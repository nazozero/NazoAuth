use crate::domain::rows::ClientRow;

use chrono::Utc;

use nazo_identity::{PublicAccount, TenantContext};

use serde_json::json;
use uuid::Uuid;

fn includes_user(context: TenantContext, user: &PublicAccount) -> bool {
    context.matches_raw(user.tenant_id(), user.realm_id(), user.organization_id())
}

fn includes_client(context: TenantContext, client: &ClientRow) -> bool {
    context.matches_raw(client.tenant_id, client.realm_id, client.organization_id)
}

use super::*;

fn user_in_context(context: TenantContext) -> PublicAccount {
    PublicAccount {
        principal: nazo_identity::Principal {
            user_id: nazo_identity::UserId::new(Uuid::now_v7()).unwrap(),
            tenant: context,
            role: nazo_identity::UserRole::User,
            active: true,
        },
        account: nazo_identity::AccountIdentity {
            username: "user".to_owned(),
            email: "user@example.com".to_owned(),
            email_verified: true,
            mfa_enabled: false,
        },
        profile: nazo_identity::UserProfile::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn client_in_context(context: TenantContext) -> ClientRow {
    crate::domain::rows::ClientRow {
        id: Uuid::now_v7(),
        tenant_id: context.tenant_id.as_uuid(),
        realm_id: context.realm_id.as_uuid(),
        organization_id: context.organization_id.as_uuid(),
        registration: nazo_auth::ValidatedClientRegistration {
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "public".to_owned(),
            redirect_uris: serde_json::from_value(json!(["https://client.example/callback"]))
                .expect("redirect_uris fixture"),
            scopes: serde_json::from_value(json!(["openid"])).expect("scopes fixture"),
            allowed_audiences: serde_json::from_value(json!(["resource://default"]))
                .expect("audiences fixture"),
            grant_types: serde_json::from_value(json!(["authorization_code"]))
                .expect("grants fixture"),
            token_endpoint_auth_method: "none".to_owned(),
            require_dpop_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: serde_json::from_value(json!([])).expect("dns fixture"),
            tls_client_auth_san_uri: serde_json::from_value(json!([])).expect("uri fixture"),
            tls_client_auth_san_ip: serde_json::from_value(json!([])).expect("ip fixture"),
            tls_client_auth_san_email: serde_json::from_value(json!([])).expect("email fixture"),
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
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
            post_logout_redirect_uris: serde_json::from_value(json!([]))
                .expect("post logout fixture"),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            security_policy: nazo_auth::ClientSecurityPolicy::default(),
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

#[test]
fn tenant_context_rejects_cross_tenant_entities() {
    let context = TenantContext::default_system();
    let other = TenantContext {
        tenant_id: nazo_identity::TenantId::new(Uuid::now_v7()).unwrap(),
        ..context
    };

    assert!(includes_user(context, &user_in_context(context)));
    assert!(!includes_user(context, &user_in_context(other)));
    assert!(includes_client(context, &client_in_context(context)));
    assert!(!includes_client(context, &client_in_context(other)));
    assert!(context.same_tenant(nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap()));
    assert!(!context.same_tenant(other.tenant_id));
}
