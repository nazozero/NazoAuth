use super::prelude::*;

pub(crate) const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);
pub(crate) const DEFAULT_REALM_ID: Uuid = Uuid::from_u128(2);
pub(crate) const DEFAULT_ORGANIZATION_ID: Uuid = Uuid::from_u128(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TenantContext {
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
}

impl Default for TenantContext {
    fn default() -> Self {
        Self {
            tenant_id: DEFAULT_TENANT_ID,
            realm_id: DEFAULT_REALM_ID,
            organization_id: DEFAULT_ORGANIZATION_ID,
        }
    }
}

impl TenantContext {
    pub(crate) fn includes_user(&self, user: &UserRow) -> bool {
        user.tenant_id == self.tenant_id
            && user.realm_id == self.realm_id
            && user.organization_id == self.organization_id
    }

    pub(crate) fn includes_client(&self, client: &ClientRow) -> bool {
        client.tenant_id == self.tenant_id
            && client.realm_id == self.realm_id
            && client.organization_id == self.organization_id
    }

    pub(crate) fn same_tenant(&self, tenant_id: Uuid) -> bool {
        tenant_id == self.tenant_id
    }
}

pub(crate) fn default_tenant_context() -> TenantContext {
    TenantContext::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_in_context(context: TenantContext) -> UserRow {
        UserRow {
            id: Uuid::now_v7(),
            tenant_id: context.tenant_id,
            realm_id: context.realm_id,
            organization_id: context.organization_id,
            username: "user".to_owned(),
            email: "user@example.com".to_owned(),
            display_name: None,
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
            role: "user".to_owned(),
            admin_level: 0,
            address_formatted: None,
            address_street_address: None,
            address_locality: None,
            address_region: None,
            address_postal_code: None,
            address_country: None,
            phone_number: None,
            phone_number_verified: false,
            email_verified: true,
            password_hash: "hash".to_owned(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn client_in_context(context: TenantContext) -> ClientRow {
        ClientRow {
            id: Uuid::now_v7(),
            tenant_id: context.tenant_id,
            realm_id: context.realm_id,
            organization_id: context.organization_id,
            client_id: "client-1".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "public".to_owned(),
            client_secret_argon2_hash: None,
            redirect_uris: json!(["https://client.example/callback"]),
            scopes: json!(["openid"]),
            allowed_audiences: json!(["resource://default"]),
            grant_types: json!(["authorization_code"]),
            token_endpoint_auth_method: "none".to_owned(),
            require_dpop_bound_tokens: false,
            require_mtls_bound_tokens: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: json!([]),
            tls_client_auth_san_uri: json!([]),
            tls_client_auth_san_ip: json!([]),
            tls_client_auth_san_email: json!([]),
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            is_active: true,
            jwks: None,
            post_logout_redirect_uris: json!([]),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
        }
    }

    #[test]
    fn tenant_context_rejects_cross_tenant_entities() {
        let context = default_tenant_context();
        let other = TenantContext {
            tenant_id: Uuid::now_v7(),
            ..context
        };

        assert!(context.includes_user(&user_in_context(context)));
        assert!(!context.includes_user(&user_in_context(other)));
        assert!(context.includes_client(&client_in_context(context)));
        assert!(!context.includes_client(&client_in_context(other)));
        assert!(context.same_tenant(DEFAULT_TENANT_ID));
        assert!(!context.same_tenant(other.tenant_id));
    }
}
