diesel::table! {
    users (id) {
        id -> Uuid, tenant_id -> Uuid, realm_id -> Uuid, organization_id -> Uuid,
        username -> Varchar, email -> Varchar, password_hash -> Varchar, is_active -> Bool,
        mfa_enabled -> Bool, created_at -> Timestamptz, updated_at -> Timestamptz,
        email_verified -> Bool, display_name -> Nullable<Varchar>, avatar_url -> Nullable<Varchar>,
        given_name -> Nullable<Varchar>, family_name -> Nullable<Varchar>, middle_name -> Nullable<Varchar>,
        nickname -> Nullable<Varchar>, profile_url -> Nullable<Varchar>, website_url -> Nullable<Varchar>,
        gender -> Nullable<Varchar>, birthdate -> Nullable<Varchar>, zoneinfo -> Nullable<Varchar>,
        locale -> Nullable<Varchar>, role -> Text, admin_level -> Int4,
        address_formatted -> Nullable<Varchar>, address_street_address -> Nullable<Varchar>,
        address_locality -> Nullable<Varchar>, address_region -> Nullable<Varchar>,
        address_postal_code -> Nullable<Varchar>, address_country -> Nullable<Varchar>,
        phone_number -> Nullable<Varchar>, phone_number_verified -> Bool,
    }
}

diesel::table! {
    user_totp_credentials (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, secret_base32 -> Varchar,
        label -> Varchar, confirmed_at -> Nullable<Timestamptz>, last_used_step -> Nullable<Int8>,
        created_at -> Timestamptz, updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa_backup_codes (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, code_hash -> Varchar,
        used_at -> Nullable<Timestamptz>, created_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa_remembered_devices (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, token_hash -> Varchar,
        user_agent_hash -> Nullable<Varchar>, created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>, expires_at -> Timestamptz,
    }
}

diesel::table! {
    user_passkey_credentials (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, credential_id -> Varchar,
        credential -> Jsonb, label -> Varchar, sign_count -> Int8,
        last_used_at -> Nullable<Timestamptz>, created_at -> Timestamptz, updated_at -> Timestamptz,
    }
}

diesel::table! {
    external_identity_links (id) {
        id -> Uuid, tenant_id -> Uuid, user_id -> Uuid, provider_type -> Varchar,
        provider_id -> Varchar, subject -> Varchar, email -> Varchar, claims -> Jsonb,
        created_at -> Timestamptz, updated_at -> Timestamptz, last_login_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    oauth_tokens (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Nullable<Uuid>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_client_grants (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        client_id -> Uuid,
        first_authorized_at -> Timestamptz,
        last_authorized_at -> Timestamptz,
        last_scopes -> Jsonb,
        last_resource_indicators -> Jsonb,
        last_authorization_details -> Jsonb,
        authorization_count -> Int4,
    }
}

diesel::table! {
    client_access_requests (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        site_name -> Varchar,
        site_url -> Varchar,
        request_description -> Varchar,
        status -> SmallInt,
        admin_note -> Nullable<Varchar>,
        resolved_by_user_id -> Nullable<Uuid>,
        approved_client_id -> Nullable<Uuid>,
        resolved_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_clients (id) {
        id -> Uuid,
        client_id -> Varchar,
        client_name -> Varchar,
    }
}

diesel::joinable!(client_access_requests -> users (user_id));
diesel::joinable!(user_client_grants -> oauth_clients (client_id));
diesel::joinable!(user_client_grants -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    users,
    user_totp_credentials,
    user_mfa_backup_codes,
    user_mfa_remembered_devices,
    user_passkey_credentials,
    external_identity_links,
    oauth_tokens,
    user_client_grants,
    client_access_requests,
    oauth_clients
);
