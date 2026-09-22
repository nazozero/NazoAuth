// Test-only Diesel schema for database fixtures. Production identity persistence is owned by
// `nazo-postgres`; these declarations let source-mounted tests insert and inspect database state
// without exposing postgres internals.

diesel::table! {
    oauth_clients (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        realm_id -> Uuid,
        organization_id -> Uuid,
        client_id -> Varchar,
        client_name -> Varchar,
        client_type -> Text,
        client_secret_hash -> Nullable<Varchar>,
        registration_access_token_blake3 -> Nullable<Varchar>,
        redirect_uris -> Jsonb,
        scopes -> Jsonb,
        grant_types -> Jsonb,
        token_endpoint_auth_method -> Varchar,
        require_dpop_bound_tokens -> Bool,
        require_mtls_bound_tokens -> Bool,
        tls_client_auth_subject_dn -> Nullable<Varchar>,
        tls_client_auth_cert_sha256 -> Nullable<Varchar>,
        tls_client_auth_san_dns -> Jsonb,
        tls_client_auth_san_uri -> Jsonb,
        tls_client_auth_san_ip -> Jsonb,
        tls_client_auth_san_email -> Jsonb,
        allow_client_assertion_audience_array -> Bool,
        allow_client_assertion_endpoint_audience -> Bool,
        require_par_request_object -> Bool,
        is_active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        allowed_audiences -> Jsonb,
        security_policy -> Jsonb,
        jwks -> Nullable<Jsonb>,
        introspection_encrypted_response_alg -> Nullable<Varchar>,
        introspection_encrypted_response_enc -> Nullable<Varchar>,
        userinfo_signed_response_alg -> Nullable<Varchar>,
        userinfo_encrypted_response_alg -> Nullable<Varchar>,
        userinfo_encrypted_response_enc -> Nullable<Varchar>,
        authorization_signed_response_alg -> Nullable<Varchar>,
        authorization_encrypted_response_alg -> Nullable<Varchar>,
        authorization_encrypted_response_enc -> Nullable<Varchar>,
        post_logout_redirect_uris -> Jsonb,
        backchannel_logout_uri -> Nullable<Varchar>,
        backchannel_logout_session_required -> Bool,
        frontchannel_logout_uri -> Nullable<Varchar>,
        frontchannel_logout_session_required -> Bool,
        subject_type -> Text,
        sector_identifier_uri -> Nullable<Text>,
        sector_identifier_host -> Nullable<Text>,
    }
}

diesel::table! {
    external_identity_links (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        provider_type -> Varchar,
        provider_id -> Varchar,
        subject -> Varchar,
        email -> Varchar,
        claims -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        last_login_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_passkey_credentials (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        credential_id -> Varchar,
        credential -> Jsonb,
        label -> Varchar,
        sign_count -> Int8,
        last_used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_totp_credentials (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        secret_ciphertext -> Binary,
        secret_key_id -> Varchar,
        label -> Varchar,
        confirmed_at -> Nullable<Timestamptz>,
        last_used_step -> Nullable<Int8>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa_backup_codes (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        code_hash -> Varchar,
        used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_mfa_remembered_devices (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        user_agent_hash -> Nullable<Varchar>,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        tenant_id -> Uuid,
        realm_id -> Uuid,
        organization_id -> Uuid,
        username -> Varchar,
        email -> Varchar,
        password_hash -> Varchar,
        is_active -> Bool,
        mfa_enabled -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        email_verified -> Bool,
        display_name -> Nullable<Varchar>,
        avatar_url -> Nullable<Varchar>,
        given_name -> Nullable<Varchar>,
        family_name -> Nullable<Varchar>,
        middle_name -> Nullable<Varchar>,
        nickname -> Nullable<Varchar>,
        profile_url -> Nullable<Varchar>,
        website_url -> Nullable<Varchar>,
        gender -> Nullable<Varchar>,
        birthdate -> Nullable<Varchar>,
        zoneinfo -> Nullable<Varchar>,
        locale -> Nullable<Varchar>,
        role -> Text,
        admin_level -> Int4,
        address_formatted -> Nullable<Varchar>,
        address_street_address -> Nullable<Varchar>,
        address_locality -> Nullable<Varchar>,
        address_region -> Nullable<Varchar>,
        address_postal_code -> Nullable<Varchar>,
        address_country -> Nullable<Varchar>,
        phone_number -> Nullable<Varchar>,
        phone_number_verified -> Bool,
    }
}

diesel::table! {
    oauth_refresh_contracts (tenant_id, contract_blake3) {
        tenant_id -> Uuid,
        contract_blake3 -> Binary,
        contract -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_refresh_families (tenant_id, token_family_id) {
        tenant_id -> Uuid,
        token_family_id -> Uuid,
        client_id -> Uuid,
        user_id -> Nullable<Uuid>,
        contract_blake3 -> Binary,
        current_member_id -> Uuid,
        current_token_blake3 -> Binary,
        current_audience -> Jsonb,
        current_issued_at -> Timestamptz,
        current_expires_at -> Timestamptz,
        current_id_token_sid -> Nullable<Varchar>,
        dpop_jkt -> Nullable<Varchar>,
        mtls_x5t_s256 -> Nullable<Varchar>,
        client_attestation_jkt -> Nullable<Varchar>,
        created_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        reuse_detected_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    oauth_refresh_spent_tokens (tenant_id, refresh_token_blake3) {
        tenant_id -> Uuid,
        refresh_token_blake3 -> Binary,
        token_family_id -> Uuid,
        member_id -> Uuid,
        successor_member_id -> Uuid,
        spent_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    access_token_revocations (id) {
        id -> Uuid,
        access_token_jti_blake3 -> Varchar,
        client_id -> Uuid,
        tenant_id -> Uuid,
        revoked_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    oauth_token_issuances (issuance_id) {
        issuance_id -> Uuid,
        tenant_id -> Uuid,
        client_id -> Uuid,
        user_id -> Nullable<Uuid>,
        single_use_key_blake3 -> Nullable<Binary>,
        access_token_jti -> Varchar,
        access_token_expires_at -> Timestamptz,
        retain_until -> Timestamptz,
    }
}
