diesel::table! {
    access_token_revocations (id) {
        id -> Uuid,
        access_token_jti_blake3 -> Varchar,
        client_id -> Uuid,
        revoked_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    client_access_requests (id) {
        id -> Uuid,
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
        client_type -> Text,
        client_secret_argon2_hash -> Nullable<Varchar>,
        redirect_uris -> Jsonb,
        scopes -> Jsonb,
        grant_types -> Jsonb,
        token_endpoint_auth_method -> Varchar,
        require_dpop_bound_tokens -> Bool,
        allow_client_assertion_audience_array -> Bool,
        require_par_request_object -> Bool,
        is_active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        allowed_audiences -> Jsonb,
        jwks -> Nullable<Jsonb>,
    }
}

diesel::table! {
    oauth_tokens (id) {
        id -> Uuid,
        refresh_token_blake3 -> Varchar,
        token_family_id -> Uuid,
        rotated_from_id -> Nullable<Uuid>,
        client_id -> Uuid,
        user_id -> Nullable<Uuid>,
        scopes -> Jsonb,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        reuse_detected_at -> Nullable<Timestamptz>,
        subject -> Varchar,
        dpop_jkt -> Nullable<Varchar>,
    }
}

diesel::table! {
    user_client_grants (id) {
        id -> Uuid,
        user_id -> Uuid,
        client_id -> Uuid,
        first_authorized_at -> Timestamptz,
        last_authorized_at -> Timestamptz,
        last_scopes -> Jsonb,
        authorization_count -> Int4,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
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

diesel::joinable!(access_token_revocations -> oauth_clients (client_id));
diesel::joinable!(client_access_requests -> oauth_clients (approved_client_id));
diesel::joinable!(oauth_tokens -> oauth_clients (client_id));
diesel::joinable!(oauth_tokens -> users (user_id));
diesel::joinable!(user_client_grants -> oauth_clients (client_id));
diesel::joinable!(user_client_grants -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    access_token_revocations,
    client_access_requests,
    oauth_clients,
    oauth_tokens,
    user_client_grants,
    users,
);
