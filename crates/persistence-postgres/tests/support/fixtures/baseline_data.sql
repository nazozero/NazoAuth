-- Populated v0.3.2 state used by the baseline adoption test.
DO $$
DECLARE
    tenant UUID := '00000000-0000-0000-0000-000000000001';
    actor UUID;
    client UUID;
    family UUID := uuidv7();
    member UUID := uuidv7();
    digest BYTEA := decode(repeat('01', 32), 'hex');
BEGIN
    INSERT INTO users (username, email, password_hash, mfa_enabled)
    VALUES ('baseline-user', 'baseline@example.test', 'retained-password-hash', TRUE)
    RETURNING id INTO actor;
    INSERT INTO oauth_clients (client_id, client_name, client_type, redirect_uris, scopes,
        grant_types, token_endpoint_auth_method, security_policy)
    VALUES ('baseline-client', 'Baseline client', 'confidential', '["https://client.example/cb"]',
        '["openid","offline_access"]', '["authorization_code","refresh_token"]', 'client_secret_basic',
        '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}')
    RETURNING id INTO client;
    INSERT INTO oauth_subject_bindings (tenant_id, subject, user_id) VALUES (tenant, 'baseline-subject', actor);
    INSERT INTO user_client_grants (user_id, client_id, first_authorized_at, last_authorized_at, last_scopes)
    VALUES (actor, client, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '["openid"]');
    INSERT INTO user_totp_credentials (tenant_id, user_id, confirmed_at, last_used_step, secret_ciphertext, secret_key_id)
    VALUES (tenant, actor, CURRENT_TIMESTAMP, 42, decode('01' || repeat('ab', 44), 'hex'), 'fixture-root');
    INSERT INTO user_mfa_backup_codes (tenant_id, user_id, code_hash)
    VALUES (tenant, actor, 'retained-backup-verifier');
    INSERT INTO tenant_signing_keysets (tenant_id, revision, public_metadata, encrypted_private_material, wrapping_key_id)
    VALUES (tenant, 7, '{"keys":[]}', decode('010203', 'hex'), 'fixture-root');
    INSERT INTO oauth_refresh_contracts (tenant_id, contract_blake3, contract)
    VALUES (tenant, digest, jsonb_build_object(
        'subject', actor::TEXT, 'scopes', '["openid","offline_access"]'::JSONB,
        'audiences', '["resource://baseline"]'::JSONB, 'authorization_details', '[]'::JSONB,
        'authentication_context', jsonb_build_object('version', 1, 'issuer', 'https://issuer.example',
            'audience', 'baseline-client', 'auth_time', 1700000000, 'amr', '["pwd","otp"]'::JSONB,
            'userinfo_claims', '[]'::JSONB, 'id_token_claims', '[]'::JSONB)));
    INSERT INTO oauth_refresh_families (tenant_id, token_family_id, client_id, user_id,
        contract_blake3, current_member_id, current_token_blake3, current_audience,
        current_issued_at, current_expires_at)
    VALUES (tenant, family, client, actor, digest, member, digest, '["resource://baseline"]',
        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 day');
    INSERT INTO oauth_refresh_spent_tokens (tenant_id, refresh_token_blake3, token_family_id,
        member_id, successor_member_id, spent_at, expires_at)
    VALUES (tenant, decode(repeat('02', 32), 'hex'), family, uuidv7(), member,
        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 day');
    INSERT INTO oauth_token_issuances (issuance_id, tenant_id, client_id, user_id, single_use_key_blake3,
        access_token_jti, access_token_expires_at, retain_until, refresh_token_family_id, receipt_contract_version)
    VALUES (uuidv7(), tenant, client, actor, digest, 'baseline-jti', CURRENT_TIMESTAMP + INTERVAL '1 hour',
        CURRENT_TIMESTAMP + INTERVAL '2 hours', family, 2);
    INSERT INTO controller_registry_slots (deployment_id, controller_id, label, kid, public_key,
        slot_index, issued_at, expires_at, status)
    VALUES ('baseline-deployment', uuidv7()::TEXT, 'primary', repeat('a', 43), digest, 0,
        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '30 days', 'active');
    PERFORM public.nazo_persist_security_audit_event(uuidv7(), 'baseline_fixture', 'security',
        '{"preserve":"pending audit evidence"}', CURRENT_TIMESTAMP);
END $$;
