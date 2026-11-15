CREATE OR REPLACE FUNCTION public.nazo_client_security_policy_is_current(policy jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $$
    SELECT jsonb_typeof(policy) = 'object'
       AND policy ?& ARRAY[
            'version', 'assurance', 'require_signed_authorization_request',
            'require_signed_authorization_response',
            'require_signed_introspection_response', 'session_management',
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce'
       ]
       AND policy - ARRAY[
            'version', 'assurance', 'require_pushed_authorization_requests',
            'require_signed_authorization_request',
            'require_signed_authorization_response',
            'require_signed_introspection_response', 'session_management',
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce', 'authorization_code_profile'
       ] = '{}'::jsonb
       AND (
            NOT policy ? 'authorization_code_profile'
            OR (
                jsonb_typeof(policy -> 'authorization_code_profile') = 'string'
                AND policy ->> 'authorization_code_profile' IN ('oauth20', 'oauth21')
                AND (
                    policy ->> 'authorization_code_profile' = 'oauth20'
                    OR (policy ->> 'assurance' = 'baseline'
                        AND policy ->> 'allow_confidential_oidc_without_pkce' = 'false')
                )
            )
       )
       AND jsonb_typeof(policy -> 'version') = 'number'
       AND policy ->> 'version' = '1'
       AND jsonb_typeof(policy -> 'assurance') = 'string'
       AND policy ->> 'assurance' IN ('baseline', 'fapi2')
       AND (
            NOT policy ? 'require_pushed_authorization_requests'
            OR jsonb_typeof(policy -> 'require_pushed_authorization_requests') = 'boolean'
       )
       AND jsonb_typeof(policy -> 'require_signed_authorization_request') = 'boolean'
       AND jsonb_typeof(policy -> 'require_signed_authorization_response') = 'boolean'
       AND jsonb_typeof(policy -> 'require_signed_introspection_response') = 'boolean'
       AND jsonb_typeof(policy -> 'session_management') = 'boolean'
       AND jsonb_typeof(policy -> 'allow_cross_device_flows') = 'boolean'
       AND jsonb_typeof(policy -> 'allow_confidential_oidc_without_pkce') = 'boolean';
$$;
