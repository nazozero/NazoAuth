-- Never silently change the wire contract of an active OAuth 2.1 registration.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.oauth_clients
               WHERE security_policy ->> 'authorization_code_profile' = 'oauth21') THEN
        RAISE EXCEPTION 'Reset OAuth 2.1 client profiles before rolling back this migration';
    END IF;
END;
$$;
UPDATE public.oauth_clients
SET security_policy = security_policy - 'authorization_code_profile'
WHERE security_policy ? 'authorization_code_profile';

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
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce'
       ] = '{}'::jsonb
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
