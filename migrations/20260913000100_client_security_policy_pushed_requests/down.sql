-- Fail closed: a client whose policy requires pushed authorization requests
-- must not be silently relaxed to the old validator. Refuse the downgrade
-- before touching any data.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM oauth_clients
        WHERE security_policy -> 'require_pushed_authorization_requests' = 'true'::jsonb
    ) THEN
        RAISE EXCEPTION
            'downgrade refused: client security policy requires pushed authorization requests';
    END IF;
END
$$;

-- No `true` remains at this point, and the relaxed validator only admits a
-- boolean, so every surviving key is `false`; stripping it restores the
-- pre-migration policy shape.
UPDATE oauth_clients
SET security_policy = security_policy - 'require_pushed_authorization_requests'
WHERE security_policy ? 'require_pushed_authorization_requests';

CREATE OR REPLACE FUNCTION nazo_client_security_policy_is_current(policy JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT jsonb_typeof(policy) = 'object'
       AND policy ?& ARRAY[
            'version', 'assurance', 'require_signed_authorization_request',
            'require_signed_authorization_response',
            'require_signed_introspection_response', 'session_management',
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce'
       ]
       AND policy - ARRAY[
            'version', 'assurance', 'require_signed_authorization_request',
            'require_signed_authorization_response',
            'require_signed_introspection_response', 'session_management',
            'allow_cross_device_flows', 'allow_confidential_oidc_without_pkce'
       ] = '{}'::jsonb
       AND jsonb_typeof(policy -> 'version') = 'number'
       AND policy ->> 'version' = '1'
       AND jsonb_typeof(policy -> 'assurance') = 'string'
       AND policy ->> 'assurance' IN ('baseline', 'fapi2')
       AND jsonb_typeof(policy -> 'require_signed_authorization_request') = 'boolean'
       AND jsonb_typeof(policy -> 'require_signed_authorization_response') = 'boolean'
       AND jsonb_typeof(policy -> 'require_signed_introspection_response') = 'boolean'
       AND jsonb_typeof(policy -> 'session_management') = 'boolean'
       AND jsonb_typeof(policy -> 'allow_cross_device_flows') = 'boolean'
       AND jsonb_typeof(policy -> 'allow_confidential_oidc_without_pkce') = 'boolean';
$$;
