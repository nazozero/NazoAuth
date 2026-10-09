-- An older binary cannot read compact contracts. Do not destroy authorization
-- evidence or expand/rekey active contracts to manufacture a downgrade.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_refresh_contracts
               WHERE contract #>> '{authentication_context,version}' = '2') THEN
        RAISE EXCEPTION 'compact refresh contracts still exist; downgrade is unsafe'
            USING ERRCODE = '55006';
    END IF;
END;
$$;
CREATE OR REPLACE FUNCTION nazo_refresh_contract_well_formed(contract JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
    -- COALESCE guards the CHECK semantics: jsonb_path_match on a missing key
    -- yields NULL, and a CHECK constraint accepts NULL. NULL must fail.
    SELECT COALESCE(
       contract IS NOT NULL
       AND jsonb_path_match(contract, '$.type() == "object"')
       AND jsonb_path_match(contract -> 'subject', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND jsonb_path_match(contract -> 'scopes', '$.type() == "array" && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND jsonb_path_match(contract -> 'audiences', '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND jsonb_path_match(contract -> 'authorization_details', '$.type() == "array"')
       AND jsonb_path_match(contract -> 'authentication_context', '$.type() == "object"')
       AND (contract #>> '{authentication_context,version}')::INT = 1
       AND jsonb_path_match(contract -> 'authentication_context' -> 'issuer', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND jsonb_path_match(contract -> 'authentication_context' -> 'audience', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND (contract #>> '{authentication_context,auth_time}')::BIGINT > 0
       AND jsonb_path_match(contract -> 'authentication_context' -> 'amr', '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND COALESCE(contract #>> '{authentication_context,nonce}', '') = ''
       AND COALESCE(contract #>> '{authentication_context,id_token_sid}', '') = ''
       AND jsonb_path_match(contract -> 'authentication_context' -> 'userinfo_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))')
       AND jsonb_path_match(contract -> 'authentication_context' -> 'id_token_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))'),
       FALSE
    );
$$;
