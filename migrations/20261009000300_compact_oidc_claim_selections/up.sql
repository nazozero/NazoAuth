-- New refresh contracts encode each claim request once (version 2).
-- Version 1 remains readable, with its original content key and original JSON.
-- Never rewrite active contracts or recompute referenced historical digests.
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
       AND (contract #>> '{authentication_context,version}')::INT IN (1, 2)
       AND jsonb_path_match(contract -> 'authentication_context' -> 'issuer', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND jsonb_path_match(contract -> 'authentication_context' -> 'audience', 'exists($ ? (@.type() == "string" && !(@ like_regex "^\\s*$")))')
       AND (contract #>> '{authentication_context,auth_time}')::BIGINT > 0
       AND jsonb_path_match(contract -> 'authentication_context' -> 'amr', '$.type() == "array" && $.size() > 0 && !exists($[*] ? (@.type() != "string" || @ like_regex "^\\s*$"))')
       AND COALESCE(contract #>> '{authentication_context,nonce}', '') = ''
       AND COALESCE(contract #>> '{authentication_context,id_token_sid}', '') = ''
       AND CASE (contract #>> '{authentication_context,version}')::INT
         WHEN 1 THEN
           jsonb_path_match(contract -> 'authentication_context' -> 'userinfo_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))')
           AND jsonb_path_match(contract -> 'authentication_context' -> 'id_token_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))')
         WHEN 2 THEN
           NOT ((contract -> 'authentication_context') ? 'userinfo_claims')
           AND NOT ((contract -> 'authentication_context') ? 'id_token_claims')
           AND jsonb_path_match(contract -> 'authentication_context' -> 'userinfo_claim_requests', '$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string" || @.name like_regex "^\\s*$" || (exists(@.essential) && @.essential.type() != "boolean") || (exists(@.values) && @.values.type() != "array")))')
           AND jsonb_path_match(contract -> 'authentication_context' -> 'id_token_claim_requests', '$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string" || @.name like_regex "^\\s*$" || (exists(@.essential) && @.essential.type() != "boolean") || (exists(@.values) && @.values.type() != "array")))')
         ELSE FALSE
       END,
       FALSE
    );
$$;
