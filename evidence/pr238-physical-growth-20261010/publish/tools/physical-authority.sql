SELECT json_build_object(
 'constraints',(SELECT json_agg(t) FROM (SELECT conrelid::regclass::text AS relation,conname,convalidated,condeferrable,pg_get_constraintdef(oid) AS definition
 FROM pg_constraint WHERE (conrelid='oauth_clients'::regclass AND contype='p') OR
 (conrelid='oauth_token_issuances'::regclass AND conname='fk_oauth_token_issuances_client_tenant')) t),
 'index',pg_get_indexdef('oauth_token_issuances_single_use_key_idx'::regclass)
);
