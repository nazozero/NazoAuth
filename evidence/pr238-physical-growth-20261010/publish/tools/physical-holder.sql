SELECT json_build_object(
 'ts', extract(epoch from clock_timestamp()),
 'rows', count(*),
 'holder_bytes', sum(pg_column_size(authorization_code_holder)),
 'sparse_holder_bytes', sum(pg_column_size(jsonb_strip_nulls(authorization_code_holder))),
 'null_member_count', sum((SELECT count(*) FROM jsonb_each(authorization_code_holder) e WHERE e.value='null'::jsonb)),
 'populated_fields', (SELECT json_object_agg(k,n) FROM (
  SELECT key k,count(*) n FROM oauth_token_issuances t CROSS JOIN LATERAL jsonb_each(t.authorization_code_holder) e
  WHERE e.value<>'null'::jsonb GROUP BY key) f)
 ) FROM oauth_token_issuances WHERE authorization_code_holder IS NOT NULL;
