BEGIN;
CREATE TEMP TABLE receipt_key_probe (tenant_id uuid,client_id uuid,single_use_key_blake3 bytea);
INSERT INTO receipt_key_probe
SELECT '00000000-0000-0000-0000-000000000001'::uuid,
       '00000000-0000-0000-0000-000000000002'::uuid,
       sha256(n::text::bytea) FROM generate_series(1,300000) n;
CREATE UNIQUE INDEX receipt_key_with_tenant ON receipt_key_probe(tenant_id,client_id,single_use_key_blake3);
CREATE UNIQUE INDEX receipt_key_without_redundant_tenant ON receipt_key_probe(client_id,single_use_key_blake3);
SELECT json_build_object('rows',300000,
 'with_tenant_bytes',pg_relation_size('receipt_key_with_tenant'),
 'without_redundant_tenant_bytes',pg_relation_size('receipt_key_without_redundant_tenant'));
ROLLBACK;
