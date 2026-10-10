-- Regenerate only the unused adapter UUID; preserve every revoked token,
-- its tenant/client binding, first revocation time and maximum deadline.
ALTER TABLE access_token_revocations DROP CONSTRAINT access_token_revocations_pkey;
CREATE UNIQUE INDEX ux_access_token_revocations_tenant_jti_blake3
    ON access_token_revocations(tenant_id, access_token_jti_blake3);
ALTER TABLE access_token_revocations ADD COLUMN id UUID NOT NULL DEFAULT uuidv7();
ALTER TABLE access_token_revocations ADD CONSTRAINT access_token_revocations_pkey PRIMARY KEY(id);
