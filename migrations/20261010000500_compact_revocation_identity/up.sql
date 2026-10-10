-- Tenant/JTI is already the lookup, conflict, retention and reclamation identity.
-- No production reader or foreign key refers to the independent UUID.
ALTER TABLE access_token_revocations DROP COLUMN id;
ALTER TABLE access_token_revocations ADD CONSTRAINT access_token_revocations_pkey
    PRIMARY KEY USING INDEX ux_access_token_revocations_tenant_jti_blake3;
