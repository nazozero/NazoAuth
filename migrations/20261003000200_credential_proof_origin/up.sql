ALTER TABLE openid4vci_access_grants
    ADD COLUMN proof_origin TEXT NOT NULL DEFAULT 'legacy_unspecified',
    ADD CONSTRAINT ck_openid4vci_proof_origin
        CHECK (proof_origin IN ('registered_client', 'anonymous_pre_authorized', 'legacy_unspecified'));
