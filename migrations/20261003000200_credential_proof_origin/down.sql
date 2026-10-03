DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM openid4vci_access_grants WHERE proof_origin = 'anonymous_pre_authorized') THEN
        RAISE EXCEPTION 'cannot discard anonymous credential proof provenance while grants remain';
    END IF;
END $$;
ALTER TABLE openid4vci_access_grants
    DROP CONSTRAINT ck_openid4vci_proof_origin,
    DROP COLUMN proof_origin;
