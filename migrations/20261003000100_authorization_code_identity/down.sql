-- Quiesce all issuance and change the transient-state epoch before rollback.
-- Never remove a live durable v2 fence to admit a legacy binary.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_token_issuances WHERE receipt_contract_version = 2) THEN
        RAISE EXCEPTION 'cannot roll back authorization code identity while v2 receipts exist';
    END IF;
END;
$$;

ALTER TABLE oauth_token_issuances
    DROP CONSTRAINT oauth_token_issuances_receipt_contract_check,
    DROP COLUMN authorization_code_holder,
    DROP COLUMN receipt_contract_version;
