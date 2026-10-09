-- The old request digest cannot be inverted to recover a code identity.
-- Preserve historical receipts, but require the new contract on every new
-- single-use insert. Old binaries therefore fail closed during mixed rollout.
ALTER TABLE oauth_token_issuances
    ADD COLUMN receipt_contract_version SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN authorization_code_holder JSONB,
    ADD CONSTRAINT oauth_token_issuances_receipt_contract_check
        CHECK (single_use_key_blake3 IS NULL OR receipt_contract_version = 2) NOT VALID;

COMMENT ON COLUMN oauth_token_issuances.authorization_code_holder IS
    'Versioned original proof requirements for code replay revocation; independent of the stable one-use code identity. Legacy receipts remain NULL.';
