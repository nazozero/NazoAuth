-- Only unconsumed credentials remain. Do not recreate deleted used codes.
-- The recreated timestamp is adapter metadata, not original creation history.
DROP INDEX ix_user_mfa_backup_codes_tenant_user_active;
ALTER TABLE user_mfa_backup_codes
    ADD COLUMN used_at TIMESTAMPTZ,
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX ix_user_mfa_backup_codes_tenant_user_active
    ON user_mfa_backup_codes (tenant_id, user_id) WHERE used_at IS NULL;

-- Recreate only unused adapter metadata; never replace a secret, generation,
-- confirmation time or replay step during rollback.
ALTER TABLE user_totp_credentials
    ADD COLUMN label VARCHAR(200) NOT NULL DEFAULT 'Authenticator',
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD CONSTRAINT ck_user_totp_credentials_label_non_empty CHECK (length(trim(label)) > 0);
