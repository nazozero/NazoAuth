-- A backup verifier is a consumable credential, not a second audit history.
-- Missing candidate IDs already reject reuse. Retain live IDs, hashes and
-- tenant/user ownership; independent security events retain the outcome.
DELETE FROM user_mfa_backup_codes WHERE used_at IS NOT NULL;
DROP INDEX ix_user_mfa_backup_codes_tenant_user_active;
ALTER TABLE user_mfa_backup_codes DROP COLUMN used_at, DROP COLUMN created_at;
CREATE INDEX ix_user_mfa_backup_codes_tenant_user_active
    ON user_mfa_backup_codes (tenant_id, user_id);

-- Enrollment labels are rendered directly into the otpauth response. The
-- stored label and generic timestamps have no reader; confirmed_at and
-- last_used_step retain the actual confirmation and replay facts.
ALTER TABLE user_totp_credentials
    DROP COLUMN label, DROP COLUMN created_at, DROP COLUMN updated_at;
