DROP INDEX IF EXISTS ix_user_mfa_remembered_devices_tenant_user_active;
DROP INDEX IF EXISTS ux_user_mfa_remembered_devices_tenant_token;
DROP TABLE IF EXISTS user_mfa_remembered_devices;

DROP INDEX IF EXISTS ix_user_mfa_backup_codes_tenant_user_active;
DROP TABLE IF EXISTS user_mfa_backup_codes;

DROP INDEX IF EXISTS ix_user_totp_credentials_user;
DROP INDEX IF EXISTS ux_user_totp_credentials_tenant_user;
DROP TABLE IF EXISTS user_totp_credentials;
