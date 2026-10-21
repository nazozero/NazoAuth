DROP TRIGGER tr_totp_write_key ON user_totp_credentials;
DROP FUNCTION nazo_check_totp_write_key();
DROP INDEX ix_totp_key_rewrap;
DROP TABLE mfa_totp_key_state;
