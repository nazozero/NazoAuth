CREATE TABLE mfa_totp_key_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    current_key_id text NOT NULL CHECK (length(current_key_id) BETWEEN 1 AND 128),
    previous_key_id text
);
CREATE INDEX ix_totp_key_rewrap ON user_totp_credentials (secret_key_id, id);

-- The same row lock orders activation, enrollment and bounded rewrapping.
-- Enforce the fence here so even an older binary cannot reintroduce retired keys.
CREATE FUNCTION nazo_check_totp_write_key() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE active_key text;
BEGIN
    INSERT INTO mfa_totp_key_state (current_key_id) VALUES (NEW.secret_key_id)
    ON CONFLICT DO NOTHING;
    SELECT current_key_id INTO STRICT active_key FROM mfa_totp_key_state
    WHERE singleton FOR SHARE;
    IF active_key <> NEW.secret_key_id THEN
        RAISE EXCEPTION 'TOTP encryption writer uses an inactive key id' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER tr_totp_write_key BEFORE INSERT OR UPDATE OF secret_ciphertext, secret_key_id
ON user_totp_credentials FOR EACH ROW EXECUTE FUNCTION nazo_check_totp_write_key();
