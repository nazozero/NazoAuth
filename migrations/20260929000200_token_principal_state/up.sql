-- Token invalidation belongs to its principal, not to every issued JWT.
-- Existing tokens/issuance rows remain valid under their original contract.
ALTER TABLE oauth_clients ADD COLUMN access_token_epoch BIGINT NOT NULL DEFAULT 0
    CHECK (access_token_epoch >= 0);
ALTER TABLE users ADD COLUMN access_token_epoch BIGINT NOT NULL DEFAULT 0
    CHECK (access_token_epoch >= 0);

-- Cover every principal deactivation writer, including SCIM and operator
-- transactions. Reactivation never restores the old epoch. The row update
-- serializes with issuance's existing FOR SHARE principal locks.
CREATE FUNCTION nazo_advance_access_token_epoch() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.is_active AND NOT NEW.is_active THEN
        NEW.access_token_epoch := OLD.access_token_epoch + 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_client_access_token_epoch
    BEFORE UPDATE OF is_active ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION nazo_advance_access_token_epoch();
CREATE TRIGGER user_access_token_epoch
    BEFORE UPDATE OF is_active ON users
    FOR EACH ROW EXECUTE FUNCTION nazo_advance_access_token_epoch();

-- Stable reverse lookup for non-public subjects. Repeated token issuance
-- reuses one binding; public subjects need no binding at all. No expiry
-- sweep: the identity relation ends with its owning user.
CREATE TABLE oauth_subject_bindings (
    tenant_id UUID NOT NULL,
    subject VARCHAR(255) NOT NULL CHECK (subject <> ''),
    user_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, subject),
    FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX oauth_subject_bindings_owner_idx ON oauth_subject_bindings (user_id, tenant_id);
