ALTER TABLE users ADD COLUMN avatar_revision bigint NOT NULL DEFAULT 0 CHECK (avatar_revision >= 0);
CREATE FUNCTION nazo_advance_avatar_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.avatar_url IS DISTINCT FROM OLD.avatar_url THEN
        NEW.avatar_revision := OLD.avatar_revision + 1;
    ELSE
        NEW.avatar_revision := OLD.avatar_revision;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER tr_avatar_revision BEFORE UPDATE OF avatar_url, avatar_revision ON users
FOR EACH ROW EXECUTE FUNCTION nazo_advance_avatar_revision();
