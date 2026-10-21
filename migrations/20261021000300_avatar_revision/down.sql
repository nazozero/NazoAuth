DROP TRIGGER tr_avatar_revision ON users;
DROP FUNCTION nazo_advance_avatar_revision();
ALTER TABLE users DROP COLUMN avatar_revision;
