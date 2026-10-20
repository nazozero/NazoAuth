ALTER TABLE users
    ADD COLUMN deleted_at timestamptz,
    ADD CONSTRAINT users_deleted_inactive CHECK (deleted_at IS NULL OR NOT is_active);
