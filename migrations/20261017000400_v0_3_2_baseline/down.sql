-- Restore a verified database backup to return to an earlier release.
DO $$ BEGIN
    RAISE EXCEPTION 'cannot roll back the v0.3.2 baseline; restore a verified database backup';
END $$;
