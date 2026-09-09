DO $$ BEGIN
    RAISE EXCEPTION 'exporter-owned audit chain migration is irreversible; restore the matching pre-upgrade database backup and binaries';
END $$;
