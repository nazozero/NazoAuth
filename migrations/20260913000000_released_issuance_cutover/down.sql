DO $$ BEGIN RAISE EXCEPTION 'released issuance cutover is irreversible; restore the pre-upgrade database backup to downgrade'; END $$;
