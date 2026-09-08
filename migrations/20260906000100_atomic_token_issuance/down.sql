DO $$
BEGIN
    RAISE EXCEPTION
        'atomic token issuance migration is irreversible; restore the pre-upgrade database backup before running the legacy writer';
END
$$;
