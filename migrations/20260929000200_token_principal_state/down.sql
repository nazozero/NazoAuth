-- An epoch downgrade could resurrect tokens, and deleting bindings could
-- strand live pairwise tokens. Recovery must use the version-coupled backup.
DO $$ BEGIN
    RAISE EXCEPTION 'token principal state cannot be downgraded safely; restore a matching backup';
END $$;
