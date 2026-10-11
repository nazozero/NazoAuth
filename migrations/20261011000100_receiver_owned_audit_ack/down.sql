DO $$ BEGIN RAISE EXCEPTION 'receiver-owned audit acknowledgement cannot be downgraded automatically; use a verified pre-cutover recovery'; END $$;
