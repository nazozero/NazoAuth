-- Restore the original function-local configuration.
ALTER FUNCTION public.nazo_commit_authorization_decision(
    UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT,
    UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB
) RESET lock_timeout;
