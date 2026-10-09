-- Bound locks inside the decision statement, including implicit transactions.
ALTER FUNCTION public.nazo_commit_authorization_decision(
    UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT,
    UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB
) SET lock_timeout = '2s';
