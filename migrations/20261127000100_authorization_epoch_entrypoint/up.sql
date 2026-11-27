-- Browser decisions must carry the epoch established by authentication.
-- Old service instances must be drained before this migration.
DROP FUNCTION public.nazo_commit_authorization_decision(UUID, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, TEXT, UUID, TIMESTAMPTZ, JSONB, JSONB, JSONB, JSONB);
