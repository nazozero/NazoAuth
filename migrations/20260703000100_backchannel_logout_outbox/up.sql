CREATE TABLE IF NOT EXISTS backchannel_logout_deliveries (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    client_public_id VARCHAR NOT NULL,
    logout_uri TEXT NOT NULL,
    logout_token TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    last_error TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_backchannel_logout_delivery_attempts_non_negative CHECK (attempts >= 0),
    CONSTRAINT ck_backchannel_logout_delivery_terminal_once CHECK (
        delivered_at IS NULL OR failed_at IS NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_backchannel_logout_deliveries_due
    ON backchannel_logout_deliveries (next_attempt_at, created_at)
    WHERE delivered_at IS NULL AND failed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_backchannel_logout_deliveries_client
    ON backchannel_logout_deliveries (tenant_id, client_id, created_at);
