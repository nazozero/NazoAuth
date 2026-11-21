-- Verification attempts are a property of one owned challenge. Reservations
-- use tenant-scoped nazo_state rows; replacement must match their current owner.
CREATE TABLE IF NOT EXISTS nazo_email_codes (
    tenant_id TEXT NOT NULL, email_hash TEXT NOT NULL, owner TEXT NOT NULL,
    verification_hash TEXT NOT NULL CHECK(length(trim(verification_hash))>0),
    version TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
    expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN 0 AND 9007199254740991),
    PRIMARY KEY(tenant_id,email_hash)
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nazo_email_codes_expiry ON nazo_email_codes(tenant_id,expires_at);
