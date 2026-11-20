-- A public-authority replacement under the same IACA does not create a new
-- number space. Keep the highest accepted publication even after expiration.
CREATE TABLE IF NOT EXISTS nazo_mdoc_crl_publications (
    tenant_id TEXT NOT NULL,
    issuer_id TEXT NOT NULL CHECK(length(issuer_id)=64 AND issuer_id NOT GLOB '*[^0-9a-f]*'),
    issuer TEXT NOT NULL CHECK(length(issuer) BETWEEN 1 AND 8192),
    number_hex TEXT NOT NULL CHECK(length(number_hex)=40 AND number_hex NOT GLOB '*[^0-9a-f]*'
        AND number_hex<>'0000000000000000000000000000000000000000'),
    der_sha256 TEXT NOT NULL CHECK(length(der_sha256)=64 AND der_sha256 NOT GLOB '*[^0-9a-f]*'),
    authority_hash TEXT NOT NULL CHECK(length(authority_hash)=64 AND authority_hash NOT GLOB '*[^0-9a-f]*'),
    this_update INTEGER NOT NULL CHECK(this_update BETWEEN -9007199254740991 AND 9007199254740991),
    next_update INTEGER NOT NULL CHECK(next_update BETWEEN -9007199254740991 AND 9007199254740991),
    accepted_at INTEGER NOT NULL CHECK(accepted_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY(tenant_id,issuer_id),
    CHECK(this_update<next_update AND accepted_at>=this_update AND accepted_at<next_update)
) WITHOUT ROWID, STRICT;

CREATE TRIGGER IF NOT EXISTS nazo_mdoc_crl_publications_monotonic
BEFORE UPDATE ON nazo_mdoc_crl_publications
WHEN NEW.tenant_id<>OLD.tenant_id OR NEW.issuer_id<>OLD.issuer_id
    OR NEW.number_hex<=OLD.number_hex OR NEW.this_update<OLD.this_update
BEGIN SELECT RAISE(ABORT,'CRL publication cannot move backwards'); END;

CREATE TRIGGER IF NOT EXISTS nazo_mdoc_crl_publications_no_delete
BEFORE DELETE ON nazo_mdoc_crl_publications
BEGIN SELECT RAISE(ABORT,'CRL publication fence must be retained'); END;
