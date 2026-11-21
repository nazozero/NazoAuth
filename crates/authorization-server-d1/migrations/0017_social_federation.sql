-- Use the same provider type as the shared federation service and PostgreSQL.
CREATE TABLE nazo_federation_links_new (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, user_id TEXT NOT NULL,
    provider_type TEXT NOT NULL CHECK(provider_type IN ('oidc','oauth2_social','saml')),
    provider_id TEXT NOT NULL, subject TEXT NOT NULL, email TEXT NOT NULL,
    claims TEXT NOT NULL CHECK(json_valid(claims)),
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_login_at INTEGER,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,provider_type,provider_id,subject),
    FOREIGN KEY(tenant_id,user_id) REFERENCES nazo_users(tenant_id,id)
) WITHOUT ROWID, STRICT;

INSERT INTO nazo_federation_links_new
    (tenant_id,id,user_id,provider_type,provider_id,subject,email,claims,created_at,updated_at,last_login_at)
SELECT tenant_id,id,user_id,
    CASE provider_type WHEN 'social' THEN 'oauth2_social' ELSE provider_type END,
    provider_id,subject,email,claims,created_at,updated_at,last_login_at
FROM nazo_federation_links;

DROP TABLE nazo_federation_links;
ALTER TABLE nazo_federation_links_new RENAME TO nazo_federation_links;
CREATE INDEX nazo_federation_user ON nazo_federation_links(tenant_id,user_id);
