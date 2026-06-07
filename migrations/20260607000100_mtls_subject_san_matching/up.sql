ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS tls_client_auth_san_dns JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS tls_client_auth_san_uri JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS tls_client_auth_san_ip JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS tls_client_auth_san_email JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN oauth_clients.tls_client_auth_subject_dn IS
    'Registered exact subject DN for tls_client_auth client authentication';
COMMENT ON COLUMN oauth_clients.tls_client_auth_san_dns IS
    'Registered DNS subjectAltName values for tls_client_auth client authentication';
COMMENT ON COLUMN oauth_clients.tls_client_auth_san_uri IS
    'Registered URI subjectAltName values for tls_client_auth client authentication';
COMMENT ON COLUMN oauth_clients.tls_client_auth_san_ip IS
    'Registered IP subjectAltName values for tls_client_auth client authentication';
COMMENT ON COLUMN oauth_clients.tls_client_auth_san_email IS
    'Registered email subjectAltName values for tls_client_auth client authentication';
