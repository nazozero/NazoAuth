COMMENT ON COLUMN oauth_clients.tls_client_auth_san_email IS NULL;
COMMENT ON COLUMN oauth_clients.tls_client_auth_san_ip IS NULL;
COMMENT ON COLUMN oauth_clients.tls_client_auth_san_uri IS NULL;
COMMENT ON COLUMN oauth_clients.tls_client_auth_san_dns IS NULL;
COMMENT ON COLUMN oauth_clients.tls_client_auth_subject_dn IS
    'Registered subject DN for tls_client_auth clients; retained for discovery/admin compatibility';

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS tls_client_auth_san_email,
    DROP COLUMN IF EXISTS tls_client_auth_san_ip,
    DROP COLUMN IF EXISTS tls_client_auth_san_uri,
    DROP COLUMN IF EXISTS tls_client_auth_san_dns;
