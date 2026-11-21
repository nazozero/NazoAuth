CREATE TABLE IF NOT EXISTS nazo_logout_outbox (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, operation_key TEXT NOT NULL,
    client_id TEXT NOT NULL, client_public_id TEXT NOT NULL,
    logout_uri TEXT NOT NULL, logout_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL, available_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, lease_until INTEGER,
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','delivered','failed')),
    last_error TEXT,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,operation_key,client_id)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_logout_due ON nazo_logout_outbox(tenant_id,state,available_at,expires_at);

CREATE TABLE IF NOT EXISTS nazo_avatar_objects (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, version TEXT NOT NULL,
    content_type TEXT NOT NULL, byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 2097152),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,user_id,version)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_avatar_chunks (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, version TEXT NOT NULL,
    ordinal INTEGER NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY(tenant_id,user_id,version,ordinal),
    FOREIGN KEY(tenant_id,user_id,version) REFERENCES nazo_avatar_objects(tenant_id,user_id,version) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX IF NOT EXISTS nazo_audit_authorizations ON nazo_audit(
    tenant_id,json_extract(payload,'$.user_id'),json_extract(payload,'$.client_id'),occurred_at
) WHERE event_type='authorization_decision' AND json_extract(payload,'$.decision')='approve';

CREATE TABLE IF NOT EXISTS nazo_grant_activity (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, client_id TEXT NOT NULL,
    last_authorized_at INTEGER NOT NULL, authorization_count INTEGER NOT NULL CHECK(authorization_count>0),
    PRIMARY KEY(tenant_id,user_id,client_id),
    FOREIGN KEY(tenant_id,user_id,client_id) REFERENCES nazo_grants(tenant_id,user_id,client_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- Existing accepting decisions already have atomic canonical audit evidence.
-- Before this migration, removal was terminal client deactivation: surviving
-- grants therefore retain the complete recorded authorization generation.
INSERT OR IGNORE INTO nazo_grant_activity
SELECT g.tenant_id,g.user_id,g.client_id,MAX(a.occurred_at),COUNT(*)
FROM nazo_grants g JOIN nazo_clients c ON c.tenant_id=g.tenant_id AND c.id=g.client_id
JOIN nazo_audit a ON a.tenant_id=g.tenant_id AND a.event_type='authorization_decision'
  AND json_extract(a.payload,'$.user_id')=g.user_id AND json_extract(a.payload,'$.client_id')=c.client_id
  AND json_extract(a.payload,'$.decision')='approve'
GROUP BY g.tenant_id,g.user_id,g.client_id;
CREATE TRIGGER IF NOT EXISTS nazo_grant_insert_activity AFTER INSERT ON nazo_grants BEGIN
    INSERT INTO nazo_grant_activity
    SELECT NEW.tenant_id,NEW.user_id,NEW.client_id,occurred_at,1 FROM nazo_audit
    WHERE tenant_id=NEW.tenant_id AND event_id=NEW.revision AND event_type='authorization_decision';
END;
CREATE TRIGGER IF NOT EXISTS nazo_grant_update_activity AFTER UPDATE OF revision ON nazo_grants
WHEN NEW.revision<>OLD.revision BEGIN
    INSERT INTO nazo_grant_activity
    SELECT NEW.tenant_id,NEW.user_id,NEW.client_id,occurred_at,1 FROM nazo_audit
    WHERE tenant_id=NEW.tenant_id AND event_id=NEW.revision AND event_type='authorization_decision'
    ON CONFLICT(tenant_id,user_id,client_id) DO UPDATE SET
      last_authorized_at=excluded.last_authorized_at,authorization_count=authorization_count+1;
END;

-- Bounded Cron reclamation and child ownership checks avoid full-table scans.
CREATE INDEX IF NOT EXISTS nazo_logout_expiry ON nazo_logout_outbox(tenant_id,expires_at,id);
CREATE INDEX IF NOT EXISTS nazo_vci_offers_expiry ON nazo_vci_offers(tenant_id,expires_at,id);
CREATE INDEX IF NOT EXISTS nazo_vci_nonce_expiry ON nazo_vci_nonces(tenant_id,expires_at,nonce_hash);
CREATE INDEX IF NOT EXISTS nazo_vci_access_expiry ON nazo_vci_access(tenant_id,expires_at,token_id);
CREATE INDEX IF NOT EXISTS nazo_vci_responses_expiry ON nazo_vci_responses(tenant_id,expires_at,issuance_id);
CREATE INDEX IF NOT EXISTS nazo_vci_responses_owner ON nazo_vci_responses(tenant_id,token_id);
CREATE INDEX IF NOT EXISTS nazo_vci_deferred_expiry ON nazo_vci_deferred(tenant_id,expires_at,id);
CREATE INDEX IF NOT EXISTS nazo_vci_deferred_owner ON nazo_vci_deferred(tenant_id,token_id);
CREATE INDEX IF NOT EXISTS nazo_vci_notification_expiry ON nazo_vci_notifications(tenant_id,expires_at,notification_id);
CREATE INDEX IF NOT EXISTS nazo_vci_notification_owner ON nazo_vci_notifications(tenant_id,token_id);
