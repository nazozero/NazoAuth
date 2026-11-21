-- Preserve valid grants whose complete historical statistics were not recorded.
-- Intent audit entries are not proof of a completed device grant; do not invent
-- a timestamp or count from an intent or the migration's wall clock.
CREATE TABLE IF NOT EXISTS nazo_grant_history_unknown (
    tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, client_id TEXT NOT NULL,
    last_authorization_unknown INTEGER NOT NULL CHECK(last_authorization_unknown IN (0,1)),
    PRIMARY KEY(tenant_id,user_id,client_id),
    FOREIGN KEY(tenant_id,user_id,client_id) REFERENCES nazo_grants(tenant_id,user_id,client_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT OR IGNORE INTO nazo_grant_history_unknown
SELECT g.tenant_id,g.user_id,g.client_id,CASE WHEN EXISTS(
    SELECT 1 FROM nazo_audit a WHERE a.tenant_id=g.tenant_id AND a.event_id=g.revision
      AND a.event_type='authorization_decision') THEN 0 ELSE 1 END
FROM nazo_grants g JOIN nazo_clients c ON c.tenant_id=g.tenant_id AND c.id=g.client_id
WHERE NOT EXISTS(SELECT 1 FROM nazo_grant_activity a
    WHERE a.tenant_id=g.tenant_id AND a.user_id=g.user_id AND a.client_id=g.client_id)
  OR NOT EXISTS(SELECT 1 FROM nazo_audit a WHERE a.tenant_id=g.tenant_id AND a.event_id=g.revision
    AND a.event_type='authorization_decision')
  OR EXISTS(SELECT 1 FROM nazo_audit a WHERE a.tenant_id=g.tenant_id AND a.event_type='device_decision_intent'
    AND json_extract(a.payload,'$.user_id')=g.user_id AND json_extract(a.payload,'$.client_id')=c.client_id
    AND json_extract(a.payload,'$.decision')='approve');

DROP TRIGGER IF EXISTS nazo_grant_insert_activity;
DROP TRIGGER IF EXISTS nazo_grant_update_activity;
CREATE TRIGGER nazo_grant_insert_activity AFTER INSERT ON nazo_grants BEGIN
    INSERT INTO nazo_grant_activity
    SELECT NEW.tenant_id,NEW.user_id,NEW.client_id,occurred_at,1 FROM nazo_audit
    WHERE tenant_id=NEW.tenant_id AND event_id=NEW.revision
      AND event_type IN ('authorization_decision','device_grant_authorized');
END;
CREATE TRIGGER nazo_grant_update_activity AFTER UPDATE OF revision ON nazo_grants
WHEN NEW.revision<>OLD.revision BEGIN
    INSERT INTO nazo_grant_activity
    SELECT NEW.tenant_id,NEW.user_id,NEW.client_id,occurred_at,1 FROM nazo_audit
    WHERE tenant_id=NEW.tenant_id AND event_id=NEW.revision
      AND event_type IN ('authorization_decision','device_grant_authorized')
    ON CONFLICT(tenant_id,user_id,client_id) DO UPDATE SET
      last_authorized_at=excluded.last_authorized_at,authorization_count=authorization_count+1;
    UPDATE nazo_grant_history_unknown SET last_authorization_unknown=0
    WHERE tenant_id=NEW.tenant_id AND user_id=NEW.user_id AND client_id=NEW.client_id
      AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=NEW.tenant_id AND event_id=NEW.revision
        AND event_type IN ('authorization_decision','device_grant_authorized'));
END;
