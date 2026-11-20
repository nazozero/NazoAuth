-- Deployment selection supplies the initial desired state only. Subsequent
-- desired/instance changes and their receipts are owned by the runtime store.
CREATE TABLE IF NOT EXISTS nazo_module_desired (
    tenant_id TEXT NOT NULL,
    module_id TEXT NOT NULL CHECK(module_id IN (
        'device_authorization','token_exchange','jwt_bearer_grant','ciba',
        'dynamic_client_registration','request_objects','jarm','authorization_details',
        'http_message_signatures','scim','scim_security_events','native_sso',
        'frontchannel_logout','session_management','openid4vci_issuer','openid4vp_verifier')),
    mode TEXT NOT NULL CHECK(mode IN ('enabled','disabled')),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    actor_id TEXT,
    reason TEXT CHECK(reason IS NULL OR length(trim(reason))>=1 AND length(reason)<=500),
    updated_at INTEGER NOT NULL CHECK(updated_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY(tenant_id,module_id)
) WITHOUT ROWID, STRICT;

-- The old profile has no authoritative change time or actor. Preserve that
-- absence as the epoch baseline; do not invent historical change events.
INSERT INTO nazo_module_desired(tenant_id,module_id,mode,revision,actor_id,reason,updated_at)
SELECT tenant_id,module_id,CASE enabled WHEN 1 THEN 'enabled' ELSE 'disabled' END,
       1,NULL,'deployment profile',0 FROM nazo_modules WHERE true
ON CONFLICT(tenant_id,module_id) DO NOTHING;

CREATE TRIGGER IF NOT EXISTS nazo_module_profile_initialize
AFTER INSERT ON nazo_modules
BEGIN
    INSERT INTO nazo_module_desired(tenant_id,module_id,mode,revision,actor_id,reason,updated_at)
    VALUES(NEW.tenant_id,NEW.module_id,CASE NEW.enabled WHEN 1 THEN 'enabled' ELSE 'disabled' END,
           1,NULL,'deployment profile',0);
END;

CREATE TRIGGER IF NOT EXISTS nazo_module_desired_revision
BEFORE UPDATE ON nazo_module_desired
WHEN NEW.tenant_id<>OLD.tenant_id OR NEW.module_id<>OLD.module_id
    OR NEW.revision<>OLD.revision+1 OR NEW.mode=OLD.mode
BEGIN SELECT RAISE(ABORT,'module desired state must advance one revision'); END;

CREATE TABLE IF NOT EXISTS nazo_module_instances (
    tenant_id TEXT NOT NULL,
    instance_id TEXT NOT NULL CHECK(length(trim(instance_id))>=1 AND length(instance_id)<=255),
    module_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('disabled','starting','enabled','draining','failed')),
    transition_revision INTEGER NOT NULL CHECK(transition_revision BETWEEN 0 AND 9007199254740991),
    applied_revision INTEGER CHECK(applied_revision IS NULL OR applied_revision BETWEEN 0 AND transition_revision),
    drain_deadline INTEGER CHECK(drain_deadline IS NULL OR drain_deadline BETWEEN -9007199254740991 AND 9007199254740991),
    error_code TEXT CHECK(error_code IS NULL OR length(trim(error_code))>=1 AND length(error_code)<=128),
    updated_at INTEGER NOT NULL CHECK(updated_at BETWEEN -9007199254740991 AND 9007199254740991),
    PRIMARY KEY(tenant_id,instance_id,module_id),
    FOREIGN KEY(tenant_id,module_id) REFERENCES nazo_module_desired(tenant_id,module_id)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_module_instances_age
ON nazo_module_instances(tenant_id,updated_at);

CREATE TABLE IF NOT EXISTS nazo_module_events (
    event_id TEXT PRIMARY KEY CHECK(length(event_id)=36),
    tenant_id TEXT NOT NULL,
    module_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN (
        'desired_state_changed','transition_started','transition_completed','transition_failed',
        'drain_started','drain_completed','stale_transition_discarded')),
    occurred_at INTEGER NOT NULL CHECK(occurred_at BETWEEN -9007199254740991 AND 9007199254740991),
    record TEXT NOT NULL CHECK(json_valid(record) AND json_type(record)='object'
        AND json_extract(record,'$.event_id')=event_id
        AND json_extract(record,'$.module_id')=module_id
        AND json_extract(record,'$.event_type')=event_type
        AND json_extract(record,'$.occurred_at')=occurred_at
        AND json_type(record,'$.revision')='integer'
        AND json_extract(record,'$.revision') BETWEEN 0 AND 9007199254740991)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_module_events_page
ON nazo_module_events(tenant_id,occurred_at DESC,event_id DESC);
CREATE TRIGGER IF NOT EXISTS nazo_module_events_no_update BEFORE UPDATE ON nazo_module_events
BEGIN SELECT RAISE(ABORT,'runtime module events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS nazo_module_events_no_delete BEFORE DELETE ON nazo_module_events
BEGIN SELECT RAISE(ABORT,'runtime module events are append-only'); END;
