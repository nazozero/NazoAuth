-- OpenID4VC state remains tenant scoped. Claims, offer secrets, exact credential
-- responses and presentation keys/results are authenticated ciphertext.
CREATE TABLE IF NOT EXISTS nazo_vc_trust_policies (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, resource_id TEXT NOT NULL,
    resource_digest TEXT NOT NULL CHECK(length(resource_digest)=64),
    material TEXT NOT NULL CHECK(json_valid(material)),
    source TEXT NOT NULL CHECK(source='operator-managed'),
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,resource_id,resource_digest)
) WITHOUT ROWID, STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS nazo_vc_trust_active ON nazo_vc_trust_policies(tenant_id,resource_id) WHERE active=1;
CREATE TABLE IF NOT EXISTS nazo_vc_trust_clients (
    tenant_id TEXT NOT NULL, client_id TEXT NOT NULL, policy_id TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    PRIMARY KEY(tenant_id,client_id,policy_id),
    FOREIGN KEY(tenant_id,client_id) REFERENCES nazo_clients(tenant_id,id),
    FOREIGN KEY(tenant_id,policy_id) REFERENCES nazo_vc_trust_policies(tenant_id,id)
) WITHOUT ROWID, STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS nazo_vc_trust_client_active ON nazo_vc_trust_clients(tenant_id,client_id) WHERE active=1;

CREATE TABLE IF NOT EXISTS nazo_vp_transactions (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL,
    request_jti TEXT NOT NULL, request_sha256 TEXT NOT NULL, canonical_request TEXT NOT NULL,
    record TEXT NOT NULL CHECK(json_valid(record)), state_hash TEXT NOT NULL,
    trust_id TEXT, trust_resource TEXT, trust_digest TEXT,
    private_key_ciphertext TEXT, result_ciphertext TEXT,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, completed_at INTEGER,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,request_jti),
    CHECK(expires_at>created_at),
    CHECK((trust_id IS NULL AND trust_resource IS NULL AND trust_digest IS NULL) OR
          (trust_id IS NOT NULL AND trust_resource IS NOT NULL AND trust_digest IS NOT NULL)),
    CHECK((completed_at IS NULL AND result_ciphertext IS NULL) OR
          (completed_at IS NOT NULL AND result_ciphertext IS NOT NULL AND private_key_ciphertext IS NULL))
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_vp_expiry ON nazo_vp_transactions(tenant_id,expires_at);

CREATE TABLE IF NOT EXISTS nazo_vci_offers (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, subject_id TEXT,
    configuration_ids TEXT NOT NULL CHECK(json_valid(configuration_ids) AND json_array_length(configuration_ids)>0),
    grants_ciphertext TEXT NOT NULL, issuer_state_hash TEXT, code_hash TEXT, tx_code_hash TEXT,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,issuer_state_hash), UNIQUE(tenant_id,code_hash),
    FOREIGN KEY(tenant_id,subject_id) REFERENCES nazo_users(tenant_id,id),
    CHECK(expires_at>created_at)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_vci_access (
    tenant_id TEXT NOT NULL, token_id TEXT NOT NULL, token_hash TEXT NOT NULL,
    subject_id TEXT NOT NULL, client_id TEXT NOT NULL,
    record TEXT NOT NULL CHECK(json_valid(record)), expires_at INTEGER NOT NULL, revoked_at INTEGER, mutation_id TEXT,
    PRIMARY KEY(tenant_id,token_id), UNIQUE(tenant_id,token_hash),
    FOREIGN KEY(tenant_id,subject_id) REFERENCES nazo_users(tenant_id,id)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS nazo_vci_access_subject ON nazo_vci_access(tenant_id,subject_id);
CREATE INDEX IF NOT EXISTS nazo_vci_access_client ON nazo_vci_access(tenant_id,client_id);
CREATE TABLE IF NOT EXISTS nazo_vci_nonces (
    tenant_id TEXT NOT NULL, nonce_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER,
    claim_id TEXT, claim_expires_at INTEGER,
    PRIMARY KEY(tenant_id,nonce_hash), CHECK(expires_at>created_at),
    CHECK((claim_id IS NULL)=(claim_expires_at IS NULL))
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_vci_responses (
    tenant_id TEXT NOT NULL, issuance_id TEXT NOT NULL, token_id TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
    selection TEXT NOT NULL CHECK(json_valid(selection)), body_ciphertext TEXT NOT NULL,
    encoding TEXT NOT NULL CHECK(encoding IN ('json','jwt')),
    status INTEGER NOT NULL CHECK(status IN (200,202)), dpop_nonce TEXT,
    expires_at INTEGER NOT NULL, mutation_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id,issuance_id),
    FOREIGN KEY(tenant_id,token_id) REFERENCES nazo_vci_access(tenant_id,token_id)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_vci_deferred (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, transaction_hash TEXT NOT NULL,
    token_id TEXT NOT NULL, record TEXT NOT NULL CHECK(json_valid(record)), payload_ciphertext TEXT NOT NULL,
    ready_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER,
    claim_id TEXT, claim_expires_at INTEGER, claim_token_id TEXT,
    PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,transaction_hash),
    FOREIGN KEY(tenant_id,token_id) REFERENCES nazo_vci_access(tenant_id,token_id),
    CHECK(expires_at>ready_at), CHECK(consumed_at IS NULL OR consumed_at>=ready_at),
    CHECK((claim_id IS NULL AND claim_expires_at IS NULL AND claim_token_id IS NULL) OR
          (claim_id IS NOT NULL AND claim_expires_at IS NOT NULL AND claim_token_id IS NOT NULL))
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_vci_notifications (
    tenant_id TEXT NOT NULL, notification_id TEXT NOT NULL, token_id TEXT NOT NULL,
    selection TEXT NOT NULL CHECK(json_valid(selection)), expires_at INTEGER NOT NULL,
    event TEXT CHECK(event IN ('credential_accepted','credential_failure','credential_deleted')),
    description TEXT, occurred_at INTEGER,
    PRIMARY KEY(tenant_id,notification_id),
    FOREIGN KEY(tenant_id,token_id) REFERENCES nazo_vci_access(tenant_id,token_id),
    CHECK((event IS NULL)=(occurred_at IS NULL))
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_vci_datasets (
    tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL, configuration_id TEXT NOT NULL,
    claims_ciphertext TEXT NOT NULL, source TEXT NOT NULL,
    valid_from INTEGER, valid_until INTEGER, updated_at INTEGER NOT NULL,
    revision TEXT NOT NULL,
    PRIMARY KEY(tenant_id,subject_id,configuration_id),
    FOREIGN KEY(tenant_id,subject_id) REFERENCES nazo_users(tenant_id,id),
    CHECK(length(trim(configuration_id)) BETWEEN 1 AND 255),
    CHECK(valid_from IS NULL OR valid_until IS NULL OR valid_until>valid_from)
) WITHOUT ROWID, STRICT;
CREATE TABLE IF NOT EXISTS nazo_vci_dataset_events (
    tenant_id TEXT NOT NULL, id TEXT NOT NULL, subject_id TEXT NOT NULL,
    configuration_id TEXT NOT NULL, action INTEGER NOT NULL CHECK(action IN (1,2)),
    actor_user_id TEXT, source TEXT NOT NULL CHECK(source IN ('admin-session','operator-managed')),
    occurred_at INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,id)
) WITHOUT ROWID, STRICT;
CREATE TRIGGER IF NOT EXISTS nazo_vci_dataset_event_no_update BEFORE UPDATE ON nazo_vci_dataset_events
BEGIN SELECT RAISE(ABORT,'credential dataset events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS nazo_vci_dataset_event_no_delete BEFORE DELETE ON nazo_vci_dataset_events
BEGIN SELECT RAISE(ABORT,'credential dataset events are append-only'); END;

-- Deactivation must retire credential continuations in the same owner write.
CREATE TRIGGER IF NOT EXISTS nazo_vci_revoke_user AFTER UPDATE OF active,epoch ON nazo_users
WHEN NEW.active=0 OR NEW.epoch<>OLD.epoch
BEGIN UPDATE nazo_vci_access SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000000 AS INTEGER))
      WHERE tenant_id=NEW.tenant_id AND subject_id=NEW.id;
      UPDATE nazo_vci_offers SET consumed_at=MAX(CAST(unixepoch('subsec')*1000000 AS INTEGER),created_at),grants_ciphertext='',tx_code_hash=NULL
      WHERE tenant_id=NEW.tenant_id AND subject_id=NEW.id AND consumed_at IS NULL;
END;
CREATE TRIGGER IF NOT EXISTS nazo_vci_revoke_client AFTER UPDATE OF active,epoch ON nazo_clients
WHEN NEW.active=0 OR NEW.epoch<>OLD.epoch
BEGIN UPDATE nazo_vci_access SET revoked_at=COALESCE(revoked_at,CAST(unixepoch('subsec')*1000000 AS INTEGER))
      WHERE tenant_id=NEW.tenant_id AND client_id=NEW.client_id; END;
