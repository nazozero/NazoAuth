CREATE TABLE oauth_client_mtls_trust_anchor_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    client_id UUID NOT NULL,
    certificate_pem TEXT NOT NULL,
    certificate_sha256 VARCHAR(64) NOT NULL,
    subject_dn TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0,
    admin_note TEXT,
    resolved_by_user_id UUID,
    resolved_at TIMESTAMPTZ,
    revoked_by_user_id UUID,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_mtls_trust_anchor_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_mtls_trust_anchor_requester
        FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT fk_mtls_trust_anchor_client
        FOREIGN KEY (client_id, tenant_id) REFERENCES oauth_clients(id, tenant_id),
    CONSTRAINT fk_mtls_trust_anchor_resolver
        FOREIGN KEY (resolved_by_user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT fk_mtls_trust_anchor_revoker
        FOREIGN KEY (revoked_by_user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT ck_mtls_trust_anchor_status CHECK (status IN (0, 1, 2, 3)),
    CONSTRAINT ck_mtls_trust_anchor_single_certificate CHECK (
        octet_length(certificate_pem) BETWEEN 1 AND 16384
        AND certificate_pem LIKE '-----BEGIN CERTIFICATE-----%'
        AND certificate_pem LIKE '%-----END CERTIFICATE-----%'
    ),
    CONSTRAINT ck_mtls_trust_anchor_digest CHECK (
        certificate_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_mtls_trust_anchor_subject CHECK (
        octet_length(subject_dn) BETWEEN 1 AND 2048
    ),
    CONSTRAINT ck_mtls_trust_anchor_validity CHECK (not_after > not_before),
    CONSTRAINT ck_mtls_trust_anchor_distinct_approver CHECK (
        resolved_by_user_id IS NULL OR resolved_by_user_id <> user_id
    ),
    CONSTRAINT ck_mtls_trust_anchor_state CHECK (
        (status = 0 AND resolved_by_user_id IS NULL AND resolved_at IS NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status IN (1, 2) AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 3 AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT ux_mtls_trust_anchor_client_certificate
        UNIQUE (tenant_id, client_id, certificate_sha256),
    CONSTRAINT uq_mtls_trust_anchor_request_tenant UNIQUE (id, tenant_id)
);

CREATE INDEX ix_mtls_trust_anchor_requester_created
    ON oauth_client_mtls_trust_anchor_requests (tenant_id, user_id, created_at DESC);
CREATE INDEX ix_mtls_trust_anchor_status_created
    ON oauth_client_mtls_trust_anchor_requests (tenant_id, status, created_at DESC);
CREATE INDEX ix_mtls_trust_anchor_active_bundle
    ON oauth_client_mtls_trust_anchor_requests (tenant_id, certificate_sha256)
    WHERE status = 1;

CREATE TABLE oauth_client_mtls_trust_anchor_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    request_id UUID NOT NULL,
    actor_user_id UUID NOT NULL,
    action SMALLINT NOT NULL,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_mtls_trust_anchor_event_request
        FOREIGN KEY (request_id, tenant_id)
        REFERENCES oauth_client_mtls_trust_anchor_requests(id, tenant_id),
    CONSTRAINT fk_mtls_trust_anchor_event_actor
        FOREIGN KEY (actor_user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT ck_mtls_trust_anchor_event_action CHECK (action IN (0, 1, 2, 3)),
    CONSTRAINT ck_mtls_trust_anchor_event_note CHECK (
        note IS NULL OR octet_length(note) BETWEEN 1 AND 1000
    )
);

CREATE INDEX ix_mtls_trust_anchor_events_request_created
    ON oauth_client_mtls_trust_anchor_events (tenant_id, request_id, created_at, id);

COMMENT ON TABLE oauth_client_mtls_trust_anchor_requests IS
    'Deployment trust-management records for RFC 8705 tls_client_auth or certificate-bound-token clients; OAuth protocol handlers never mutate this table.';
COMMENT ON COLUMN oauth_client_mtls_trust_anchor_requests.status IS
    '0=pending, 1=approved, 2=rejected, 3=revoked';
COMMENT ON TABLE oauth_client_mtls_trust_anchor_events IS
    'Append-only control-plane audit trail for trust-anchor request, approval, rejection, and revocation actions.';
COMMENT ON COLUMN oauth_client_mtls_trust_anchor_events.action IS
    '0=requested, 1=approved, 2=rejected, 3=revoked';
