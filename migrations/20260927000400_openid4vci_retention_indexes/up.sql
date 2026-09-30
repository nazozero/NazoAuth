-- Bounded expiry scans and parent-reference probes for the existing
-- security-state maintenance worker. No authority rows are deleted here.
CREATE INDEX ix_openid4vci_notification_expiry
    ON openid4vci_notifications (expires_at);
CREATE INDEX ix_openid4vci_deferred_token
    ON openid4vci_deferred_transactions (token_id);
CREATE INDEX ix_openid4vci_notification_token
    ON openid4vci_notifications (token_id);
