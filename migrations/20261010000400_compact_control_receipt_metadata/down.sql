-- Recreate only unused metadata; values are not original history.
-- No operation receipt or used-key identity is deleted or recreated.
ALTER TABLE admin_provision_receipts ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE controller_recovery_root_key_history ADD COLUMN first_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE controller_recovery_root_key_history ALTER COLUMN first_seen_at DROP DEFAULT;
