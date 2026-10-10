-- These timestamps have no policy, query, protocol or retention consumer.
-- Preserve the operation identity and every used recovery key indefinitely.
ALTER TABLE admin_provision_receipts DROP COLUMN created_at;
ALTER TABLE controller_recovery_root_key_history DROP COLUMN first_seen_at;
