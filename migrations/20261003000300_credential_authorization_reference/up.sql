-- Existing rows retain NULL lineage/selector evidence and stay token-bound.
-- Source token foreign keys and encrypted payload identities are unchanged.
ALTER TABLE openid4vci_access_grants
    ADD COLUMN authorization_id uuid,
    ADD COLUMN mtls_x5t_s256 text;
ALTER TABLE openid4vci_deferred_transactions
    ADD COLUMN authorization_id uuid,
    ADD COLUMN credential_selection jsonb,
    ADD COLUMN claim_token_id uuid;
ALTER TABLE openid4vci_notifications ADD COLUMN credential_selection jsonb;
ALTER TABLE openid4vci_issuance_responses ADD COLUMN credential_selection jsonb;
