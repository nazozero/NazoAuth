ALTER TABLE openid4vci_issuance_responses DROP COLUMN credential_selection;
ALTER TABLE openid4vci_notifications DROP COLUMN credential_selection;
ALTER TABLE openid4vci_deferred_transactions
    DROP COLUMN claim_token_id,
    DROP COLUMN credential_selection,
    DROP COLUMN authorization_id;
ALTER TABLE openid4vci_access_grants
    DROP COLUMN mtls_x5t_s256,
    DROP COLUMN authorization_id;
