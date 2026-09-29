-- Legacy receipts still provide ownership/revocation during the live-token
-- transition. New receipts exist only for SingleUse replay handling; their
-- tokens are invalidated by principal epochs, never expanded into JTI lists.
ALTER TABLE oauth_token_issuances
    ADD COLUMN principal_epoch_bound BOOLEAN NOT NULL DEFAULT FALSE;
