ALTER TABLE oauth_clients
    ADD COLUMN frontchannel_logout_uri VARCHAR NULL,
    ADD COLUMN frontchannel_logout_session_required BOOLEAN NOT NULL DEFAULT TRUE;
