ALTER TABLE oauth_clients
    DROP COLUMN frontchannel_logout_session_required,
    DROP COLUMN frontchannel_logout_uri;
