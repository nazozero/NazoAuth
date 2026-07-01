ALTER TABLE oauth_tokens
    ADD COLUMN audience jsonb NOT NULL DEFAULT '[]'::jsonb;
