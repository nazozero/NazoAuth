ALTER TABLE oauth_clients ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'public'
    CHECK (subject_type IN ('public', 'pairwise'));
ALTER TABLE oauth_clients ADD COLUMN sector_identifier_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN sector_identifier_host TEXT;
