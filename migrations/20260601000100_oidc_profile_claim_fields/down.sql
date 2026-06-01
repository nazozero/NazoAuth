ALTER TABLE users
    DROP COLUMN IF EXISTS locale,
    DROP COLUMN IF EXISTS zoneinfo,
    DROP COLUMN IF EXISTS birthdate,
    DROP COLUMN IF EXISTS gender,
    DROP COLUMN IF EXISTS website_url,
    DROP COLUMN IF EXISTS profile_url,
    DROP COLUMN IF EXISTS nickname,
    DROP COLUMN IF EXISTS middle_name,
    DROP COLUMN IF EXISTS family_name,
    DROP COLUMN IF EXISTS given_name;
