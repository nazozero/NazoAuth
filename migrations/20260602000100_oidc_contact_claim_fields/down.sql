ALTER TABLE users
    DROP COLUMN IF EXISTS phone_number_verified,
    DROP COLUMN IF EXISTS phone_number,
    DROP COLUMN IF EXISTS address_country,
    DROP COLUMN IF EXISTS address_postal_code,
    DROP COLUMN IF EXISTS address_region,
    DROP COLUMN IF EXISTS address_locality,
    DROP COLUMN IF EXISTS address_street_address,
    DROP COLUMN IF EXISTS address_formatted;
