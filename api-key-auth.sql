-- Authentication method that constrains access to an API based on having a valid
-- API key with sufficient permissions

-- assumes role 'admin' exists
CREATE SCHEMA IF NOT EXISTS api_key_auth AUTHORIZATION admin;
REVOKE ALL ON SCHEMA api_key_auth FROM PUBLIC;
GRANT USAGE ON SCHEMA api_key_auth TO PUBLIC;

-- Key definition
CREATE TABLE IF NOT EXISTS api_key_auth.keys (
    keyval      CHARACTER( 20 ) NOT NULL PRIMARY KEY, -- The key itself
    name        TEXT                                  -- Identifier for the key (for ease of management), optional
);

-- Identifies access level for each key
-- A key may have multiple entries
CREATE TABLE IF NOT EXISTS api_key_auth.access (
    keyval      CHARACTER( 20 ) NOT NULL REFERENCES api_key_auth.keys ON DELETE CASCADE ON UPDATE CASCADE,
    api         TEXT            NOT NULL, -- Which API to grant access to, or '*' for all
    role        TEXT            NOT NULL, -- Which role with the API to grant access to, or '*' for all
    PRIMARY KEY ( keyval, api, ver )
);

-- Determines if a key is valid and has access to the given API and role.
-- Possible return codes are:
--   0 - Key is valid and has access
--   1 - Key is valid but does not have access
--   2 - Key is invalid
-- This is the only object in this schema that non-admins should be able to access.
CREATE OR REPLACE FUNCTION api_key_auth.has_access( p_keyval TEXT, p_api TEXT, p_role TEXT ) 
RETURNS INTEGER AS $$
DECLARE 
    valid INTEGER;
    found INTEGER;
BEGIN
    SELECT  COUNT(*) INTO valid
    FROM    keys k
    WHERE   k.keyval = p_keyval;

    IF valid = 0 THEN
        RETURN 2;
    END IF;

    SELECT  COUNT(*) INTO found
    FROM    access u
    WHERE   u.keyval = p_keyval 
            AND ( u.api  = p_api  OR u.api  = '*' ) 
            AND ( u.role = p_role OR u.role = '*' );

    IF found > 0 THEN
        RETURN 0;
    ELSE
        RETURN 1;
    END IF;
END;
$$  LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = api_key_auth, pg_temp;