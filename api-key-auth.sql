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
    PRIMARY KEY ( keyval, api, role )
);

-- Determines if a key is valid and has access to the given API and roles.
-- Possible return codes are:
--   0 - Key is valid and has access to all the given roles in the given API
--   1 - Key is valid but does not have access to one or more of the given roles in the given API
--   2 - Key is invalid
-- This is the only object in this schema that non-admins should be able to access.
CREATE OR REPLACE FUNCTION api_key_auth.has_access( p_keyval TEXT, p_api TEXT, p_roles TEXT[] ) 
RETURNS INTEGER AS $$
DECLARE 
    valid INTEGER;
    found INTEGER;
    allowed_roles TEXT[];
BEGIN
    -- Check key is valid
    SELECT  COUNT(*) INTO valid
    FROM    api_key_auth.keys k
    WHERE   k.keyval = p_keyval;

    IF valid = 0 THEN
        RETURN 2;
    END IF;

    -- Check for wildcard role
    SELECT  COUNT(*) INTO found
    FROM    api_key_auth.access u
    WHERE   u.keyval = p_keyval 
            AND ( u.api = p_api OR u.api = '*' )
            AND u.role = '*';

    IF found > 0 THEN
        RETURN 0;
    END IF;

    -- Check for all roles
    allowed_roles := ARRAY(
        SELECT  u.role
        FROM    api_key_auth.access u
        WHERE   u.keyval = p_keyval 
                AND ( u.api = p_api OR u.api = '*' )
    );

    IF p_roles <@ allowed_roles THEN -- Requested roles must be a strict subset of allowed roles
        RETURN 0;
    ELSE
        RETURN 1;
    END IF;
END;
$$  LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = api_key_auth, pg_temp;

-- Determines if a key is valid and has access to the given API and role.
-- Possible return codes are:
--   0 - Key is valid and has access to the given role in the given API
--   1 - Key is valid but does not have access to the given role in the given API
--   2 - Key is invalid
-- This is the only object in this schema that non-admins should be able to access.
CREATE OR REPLACE FUNCTION api_key_auth.has_access( p_keyval TEXT, p_api TEXT, p_role TEXT ) 
RETURNS INTEGER
LANGUAGE SQL
STABLE
RETURN api_key_auth.has_access( p_keyval, p_api, array[ p_role ] );