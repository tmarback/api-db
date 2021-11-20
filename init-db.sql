-- Administrator role
CREATE ROLE admin WITH NOSUPERUSER CREATEDB CREATEROLE NOLOGIN;
GRANT pg_read_all_settings TO admin;

-- Database for shared API authentication methods
CREATE DATABASE auth WITH OWNER admin;
REVOKE ALL ON DATABASE auth FROM PUBLIC;
GRANT CONNECT ON DATABASE auth TO PUBLIC;