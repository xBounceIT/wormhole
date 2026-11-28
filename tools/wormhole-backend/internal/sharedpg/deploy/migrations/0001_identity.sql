-- Version 1: provisioning-only identity and privilege foundation.
-- Execute as a DBA in an empty dedicated database. No IF NOT EXISTS: never
-- adopt pre-existing roles or objects of unknown ownership.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
DO $migration_lock$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration is already in progress' USING ERRCODE='55P03';
    END IF;
END
$migration_lock$;
DO $guard$
BEGIN
    IF pg_catalog.current_setting('server_version_num')::integer < 160000 THEN
        RAISE EXCEPTION 'PostgreSQL 16 or newer is required' USING ERRCODE = '0A000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname !~ '^pg_'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname !~ '^pg_'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname !~ '^pg_'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace n
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'public')
          AND n.nspname !~ '^pg_'
    ) THEN
        RAISE EXCEPTION 'Workspace deployment requires an empty database' USING ERRCODE = '55000';
    END IF;
END
$guard$;

CREATE ROLE wh_{{TAG}}_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE wh_{{TAG}}_user NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE wh_{{TAG}}_admin NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE wh_{{TAG}}_deployer LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT wh_{{TAG}}_user TO wh_{{TAG}}_admin;
GRANT wh_{{TAG}}_owner TO wh_{{TAG}}_deployer WITH INHERIT FALSE, SET TRUE;

DO $privileges$
BEGIN
    EXECUTE pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', pg_catalog.current_database());
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO wh_{{TAG}}_user, wh_{{TAG}}_deployer', pg_catalog.current_database());
END
$privileges$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA wormhole_data AUTHORIZATION wh_{{TAG}}_owner;
CREATE SCHEMA wormhole_api_v1 AUTHORIZATION wh_{{TAG}}_owner;
REVOKE ALL ON SCHEMA wormhole_data, wormhole_api_v1 FROM PUBLIC;
GRANT USAGE ON SCHEMA wormhole_api_v1 TO wh_{{TAG}}_user;

SET LOCAL ROLE wh_{{TAG}}_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC;

CREATE TABLE wormhole_data.workspace_meta (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    workspace_id uuid NOT NULL UNIQUE CHECK (workspace_id <> '00000000-0000-0000-0000-000000000000'),
    role_tag text NOT NULL CHECK (role_tag = '{{TAG}}'),
    schema_version integer NOT NULL CHECK (schema_version >= 1),
    state text NOT NULL CHECK (state IN ('provisioning', 'ready')),
    min_api integer NOT NULL CHECK (min_api >= 1),
    max_api integer NOT NULL CHECK (max_api >= min_api),
    epoch bigint NOT NULL DEFAULT 1 CHECK (epoch >= 1),
    change_seq bigint NOT NULL DEFAULT 0 CHECK (change_seq >= 0),
    resolver_version integer NOT NULL DEFAULT 1 CHECK (resolver_version >= 1),
    signed_profile bytea NULL CHECK (pg_catalog.octet_length(signed_profile) BETWEEN 1 AND 65536),
    CHECK (state <> 'ready' OR signed_profile IS NOT NULL)
);
INSERT INTO wormhole_data.workspace_meta
    (workspace_id, role_tag, schema_version, state, min_api, max_api)
VALUES ('{{WORKSPACE_ID}}', '{{TAG}}', 1, 'provisioning', 1, 1);

CREATE TABLE wormhole_data.users (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    login_name text NOT NULL UNIQUE CHECK (pg_catalog.octet_length(login_name) BETWEEN 1 AND 256),
    name text NULL CHECK (pg_catalog.octet_length(name) <= 4096),
    is_admin boolean NOT NULL DEFAULT false,
    disabled boolean NOT NULL DEFAULT false,
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version >= 1)
);
CREATE TABLE wormhole_data.devices (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    role_name text NOT NULL UNIQUE CHECK (role_name = 'wh_{{TAG}}_d_' || id::text),
    name text NULL CHECK (pg_catalog.octet_length(name) <= 4096),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version >= 1)
);
CREATE INDEX devices_user ON wormhole_data.devices(user_id);

-- Private trigger, not an API entry point. Clients cannot execute it or update
-- the underlying table. Login-name immutability also applies to administrators.
CREATE FUNCTION wormhole_data.immutable_login_name() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
SET statement_timeout = '15s'
AS $immutable$
BEGIN
    IF NEW.login_name IS DISTINCT FROM OLD.login_name THEN
        RAISE EXCEPTION 'Login name is immutable' USING ERRCODE = '22023';
    END IF;
    RETURN NEW;
END
$immutable$;
CREATE TRIGGER users_immutable_login BEFORE UPDATE ON wormhole_data.users
FOR EACH ROW EXECUTE FUNCTION wormhole_data.immutable_login_name();

REVOKE ALL ON ALL TABLES IN SCHEMA wormhole_data FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA wormhole_data FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA wormhole_data, wormhole_api_v1 FROM PUBLIC;
COMMIT;
