-- Version 2: authenticated, audited session admission. No runtime DDL.
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
SET LOCAL timezone = 'UTC';
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id <> '{{WORKSPACE_ID}}'::uuid
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 1 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE = '55000';
    END IF;
END
$guard$;

-- The API owner cannot see another role's SSL statistics. Keep the required
-- monitoring privilege on a separate NOLOGIN role, exposed only by a fixed,
-- argument-free helper for the current backend. This step requires a DBA.
SET LOCAL ROLE NONE;
CREATE ROLE wh_{{TAG}}_observer NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT pg_read_all_stats TO wh_{{TAG}}_observer WITH INHERIT TRUE, SET FALSE;
GRANT USAGE,CREATE ON SCHEMA wormhole_data TO wh_{{TAG}}_observer;
CREATE FUNCTION wormhole_data.current_connection_tls()
RETURNS TABLE(ssl boolean,version text,client_dn text)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $tls$
    SELECT s.ssl,s.version,s.client_dn FROM pg_catalog.pg_stat_ssl s
    WHERE s.pid=pg_catalog.pg_backend_pid()
$tls$;
ALTER FUNCTION wormhole_data.current_connection_tls() OWNER TO wh_{{TAG}}_observer;
REVOKE CREATE ON SCHEMA wormhole_data FROM wh_{{TAG}}_observer;
REVOKE ALL ON FUNCTION wormhole_data.current_connection_tls() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_data.current_connection_tls() TO wh_{{TAG}}_owner;
SET LOCAL ROLE wh_{{TAG}}_owner;

ALTER TABLE wormhole_data.workspace_meta ADD COLUMN require_tls boolean NOT NULL DEFAULT true;
CREATE TABLE wormhole_data.sessions (
    id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    device_id uuid NOT NULL REFERENCES wormhole_data.devices(id),
    session_role text NOT NULL,
    backend_pid integer NOT NULL,
    ssl boolean NOT NULL,
    tls_version text NULL,
    client_dn text NULL,
    client_addr inet NULL,
    app_version text NOT NULL CHECK (pg_catalog.octet_length(app_version) BETWEEN 1 AND 64),
    started_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    last_seen timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
CREATE INDEX sessions_device ON wormhole_data.sessions(device_id);

CREATE TABLE wormhole_data.audit_log (
    id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    session_role text NOT NULL,
    source text NOT NULL CHECK (source IN ('ui','mcp')),
    action text NOT NULL,
    outcome text NOT NULL,
    client_addr inet NULL,
    app_version text NOT NULL,
    prev_hash bytea NULL,
    row_hash bytea NULL,
    PRIMARY KEY(at,id)
) PARTITION BY RANGE(at);
-- Provision this and the next UTC month. Future partition maintenance is an
-- explicit deployment operation; missing partitions must fail admission closed.
DO $partitions$
DECLARE month_offset integer; month_start timestamptz; month_end timestamptz;
BEGIN
    FOR month_offset IN 0..1 LOOP
        month_start := pg_catalog.date_trunc('month',pg_catalog.clock_timestamp()) + pg_catalog.make_interval(months => month_offset);
        month_end := month_start + interval '1 month';
        EXECUTE pg_catalog.format(
            'CREATE TABLE wormhole_data.audit_log_%s PARTITION OF wormhole_data.audit_log FOR VALUES FROM (%L) TO (%L)',
            pg_catalog.to_char(month_start,'YYYYMM'),month_start,month_end);
    END LOOP;
END
$partitions$;

CREATE FUNCTION wormhole_data.require_device()
RETURNS TABLE(user_id uuid,device_id uuid,is_admin boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
SET statement_timeout = '15s'
AS $identity$
BEGIN
    -- A retained repeatable-read snapshot must not bypass later revocation.
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Unsupported workspace transaction isolation' USING ERRCODE = 'WH006';
    END IF;
    RETURN QUERY SELECT u.id,d.id,u.is_admin
      FROM wormhole_data.devices d JOIN wormhole_data.users u ON u.id=d.user_id
      WHERE d.role_name=session_user AND d.status='active' AND NOT u.disabled;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace account or device unavailable' USING ERRCODE = 'WH001';
    END IF;
END
$identity$;

CREATE FUNCTION wormhole_api_v1.session_start(p_api integer,p_app_version text,p_source text DEFAULT 'ui')
RETURNS TABLE(session_id uuid,workspace_id uuid,user_id uuid,device_id uuid,is_admin boolean,
              min_api integer,max_api integer,epoch bigint,change_seq bigint,signed_profile bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
SET statement_timeout = '15s'
SET timezone = 'UTC'
AS $admit$
DECLARE identity record; meta record; tls record; admitted uuid;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device();
    IF p_api IS NULL OR p_app_version IS NULL OR pg_catalog.octet_length(p_app_version) NOT BETWEEN 1 AND 64
       OR p_app_version !~ '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$'
       OR p_app_version ~ '[[:cntrl:]]' OR p_source IS NULL OR p_source NOT IN ('ui','mcp') THEN
        RAISE EXCEPTION 'Invalid workspace session request' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton;
    IF meta.state <> 'ready' OR meta.signed_profile IS NULL THEN
        RAISE EXCEPTION 'Workspace provisioning is incomplete' USING ERRCODE = 'WH002';
    END IF;
    IF p_api NOT BETWEEN meta.min_api AND meta.max_api THEN
        RAISE EXCEPTION 'Unsupported workspace API version' USING ERRCODE = 'WH004';
    END IF;
    SELECT * INTO STRICT tls FROM wormhole_data.current_connection_tls();
    IF meta.require_tls AND tls.ssl IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'Workspace requires TLS' USING ERRCODE = 'WH003';
    END IF;
    INSERT INTO wormhole_data.sessions(user_id,device_id,session_role,backend_pid,ssl,tls_version,client_dn,client_addr,app_version)
    VALUES(identity.user_id,identity.device_id,session_user,pg_catalog.pg_backend_pid(),
           COALESCE(tls.ssl,false),tls.version,tls.client_dn,pg_catalog.inet_client_addr(),p_app_version)
    RETURNING id INTO admitted;
    BEGIN
        INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
        VALUES(identity.user_id,admitted,session_user,p_source,'login','success',pg_catalog.inet_client_addr(),p_app_version);
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE = 'WH005';
    END;
    RETURN QUERY SELECT admitted,meta.workspace_id,identity.user_id,identity.device_id,identity.is_admin,
                        meta.min_api,meta.max_api,meta.epoch,meta.change_seq,meta.signed_profile;
END
$admit$;

REVOKE EXECUTE ON FUNCTION wormhole_data.require_device(),wormhole_api_v1.session_start(integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.session_start(integer,text,text) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=2 WHERE singleton;
COMMIT;
