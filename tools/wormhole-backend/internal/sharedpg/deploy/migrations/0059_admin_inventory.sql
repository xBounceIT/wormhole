-- Version 59: bounded administrative account, device, session and audit pages.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $migration_lock$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration is already in progress' USING ERRCODE='55P03';
    END IF;
END
$migration_lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>58 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE INDEX admin_sessions_timeline ON wormhole_data.sessions(started_at,id);

CREATE FUNCTION wormhole_api_v1.admin_inventory(p_capability bytea,p_kind text,p_after uuid,p_before timestamptz)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET timezone='UTC' AS $inventory$
DECLARE actor record; result jsonb;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('accounts','devices','sessions','audit')
        OR (p_before IS NOT NULL AND (p_after IS NULL OR NOT pg_catalog.isfinite(p_before)))
        OR (p_kind IN ('sessions','audit') AND ((p_after IS NULL)<>(p_before IS NULL)))
        OR (p_kind IN ('accounts','devices') AND p_before IS NOT NULL)
        OR p_after='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid administrative page request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    -- require_device holds a shared lock on the current account. Re-read the
    -- role under that lock instead of relying on the cached admission flag.
    IF NOT EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin AND NOT u.disabled)
        OR NOT EXISTS (SELECT FROM wormhole_data.current_connection_tls() tls WHERE tls.ssl) THEN
        RETURN QUERY SELECT '{{WORKSPACE_ID}}'::uuid,actor.user_id,actor.device_id,NULL::jsonb;
        RETURN;
    END IF;
    CASE p_kind
    WHEN 'accounts' THEN
        SELECT jsonb_agg(jsonb_build_array(x.id,x.login_name,coalesce(x.name,''),x.is_admin::text,x.disabled::text) ORDER BY x.id)
        INTO result FROM (
            SELECT u.id,u.login_name,u.name,u.is_admin,u.disabled FROM wormhole_data.users u
            WHERE p_after IS NULL OR u.id>p_after ORDER BY u.id LIMIT 26
        ) x;
    WHEN 'devices' THEN
        SELECT jsonb_agg(jsonb_build_array(x.id,x.login_name,coalesce(x.name,''),x.status,
            to_char(x.created_at,'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY x.id)
        INTO result FROM (
            SELECT d.id,u.login_name,d.name,d.status,d.created_at FROM wormhole_data.devices d
            JOIN wormhole_data.users u ON u.id=d.user_id
            WHERE p_after IS NULL OR d.id>p_after ORDER BY d.id LIMIT 26
        ) x;
    WHEN 'sessions' THEN
        SELECT jsonb_agg(jsonb_build_array(x.id,x.login_name,x.device_id,x.app_version,
            to_char(x.started_at,'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),x.ssl::text) ORDER BY x.started_at DESC,x.id DESC)
        INTO result FROM (
            SELECT s.id,u.login_name,s.device_id,s.app_version,s.started_at,s.ssl FROM wormhole_data.sessions s
            JOIN wormhole_data.users u ON u.id=s.user_id
            WHERE p_before IS NULL OR (s.started_at,s.id)<(p_before,p_after)
            ORDER BY s.started_at DESC,s.id DESC LIMIT 26
        ) x;
    WHEN 'audit' THEN
        SELECT jsonb_agg(jsonb_build_array(x.id,x.user_id,x.session_id,x.login_name,x.action,x.outcome,x.source,
            to_char(x.at,'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY x.at DESC,x.id DESC)
        INTO result FROM (
            SELECT a.at,a.id,a.user_id,a.session_id,u.login_name,
                CASE WHEN a.action ~ '^[a-z][a-z0-9_-]{0,63}$' THEN a.action ELSE 'other' END AS action,
                CASE WHEN a.outcome ~ '^[a-z][a-z0-9_-]{0,63}$' THEN a.outcome ELSE 'other' END AS outcome,a.source
            FROM wormhole_data.audit_log a LEFT JOIN wormhole_data.users u ON u.id=a.user_id
            WHERE p_before IS NULL OR (a.at,a.id)<(p_before,p_after)
            ORDER BY a.at DESC,a.id DESC LIMIT 26
        ) x;
    END CASE;
    RETURN QUERY SELECT '{{WORKSPACE_ID}}'::uuid,actor.user_id,actor.device_id,coalesce(result,'[]'::jsonb);
END
$inventory$;

{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_api_v1.admin_inventory(bytea,text,uuid,timestamptz)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.admin_inventory(bytea,text,uuid,timestamptz) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=59 WHERE singleton;
COMMIT;
