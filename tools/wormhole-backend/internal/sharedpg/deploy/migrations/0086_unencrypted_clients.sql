-- Version 86: live workspace devices with unencrypted PostgreSQL connections.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>85 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- The NOLOGIN observer already has pg_read_all_stats. Expose only this
-- workspace's registered device IDs and their oldest live plaintext socket.
GRANT SELECT(id,role_name) ON wormhole_data.devices TO wh_{{TAG}}_observer;
GRANT SELECT(device_id,role_oid) ON wormhole_data.device_confirmations TO wh_{{TAG}}_observer;
GRANT CREATE ON SCHEMA wormhole_data TO wh_{{TAG}}_observer;
SET LOCAL ROLE wh_{{TAG}}_observer;
CREATE FUNCTION wormhole_data.live_unencrypted_devices(p_after uuid)
RETURNS TABLE(device_id uuid,connected_since timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $live$
    SELECT d.id,min(a.backend_start)
    FROM pg_catalog.pg_stat_activity a
    JOIN pg_catalog.pg_stat_ssl tls ON tls.pid=a.pid AND NOT tls.ssl
    LEFT JOIN pg_catalog.pg_stat_gssapi g ON g.pid=a.pid
    JOIN pg_catalog.pg_roles r ON r.oid=a.usesysid
    JOIN wormhole_data.devices d ON d.role_name=r.rolname::text
    LEFT JOIN wormhole_data.device_confirmations c ON c.device_id=d.id
    WHERE a.datname=current_database() AND a.backend_type='client backend'
      AND a.client_addr IS NOT NULL AND g.encrypted IS NOT TRUE
      AND (c.device_id IS NULL OR c.role_oid=r.oid)
      AND (p_after IS NULL OR d.id>p_after)
    GROUP BY d.id ORDER BY d.id LIMIT 26
$live$;
REVOKE ALL ON FUNCTION wormhole_data.live_unencrypted_devices(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_data.live_unencrypted_devices(uuid) TO wh_{{TAG}}_owner;

SET LOCAL ROLE wh_{{TAG}}_owner;
REVOKE CREATE ON SCHEMA wormhole_data FROM wh_{{TAG}}_observer;
CREATE FUNCTION wormhole_api_v1.unencrypted_clients(p_capability bytea,p_after uuid)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET timezone='UTC' AS $clients$
DECLARE actor record; result jsonb;
BEGIN
    IF p_after='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid device cursor' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin AND NOT u.disabled)
        OR NOT EXISTS (SELECT FROM wormhole_data.current_connection_tls() tls WHERE tls.ssl) THEN
        RETURN QUERY SELECT '{{WORKSPACE_ID}}'::uuid,actor.user_id,actor.device_id,NULL::jsonb;
        RETURN;
    END IF;
    SELECT jsonb_agg(jsonb_build_array(d.id,u.login_name,coalesce(d.name,''),d.status,
        to_char(l.connected_since,'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY d.id)
    INTO result FROM wormhole_data.live_unencrypted_devices(p_after) l
    JOIN wormhole_data.devices d ON d.id=l.device_id
    JOIN wormhole_data.users u ON u.id=d.user_id;
    RETURN QUERY SELECT '{{WORKSPACE_ID}}'::uuid,actor.user_id,actor.device_id,coalesce(result,'[]'::jsonb);
END
$clients$;
REVOKE ALL ON FUNCTION wormhole_api_v1.unencrypted_clients(bytea,uuid)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.unencrypted_clients(bytea,uuid) TO wh_{{TAG}}_user;

{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=86 WHERE singleton;
COMMIT;
