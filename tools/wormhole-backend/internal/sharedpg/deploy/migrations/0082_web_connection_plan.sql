-- Version 82: public routing plans for HTTP(S) with retained account pins.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>81 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

{{WEB_CONNECTION_DEFINITIONS}}
CREATE FUNCTION wormhole_api_v1.web_connection_plan(p_capability bytea,p_node uuid)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $plan$
    SELECT * FROM wormhole_api_v1.connection_plan_path(p_capability,p_node,'web');
$plan$;
REVOKE ALL ON FUNCTION wormhole_api_v1.web_connection_plan(bytea,uuid)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.web_connection_plan(bytea,uuid) TO wh_{{TAG}}_user;

{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=82 WHERE singleton;
COMMIT;
