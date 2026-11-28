-- Version 49: audited, bounded export of persistent workspace recovery data.
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
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>48 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Existing schema-48 deployments checked one exact release in this function.
{{ADMIN_RECOVERY_MATERIAL_DEFINITION}}

{{EXPORT_WORKSPACE_DEFINITION}}

REVOKE ALL ON FUNCTION wormhole_api_v1.export_workspace(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.export_workspace(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea)
    TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=49 WHERE singleton;
COMMIT;
