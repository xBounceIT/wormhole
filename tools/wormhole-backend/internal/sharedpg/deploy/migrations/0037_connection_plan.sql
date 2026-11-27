-- Version 37: authorized metadata-only connection planning.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>36 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- No SecretValues, KeyCopies, use tickets or audit issuance are read here.
-- The later audited release must independently resolve and authorize again.
{{CONNECTION_PLAN_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_api_v1.connection_plan(bytea,uuid) FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.connection_plan(bytea,uuid) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=37 WHERE singleton;
COMMIT;
