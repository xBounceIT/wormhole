-- Version 50: import a recovery archive into an empty, matching deployment.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>49 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Recovery custody survives restoration. The retired source invite does not.
ALTER TABLE wormhole_data.workspace_bootstrap ALTER COLUMN invite_id DROP NOT NULL;
CREATE TABLE wormhole_data.workspace_restore (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    archive_digest bytea NOT NULL CHECK(octet_length(archive_digest)=32)
);

{{RESTORE_WORKSPACE_DEFINITION}}

REVOKE ALL ON TABLE wormhole_data.workspace_restore FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.restore_workspace(text,text) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.restore_workspace(text,text) TO wh_{{TAG}}_deployer;
UPDATE wormhole_data.workspace_meta SET schema_version=50 WHERE singleton;
COMMIT;
