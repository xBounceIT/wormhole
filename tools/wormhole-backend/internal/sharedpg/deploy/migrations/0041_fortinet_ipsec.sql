-- Version 41: Fortinet IPsec signed tunnel metadata.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>40 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Extend the provider enum without changing records, signatures or permissions.
ALTER TABLE wormhole_data.tunnel_profiles DROP CONSTRAINT tunnel_profiles_kind_check;
ALTER TABLE wormhole_data.tunnel_profiles ADD CONSTRAINT tunnel_profiles_kind_check CHECK(kind BETWEEN 0 AND 9);
UPDATE wormhole_data.workspace_meta SET schema_version=41 WHERE singleton;
COMMIT;
