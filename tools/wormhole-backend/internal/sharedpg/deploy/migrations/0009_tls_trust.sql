-- Version 9: signed workspace TLS metadata. Provisioning writes as owner.
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
    IF NOT FOUND OR meta.workspace_id <> '{{WORKSPACE_ID}}'::uuid
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 8 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.workspace_meta
    ADD COLUMN tls_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN tls_bundle bytea,
    ADD CONSTRAINT workspace_tls_bundle_shape CHECK (
        (tls_sequence=0 AND tls_bundle IS NULL) OR
        (tls_sequence>0 AND tls_bundle IS NOT NULL AND pg_catalog.octet_length(tls_bundle) BETWEEN 1 AND 1048576)
    );

CREATE FUNCTION wormhole_api_v1.tls_trust_bundle(p_capability bytea)
RETURNS TABLE(workspace_id uuid,tls_sequence bigint,signed_bundle bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $tls$
DECLARE identity record; meta record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.tls_sequence=0 OR meta.tls_bundle IS NULL THEN
        RAISE EXCEPTION 'Workspace TLS metadata unavailable' USING ERRCODE='WH011';
    END IF;
    RETURN QUERY SELECT meta.workspace_id,meta.tls_sequence,meta.tls_bundle;
END
$tls$;

REVOKE ALL ON FUNCTION wormhole_api_v1.tls_trust_bundle(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.tls_trust_bundle(bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=9 WHERE singleton;
COMMIT;
