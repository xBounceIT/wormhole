-- Version 30: private signed boundary manifest storage/projection.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>29 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Body is the complete canonical signed native document. Header fields are
-- duplicated for versioned SQL access and MUST match after native decoding.
CREATE TABLE wormhole_data.boundary_manifests (
    boundary_id uuid PRIMARY KEY REFERENCES wormhole_data.boundaries(id),
    version bigint NOT NULL DEFAULT 1 CHECK(version>=1),
    body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 8192),
    signer_key_id uuid NOT NULL,
    signer_key_version integer NOT NULL,
    signature bytea NOT NULL CHECK(octet_length(signature)=64),
    FOREIGN KEY(signer_key_id,signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version)
);
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.boundary_manifests
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();

-- Private release composition reader. It carries no data/key/ciphertext and
-- cannot confer permission to query an arbitrary boundary from the public API.
CREATE FUNCTION wormhole_data.boundary_manifest(p_boundary uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,boundary_id uuid,epoch bigint,change_seq bigint,
    version bigint,body bytea,signer_key_id uuid,signer_key_version integer,signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $manifest$
DECLARE meta record; item wormhole_data.boundary_manifests;
BEGIN
    IF p_boundary IS NULL OR p_boundary='00000000-0000-0000-0000-000000000000'::uuid
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid boundary manifest request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004'; END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN RAISE EXCEPTION 'Catalog snapshot changed' USING ERRCODE='WH013'; END IF;
    SELECT m.* INTO item FROM wormhole_data.boundary_manifests m WHERE m.boundary_id=p_boundary;
    IF NOT FOUND THEN RAISE EXCEPTION 'Boundary manifest unavailable' USING ERRCODE='WH010'; END IF;
    -- Inactive signed documents are deliberately returned for native high-water
    -- observation even when the mutable boundary row is marked deleted.
    RETURN QUERY SELECT meta.workspace_id,item.boundary_id,meta.epoch,meta.change_seq,
        item.version,item.body,item.signer_key_id,item.signer_key_version,item.signature;
END
$manifest$;
REVOKE ALL ON TABLE wormhole_data.boundary_manifests FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_data.boundary_manifest(uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=30 WHERE singleton;
COMMIT;
