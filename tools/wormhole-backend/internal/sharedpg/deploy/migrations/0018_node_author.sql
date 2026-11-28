-- Version 18: public author verification material for visible tree nodes.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>17 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Key/certificate/state changes must invalidate in-flight catalog verification.
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.keys
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.user_key_states
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();

CREATE FUNCTION wormhole_api_v1.node_author(p_capability bytea,p_node uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,node_id uuid,author_id uuid,epoch bigint,change_seq bigint,
    signing_key_id uuid,signing_key_version integer,state_sequence bigint,signed_state bytea,
    suite smallint,public_key bytea,cert_signer_key_id uuid,cert_signer_key_version integer,
    cert_revision bigint,cert_signature bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $author$
DECLARE identity record; meta record; item record; signing record; state record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid author request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN
        RAISE EXCEPTION 'Tree snapshot changed' USING ERRCODE='WH013';
    END IF;
    -- Return the same refusal for hidden and nonexistent nodes.
    SELECT n.* INTO item FROM wormhole_data.nodes n WHERE n.id=p_node;
    IF NOT FOUND THEN RAISE EXCEPTION 'Node metadata unavailable' USING ERRCODE='WH014'; END IF;
    IF (wormhole_data.effective_permissions(identity.user_id,p_node) & 1)=0 OR item.seal IS NULL THEN
        RAISE EXCEPTION 'Node metadata unavailable' USING ERRCODE='WH014';
    END IF;
    SELECT k.* INTO signing FROM wormhole_data.keys k
        WHERE k.key_id=item.seal_signer_key_id AND k.key_version=item.seal_signer_key_version;
    IF NOT FOUND OR signing.kind<>'user-sign' OR signing.owner_id IS NULL THEN
        RAISE EXCEPTION 'Author key state unavailable' USING ERRCODE='WH010';
    END IF;
    SELECT s.* INTO state FROM wormhole_data.user_key_states s WHERE s.user_id=signing.owner_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Author key state unavailable' USING ERRCODE='WH010'; END IF;
    workspace_id:=meta.workspace_id; node_id:=p_node; author_id:=signing.owner_id;
    epoch:=meta.epoch; change_seq:=meta.change_seq;
    signing_key_id:=signing.key_id; signing_key_version:=signing.key_version;
    state_sequence:=state.state_sequence; signed_state:=state.signed_state;
    -- Preserve signed revocations even if historical certificate material is
    -- missing. No account capsule or encrypted/private key material is returned.
    IF signing.suite=1 AND pg_catalog.octet_length(signing.public_key)=32
       AND signing.cert_signer_key_id IS NOT NULL AND signing.cert_signer_key_version IS NOT NULL
       AND signing.cert_revision IS NOT NULL AND pg_catalog.octet_length(signing.cert_signature)=64 THEN
        suite:=signing.suite; public_key:=signing.public_key;
        cert_signer_key_id:=signing.cert_signer_key_id; cert_signer_key_version:=signing.cert_signer_key_version;
        cert_revision:=signing.cert_revision; cert_signature:=signing.cert_signature;
    END IF;
    RETURN NEXT;
END
$author$;
REVOKE ALL ON FUNCTION wormhole_api_v1.node_author(bytea,uuid,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.node_author(bytea,uuid,bigint,bigint) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=18 WHERE singleton;
COMMIT;
