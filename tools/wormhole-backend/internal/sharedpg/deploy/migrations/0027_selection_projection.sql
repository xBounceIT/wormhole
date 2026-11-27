-- Version 27: private signed selection snapshot projection.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>26 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Private composition helper: public release must authorize the connection first.
CREATE FUNCTION wormhole_data.selection_record(p_kind text,p_subject uuid,p_user uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,subject_id uuid,epoch bigint,change_seq bigint,
    record jsonb,boundary_id uuid,row_version bigint,seal_suite smallint,seal_signer_key_id uuid,
    seal_signer_key_version integer,seal_capability_id uuid,seal bytea,
    author_id uuid,signing_key_id uuid,signing_key_version integer,state_sequence bigint,signed_state bytea,
    suite smallint,public_key bytea,cert_signer_key_id uuid,cert_signer_key_version integer,cert_revision bigint,cert_signature bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $selection$
DECLARE meta record; item record; author record;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('slot','slot-value','override')
       OR p_subject IS NULL OR p_subject='00000000-0000-0000-0000-000000000000'::uuid
       OR (p_kind='slot' AND p_user IS NOT NULL)
       OR (p_kind<>'slot' AND (p_user IS NULL OR p_user='00000000-0000-0000-0000-000000000000'::uuid))
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid selection request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN
        RAISE EXCEPTION 'Catalog snapshot changed' USING ERRCODE='WH013';
    END IF;
    IF p_kind='slot' THEN
        SELECT s.boundary_id,s.row_version,s.seal_suite,s.seal_signer_key_id,s.seal_signer_key_version,s.seal_capability_id,s.seal,
            jsonb_build_object('id',s.id,'name',s.name,'protocol',s.protocol,'defaultCredentialId',COALESCE(s.default_credential_id::text,''),'allowSelfService',s.allow_self_service,'deleted',s.deleted) AS body
        INTO item FROM wormhole_data.credential_slots s WHERE s.id=p_subject;
    ELSIF p_kind='slot-value' THEN
        SELECT s.boundary_id,s.row_version,s.seal_suite,s.seal_signer_key_id,s.seal_signer_key_version,s.seal_capability_id,s.seal,
            jsonb_build_object('id',s.id,'slotId',s.slot_id,'userId',s.user_id,'credentialId',COALESCE(s.credential_id::text,''),'deleted',s.deleted) AS body
        INTO item FROM wormhole_data.credential_slot_values s WHERE s.slot_id=p_subject AND s.user_id=p_user;
    ELSIF p_kind='override' THEN
        SELECT s.boundary_id,s.row_version,s.seal_suite,s.seal_signer_key_id,s.seal_signer_key_version,s.seal_capability_id,s.seal,
            jsonb_build_object('nodeId',s.node_id,'userId',s.user_id,'credentialId',COALESCE(s.credential_id::text,''),'deleted',s.deleted) AS body
        INTO item FROM wormhole_data.user_node_overrides s WHERE s.node_id=p_subject AND s.user_id=p_user;
    END IF;
    IF NOT FOUND THEN RAISE EXCEPTION 'Selection metadata unavailable' USING ERRCODE='WH018'; END IF;
    IF octet_length(item.body::text)>16384 THEN RAISE EXCEPTION 'Selection projection is too large' USING ERRCODE='54000'; END IF;
    SELECT * INTO STRICT author FROM wormhole_data.node_author_material(item.seal_signer_key_id,item.seal_signer_key_version);
    -- Preserve tombstones and signed revocations for native monotonic floors.
    RETURN QUERY SELECT meta.workspace_id,p_subject,meta.epoch,meta.change_seq,item.body,
        item.boundary_id,item.row_version,item.seal_suite,item.seal_signer_key_id,item.seal_signer_key_version,item.seal_capability_id,item.seal,
        author.author_id,author.signing_key_id,author.signing_key_version,author.state_sequence,author.signed_state,
        author.suite,author.public_key,author.cert_signer_key_id,author.cert_signer_key_version,author.cert_revision,author.cert_signature;
END
$selection$;
REVOKE ALL ON FUNCTION wormhole_data.selection_record(text,uuid,uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=27 WHERE singleton;
COMMIT;
