-- Version 42: enrolled author proofs and final recipient key selection.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>41 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Public certificates only. Private helper; the caller owns source authorization.
CREATE FUNCTION wormhole_data.enrolled_author_certificate(p_user uuid,p_signer uuid,p_version integer)
RETURNS bytea LANGUAGE sql STABLE STRICT SET search_path=pg_catalog,pg_temp AS $enrolled$
    SELECT e.certificate FROM wormhole_data.user_enrollments e
    WHERE e.user_id=p_user AND e.signing_key_id=p_signer AND e.signing_key_version=p_version;
$enrolled$;
REVOKE ALL ON FUNCTION wormhole_data.enrolled_author_certificate(uuid,uuid,integer)
FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;

CREATE OR REPLACE FUNCTION wormhole_data.catalog_projection_wire(p jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE STRICT SET search_path=pg_catalog,pg_temp AS $wire$
DECLARE result jsonb; certificate bytea; i integer;
BEGIN
    certificate:=wormhole_data.enrolled_author_certificate((p->>'author_id')::uuid,(p->>'signing_key_id')::uuid,(p->>'signing_key_version')::integer);
    result:=jsonb_build_array(p->>'workspace_id',
        COALESCE(p->>'credential_id',p->>'subject_id'),
        p->>'epoch',
        p->>'change_seq',
        p->>'record',
        p->>'boundary_id',
        p->>'row_version',
        p->>'seal_suite',
        p->>'seal_signer_key_id',
        p->>'seal_signer_key_version',
        p->>'seal_capability_id',
        substr(p->>'seal',3),
        p->>'author_id',
        p->>'signing_key_id',
        p->>'signing_key_version',
        p->>'state_sequence',
        substr(p->>'signed_state',3),
        p->>'suite',
        substr(p->>'public_key',3),
        p->>'cert_signer_key_id',
        p->>'cert_signer_key_version',
        p->>'cert_revision',
        substr(p->>'cert_signature',3));
    -- Direct organisation certificates and delegated chains are exclusive.
    IF certificate IS NOT NULL THEN
        FOR i IN 17..22 LOOP result:=jsonb_set(result,ARRAY[i::text],'null'::jsonb); END LOOP;
    END IF;
    RETURN result||jsonb_build_array(encode(certificate,'hex'));
END
$wire$;

CREATE OR REPLACE FUNCTION wormhole_data.key_copy_wire(p jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE STRICT SET search_path=pg_catalog,pg_temp AS $wire$
DECLARE result jsonb; certificate bytea; i integer;
BEGIN
    certificate:=wormhole_data.enrolled_author_certificate((p->>'author_id')::uuid,(p->>'issuer_key_id')::uuid,(p->>'issuer_key_version')::integer);
    result:=jsonb_build_array(p->>'workspace_id',
        p->>'epoch',
        p->>'change_seq',
        p->>'key_id',
        p->>'key_version',
        p->>'holder_key_id',
        p->>'holder_key_version',
        p->>'suite',
        substr(p->>'enc',3),
        substr(p->>'ciphertext',3),
        p->>'issuer_key_id',
        p->>'issuer_key_version',
        substr(p->>'signature',3),
        p->>'issuer_kind',
        p->>'author_id',
        p->>'state_sequence',
        substr(p->>'signed_state',3),
        p->>'cert_suite',
        substr(p->>'cert_public',3),
        p->>'cert_signer_id',
        p->>'cert_signer_version',
        p->>'cert_revision',
        substr(p->>'cert_signature',3));
    -- Direct organisation certificates and delegated chains are exclusive.
    IF certificate IS NOT NULL THEN
        FOR i IN 17..22 LOOP result:=jsonb_set(result,ARRAY[i::text],'null'::jsonb); END LOOP;
    END IF;
    RETURN result||jsonb_build_array(encode(certificate,'hex'));
END
$wire$;

{{CONNECTION_SNAPSHOT_DEFINITION}}
{{CREDENTIAL_RELEASE_DEFINITION}}
DROP FUNCTION wormhole_api_v1.node_author(bytea,uuid,bigint,bigint);
CREATE FUNCTION wormhole_api_v1.node_author(p_capability bytea,p_node uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,node_id uuid,author_id uuid,epoch bigint,change_seq bigint,
    signing_key_id uuid,signing_key_version integer,state_sequence bigint,signed_state bytea,
    suite smallint,public_key bytea,cert_signer_key_id uuid,cert_signer_key_version integer,
    cert_revision bigint,cert_signature bytea,enrollment_certificate bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $author$
DECLARE identity record; meta record; item record; material record; certificate bytea;
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
    SELECT * INTO STRICT material FROM wormhole_data.node_author_material(item.seal_signer_key_id,item.seal_signer_key_version);
    certificate:=wormhole_data.enrolled_author_certificate(material.author_id,material.signing_key_id,material.signing_key_version);
    RETURN QUERY SELECT meta.workspace_id,p_node,material.author_id,meta.epoch,meta.change_seq,
        material.signing_key_id,material.signing_key_version,material.state_sequence,material.signed_state,
        CASE WHEN certificate IS NULL THEN material.suite END,
        CASE WHEN certificate IS NULL THEN material.public_key END,
        CASE WHEN certificate IS NULL THEN material.cert_signer_key_id END,
        CASE WHEN certificate IS NULL THEN material.cert_signer_key_version END,
        CASE WHEN certificate IS NULL THEN material.cert_revision END,
        CASE WHEN certificate IS NULL THEN material.cert_signature END,certificate;
END
$author$;
REVOKE ALL ON FUNCTION wormhole_data.catalog_projection_wire(jsonb),wormhole_data.key_copy_wire(jsonb),
wormhole_data.connection_snapshot(uuid,uuid,bigint,bigint),wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint)
FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_api_v1.node_author(bytea,uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.node_author(bytea,uuid,bigint,bigint) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=42 WHERE singleton;
COMMIT;
