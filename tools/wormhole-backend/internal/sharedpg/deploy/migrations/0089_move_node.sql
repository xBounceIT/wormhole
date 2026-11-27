-- Version 89: signed tree moves with serialized ancestry and inherited authority checks.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>88 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

{{NODE_MOVE_BINDINGS}}

{{READ_NODE_EDIT}}

-- Scalar edits and moves protect the same stored per-user selections.
CREATE OR REPLACE FUNCTION wormhole_data.node_edit_bindings(p_actor uuid,p_root uuid,p_epoch bigint,p_sequence bigint)
RETURNS TABLE(binding text,digest bytea,can_reveal boolean)
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $bindings$
    SELECT * FROM wormhole_data.node_edit_bindings(p_actor,p_root,p_epoch,p_sequence,NULL::jsonb)
$bindings$;

CREATE FUNCTION wormhole_data.move_parent_chain(p_parent uuid) RETURNS uuid[]
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $chain$
DECLARE chain uuid[]:='{}'; item record;
BEGIN
    WHILE p_parent IS NOT NULL LOOP
        IF p_parent=ANY(chain) OR cardinality(chain)>=128 THEN
            RAISE EXCEPTION 'Invalid folder ancestry' USING ERRCODE='WH025';
        END IF;
        SELECT parent_id,kind,seal,encrypted_metadata INTO STRICT item FROM wormhole_data.nodes WHERE id=p_parent FOR SHARE NOWAIT;
        IF item.kind<>0 OR item.seal IS NULL OR item.encrypted_metadata IS NOT NULL THEN
            RAISE EXCEPTION 'Folder unavailable' USING ERRCODE='WH025';
        END IF;
        chain:=array_append(chain,p_parent); p_parent:=item.parent_id;
    END LOOP;
    RETURN chain;
END
$chain$;
-- Include direct grants on the moved root so redundant ancestor grants do not
-- turn ordinary Write into an administrative operation. Retain group subjects
-- even when their memberships are temporarily empty.
CREATE FUNCTION wormhole_data.move_grants(p_chain uuid[]) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $grants$
    SELECT COALESCE(jsonb_object_agg(subject,mask),'{}'::jsonb) FROM (
        SELECT CASE WHEN user_id IS NULL THEN 'g/'||group_id ELSE 'u/'||user_id END subject,bit_or(permissions) mask
        FROM wormhole_data.grants WHERE node_id=ANY(p_chain) GROUP BY 1
    ) subjects
$grants$;
REVOKE ALL ON FUNCTION wormhole_data.move_parent_chain(uuid),wormhole_data.move_grants(uuid[]) FROM PUBLIC;

CREATE FUNCTION wormhole_api_v1.move_node(p_capability bytea,p_node uuid,p_epoch bigint,p_sequence bigint,p_revision bigint,
    p_metadata jsonb,p_signer uuid,p_signer_version integer,p_seal bytea,p_fields_seal bytea,p_policy bytea,p_state bytea)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $move$
DECLARE actor record; meta wormhole_data.workspace_meta; original wormhole_data.nodes; fields wormhole_data.node_secret_manifests;
    has_fields boolean; public_key bytea; destination uuid; source_chain uuid[]; target_chain uuid[];
    actor_mask integer; previous_masks jsonb; previous jsonb; height integer; visited integer; session_row record; receipt text;
BEGIN
    IF p_node IS NULL OR p_epoch IS NULL OR p_epoch<1 OR p_sequence IS NULL OR p_sequence<0 OR
       p_revision IS NULL OR p_revision NOT BETWEEN 1 AND 9223372036854775806 OR jsonb_typeof(p_metadata) IS DISTINCT FROM 'object' OR
       octet_length(p_metadata::text)>524288 OR p_signer IS NULL OR p_signer_version IS NULL OR p_signer_version<1 OR
       octet_length(p_seal) IS DISTINCT FROM 64 OR octet_length(p_fields_seal)<>64 OR
       octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_state) IS DISTINCT FROM 32 THEN
       RAISE EXCEPTION 'Invalid move' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT pg_try_advisory_xact_lock(hashtextextended('wormhole/move/'||meta.workspace_id::text,0)) THEN RETURN 'busy'; END IF;
    IF meta.state<>'ready' OR meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 OR
       (meta.epoch,meta.change_seq)<>(p_epoch,p_sequence) OR sha256(meta.signed_profile) IS DISTINCT FROM p_policy OR
       NOT EXISTS(SELECT FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id AND sha256(s.signed_state)=p_state
           AND convert_from(s.signed_state,'UTF8')::jsonb->'active'='true'::jsonb) THEN RETURN 'stale'; END IF;
    SELECT * INTO STRICT original FROM wormhole_data.nodes WHERE id=p_node FOR UPDATE NOWAIT;
    actor_mask:=wormhole_data.effective_permissions(actor.user_id,p_node);
    IF (actor_mask&5)<>5 OR original.seal IS NULL OR original.encrypted_metadata IS NOT NULL THEN RETURN 'unavailable'; END IF;
    IF original.row_version<>p_revision THEN RETURN 'stale'; END IF;
    IF NOT (p_metadata ? 'parentId') OR NOT wormhole_data.resolver_node_valid(p_metadata) OR
       (p_metadata-'parentId') IS DISTINCT FROM (wormhole_data.node_metadata(original)-'parentId') THEN RETURN 'unavailable'; END IF;
    destination:=(p_metadata->>'parentId')::uuid;
    IF destination IS NOT DISTINCT FROM original.parent_id OR destination=p_node THEN RETURN 'unavailable'; END IF;
    target_chain:=wormhole_data.move_parent_chain(destination);
    IF p_node=ANY(target_chain) OR (destination IS NOT NULL AND (wormhole_data.effective_permissions(actor.user_id,destination)&5)<>5)
        THEN RETURN 'unavailable'; END IF;
    source_chain:=array_prepend(p_node,wormhole_data.move_parent_chain(original.parent_id));
    target_chain:=array_prepend(p_node,target_chain);
    IF (SELECT array_agg(DISTINCT owner_user_id ORDER BY owner_user_id) FROM wormhole_data.nodes
        WHERE id=ANY(source_chain) AND owner_user_id IS NOT NULL) IS DISTINCT FROM
       (SELECT array_agg(DISTINCT owner_user_id ORDER BY owner_user_id) FROM wormhole_data.nodes
        WHERE id=ANY(target_chain) AND owner_user_id IS NOT NULL) THEN RETURN 'unavailable'; END IF;
    IF (actor_mask&16)=0 AND wormhole_data.move_grants(source_chain)<>wormhole_data.move_grants(target_chain) THEN RETURN 'unavailable'; END IF;
    SELECT * INTO fields FROM wormhole_data.node_secret_manifests WHERE node_id=p_node;
    has_fields:=FOUND;
    IF has_fields<>(p_fields_seal IS NOT NULL) OR (original.use_inline_password IS TRUE)<>EXISTS(
        SELECT FROM jsonb_array_elements(fields.fields) f WHERE f->>'field'='inlinePassword' AND (f->>'present')::boolean) OR
        (has_fields AND (fields.deleted OR (fields.row_version,fields.boundary_id)<>(p_revision,original.boundary_id))) THEN RETURN 'stale'; END IF;
{{NODE_EDIT_VERIFY_SEALS}}
    WITH RECURSIVE subtree(id,depth) AS (
        SELECT p_node,1 UNION ALL SELECT n.id,s.depth+1 FROM subtree s JOIN wormhole_data.nodes n ON n.parent_id=s.id WHERE s.depth<=128
    ), bounded AS (SELECT * FROM subtree LIMIT 8193)
    SELECT count(*),max(depth),jsonb_object_agg(id::text,wormhole_data.effective_permissions(actor.user_id,id))
        INTO visited,height,previous_masks FROM bounded;
    IF visited>8192 OR height+cardinality(target_chain)-1>128 THEN RETURN 'unavailable'; END IF;
    SELECT jsonb_object_agg(b.binding,encode(b.digest,'hex')) INTO previous
        FROM wormhole_data.node_edit_bindings(actor.user_id,p_node,p_epoch,p_sequence,previous_masks) b;
    UPDATE wormhole_data.nodes SET parent_id=destination,row_version=p_revision+1,seal_signer_key_id=p_signer,
        seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_seal WHERE id=p_node;
    IF has_fields THEN
        UPDATE wormhole_data.node_secret_manifests SET row_version=p_revision+1,seal_signer_key_id=p_signer,
            seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_fields_seal WHERE node_id=p_node;
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton;
    IF EXISTS(SELECT FROM wormhole_data.node_edit_bindings(actor.user_id,p_node,p_epoch,meta.change_seq,previous_masks) b
        WHERE previous->>b.binding IS DISTINCT FROM encode(b.digest,'hex') AND b.can_reveal IS NOT TRUE) THEN
        RAISE EXCEPTION 'Move requires Reveal' USING ERRCODE='42501';
    END IF;
    SELECT s.id,s.app_version INTO STRICT session_row FROM wormhole_data.device_admissions a JOIN wormhole_data.sessions s ON s.id=a.session_id
        WHERE a.device_id=actor.device_id AND s.user_id=actor.user_id;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,node_id)
        VALUES(actor.user_id,session_row.id,session_user,'ui','move_node','success',inet_client_addr(),session_row.app_version,p_node);
    -- Return the exact signed write once. A move to the root can remove the
    -- writer's inherited View, so an independent future edit read may be denied.
    SELECT jsonb_build_object('workspace',meta.workspace_id,'user',actor.user_id,'epoch',meta.epoch,'sequence',meta.change_seq,
        'metadata',wormhole_data.node_metadata(n),'boundary',n.boundary_id,'revision',n.row_version,
        'signer',n.seal_signer_key_id,'version',n.seal_signer_key_version,'seal',encode(n.seal,'hex'),
        'fields',f.fields,'fieldsSeal',encode(f.seal,'hex'))::text INTO STRICT receipt
        FROM wormhole_data.nodes n LEFT JOIN wormhole_data.node_secret_manifests f ON f.node_id=n.id
        WHERE n.id=p_node AND n.seal_suite=2 AND n.seal_capability_id IS NULL AND (f.node_id IS NULL OR
            (NOT f.deleted AND f.seal_suite=2 AND f.seal_capability_id IS NULL AND
            (f.boundary_id,f.row_version,f.seal_signer_key_id,f.seal_signer_key_version)=(n.boundary_id,n.row_version,n.seal_signer_key_id,n.seal_signer_key_version)));
    RETURN receipt;
EXCEPTION WHEN lock_not_available THEN RETURN 'busy';
    WHEN insufficient_privilege OR no_data_found OR program_limit_exceeded OR invalid_parameter_value OR
        SQLSTATE 'WH014' OR SQLSTATE 'WH016' OR SQLSTATE 'WH017' OR SQLSTATE 'WH018' OR SQLSTATE 'WH019' OR SQLSTATE 'WH025' THEN RETURN 'unavailable';
END
$move$;
REVOKE ALL ON FUNCTION wormhole_api_v1.move_node(bytea,uuid,bigint,bigint,bigint,jsonb,uuid,integer,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.move_node(bytea,uuid,bigint,bigint,bigint,jsonb,uuid,integer,bytea,bytea,bytea,bytea) TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=89 WHERE singleton;
COMMIT;
