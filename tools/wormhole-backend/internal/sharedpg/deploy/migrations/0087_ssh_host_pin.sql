-- Version 87: change an SSH host pin and its signed leaf revision atomically.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>86 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.ssh_host_pin(p_capability bytea,p_node uuid,p_epoch bigint,p_sequence bigint,
    p_revision bigint,p_fingerprint text,p_signer uuid,p_signer_version integer,p_seal bytea,p_fields_seal bytea,p_policy bytea,p_state bytea)
RETURNS TABLE(status text,projection jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $pin$
DECLARE actor record; meta wormhole_data.workspace_meta; target wormhole_data.nodes; profile jsonb;
    fields wormhole_data.node_secret_manifests; has_fields boolean; session_row record; signed_account jsonb;
    writing boolean := p_fingerprint IS NOT NULL;
BEGIN
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid OR
        p_epoch IS NULL OR p_epoch<1 OR p_sequence IS NULL OR p_sequence<0 OR
        p_revision IS NULL OR p_revision NOT BETWEEN 1 AND 9223372036854775806 OR
        octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_state) IS DISTINCT FROM 32 OR
        (NOT writing AND num_nonnulls(p_signer,p_signer_version,p_seal,p_fields_seal)>0) OR
        (writing AND (octet_length(p_fingerprint)<>50 OR p_fingerprint COLLATE "C" !~ '^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$'
            OR p_signer IS NULL OR p_signer_version IS NULL OR p_signer_version<1 OR octet_length(p_seal) IS DISTINCT FROM 64
            OR octet_length(p_fields_seal)<>64)) THEN
        RAISE EXCEPTION 'Invalid SSH host confirmation' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    IF writing THEN
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    ELSE
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    END IF;
    SELECT convert_from(s.signed_state,'UTF8')::jsonb INTO signed_account
        FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id AND sha256(s.signed_state)=p_state;
    IF meta.state<>'ready' OR meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 OR
        sha256(meta.signed_profile) IS DISTINCT FROM p_policy OR signed_account->>'active' IS DISTINCT FROM 'true' OR
        (meta.epoch,meta.change_seq)<>(p_epoch,p_sequence) THEN
        RETURN QUERY SELECT 'stale'::text,NULL::jsonb; RETURN;
    END IF;
    SELECT * INTO target FROM wormhole_data.nodes WHERE id=p_node;
    IF NOT FOUND OR target.kind<>1 OR target.seal IS NULL OR target.encrypted_metadata IS NOT NULL OR
        (wormhole_data.effective_permissions(actor.user_id,p_node)&7)<>7 OR
        (wormhole_data.effective_boundary_permissions(actor.user_id,target.boundary_id)&2)<>2 THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb; RETURN;
    END IF;
    IF target.row_version<>p_revision THEN RETURN QUERY SELECT 'stale'::text,NULL::jsonb; RETURN; END IF;
    SELECT wormhole_data.resolve_chain(jsonb_agg(c.node ORDER BY c.depth)) INTO profile
        FROM wormhole_data.resolution_chain(p_node,p_epoch,p_sequence) c;
    IF COALESCE((profile->>'protocol')::int,-1) NOT IN (0,7) OR profile->>'hostKeyFingerprint'=p_fingerprint THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb; RETURN;
    END IF;
    SELECT * INTO fields FROM wormhole_data.node_secret_manifests WHERE node_id=p_node;
    has_fields:=FOUND;
    IF has_fields AND (fields.row_version,fields.boundary_id)<>(target.row_version,target.boundary_id) THEN
        RETURN QUERY SELECT 'stale'::text,NULL::jsonb; RETURN;
    END IF;
    IF NOT writing THEN
        projection:=NULL;
        IF has_fields THEN
            SELECT wormhole_data.catalog_projection_wire(to_jsonb(f)) INTO STRICT projection
              FROM wormhole_data.selection_record('node-fields',p_node,NULL,p_epoch,p_sequence) f;
        END IF;
        status:='ready'; RETURN NEXT; RETURN;
    END IF;
    IF NOT EXISTS(SELECT FROM wormhole_data.user_enrollments e JOIN wormhole_data.keys k
            ON (k.key_id,k.key_version)=(e.signing_key_id,e.signing_key_version)
            WHERE e.user_id=actor.user_id AND (k.key_id,k.key_version)=(p_signer,p_signer_version)
            AND k.owner_id=actor.user_id AND k.kind='user-sign' AND k.status='active') OR has_fields<>(p_fields_seal IS NOT NULL) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb; RETURN;
    END IF;
    UPDATE wormhole_data.nodes SET ssh_known_host_fingerprint=p_fingerprint,row_version=p_revision+1,
        seal_signer_key_id=p_signer,seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_seal WHERE id=p_node;
    IF has_fields THEN
        UPDATE wormhole_data.node_secret_manifests SET row_version=p_revision+1,
            seal_signer_key_id=p_signer,seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_fields_seal WHERE node_id=p_node;
    END IF;
    SELECT s.id,s.app_version INTO STRICT session_row FROM wormhole_data.device_admissions a JOIN wormhole_data.sessions s ON s.id=a.session_id
        WHERE a.device_id=actor.device_id AND s.user_id=actor.user_id;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,node_id)
        VALUES(actor.user_id,session_row.id,session_user,'ui','ssh_host_pin_change','success',inet_client_addr(),session_row.app_version,p_node);
    RETURN QUERY SELECT 'changed'::text,NULL::jsonb;
EXCEPTION WHEN lock_not_available THEN RETURN QUERY SELECT 'busy'::text,NULL::jsonb;
END
$pin$;
REVOKE ALL ON FUNCTION wormhole_api_v1.ssh_host_pin(bytea,uuid,bigint,bigint,bigint,text,uuid,integer,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.ssh_host_pin(bytea,uuid,bigint,bigint,bigint,text,uuid,integer,bytea,bytea,bytea,bytea) TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=87 WHERE singleton;
COMMIT;
