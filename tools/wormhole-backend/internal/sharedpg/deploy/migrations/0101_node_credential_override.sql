-- Version 101: review and set a member's own credential for one connection.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>100 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.node_credential_override(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_policy bytea,p_state bytea,
    p_node uuid,p_scope text,p_name text,p_epoch bigint,p_sequence bigint,p_revision bigint,p_credential uuid,p_signature bytea)
RETURNS TABLE(status text,epoch bigint,change_seq bigint,node_chain jsonb,override_row jsonb,credential_row jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $override$
DECLARE actor record; meta record; leaf wormhole_data.nodes; choice wormhole_data.user_node_overrides;
    credential wormhole_data.credential_profiles; boundary uuid; public_key bytea; message text;
    nodes jsonb; family text; writing boolean:=p_revision IS NOT NULL;
BEGIN
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid
        OR p_name IS NULL OR octet_length(p_name)>1024 OR p_scope IS NULL OR p_scope NOT IN ('personal','shared','inherit')
        OR (p_scope='inherit')<>(p_name='') OR (NOT writing AND (p_epoch IS NOT NULL OR p_sequence IS NOT NULL OR p_credential IS NOT NULL OR p_signature IS NOT NULL))
        OR (writing AND (p_epoch IS NULL OR p_epoch<1 OR p_sequence IS NULL OR p_sequence<0 OR p_revision NOT BETWEEN 0 AND 9223372036854775806
            OR (p_scope='inherit')<>(p_credential IS NULL) OR octet_length(p_signature) IS DISTINCT FROM 64)) THEN
        RAISE EXCEPTION 'Invalid connection credential change' USING ERRCODE='22023';
    END IF;
    status:='unavailable';
    SELECT * INTO actor FROM wormhole_data.account_recovery_context(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_policy,p_state,writing);
    IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;
    SELECT * INTO leaf FROM wormhole_data.nodes n WHERE n.id=p_node AND n.kind=1 AND n.seal IS NOT NULL AND n.encrypted_metadata IS NULL
        AND (wormhole_data.effective_permissions(actor.actor,n.id)&3)=3;
    IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;
    SELECT m.epoch,m.change_seq INTO STRICT meta FROM wormhole_data.workspace_meta m WHERE m.singleton;
    SELECT * INTO choice FROM wormhole_data.user_node_overrides o WHERE o.node_id=p_node AND o.user_id=actor.actor;
    boundary:=coalesce(choice.boundary_id,leaf.boundary_id);
    IF NOT EXISTS(SELECT FROM wormhole_data.boundaries b WHERE b.id=boundary AND NOT b.deleted AND
        (b.id=leaf.boundary_id OR b.owner_user_id=actor.actor OR (wormhole_data.effective_boundary_permissions(actor.actor,b.id)&2)=2)) THEN
        RETURN NEXT; RETURN;
    END IF;
    IF writing AND ((p_epoch,p_sequence) IS DISTINCT FROM (meta.epoch,meta.change_seq) OR p_revision<>coalesce(choice.row_version,0)) THEN
        status:='stale'; RETURN NEXT; RETURN;
    END IF;
    SELECT jsonb_agg(c.node ORDER BY c.depth) INTO nodes FROM wormhole_data.resolution_chain(p_node,meta.epoch,meta.change_seq) c;
    family:=CASE wormhole_data.resolve_chain(nodes)->>'protocol' WHEN '0' THEN 'ssh' WHEN '7' THEN 'ssh' WHEN '1' THEN 'rdp' WHEN '6' THEN 'vnc' END;
    IF family IS NULL THEN RETURN NEXT; RETURN; END IF;
    IF p_scope<>'inherit' THEN
        SELECT c.* INTO credential FROM wormhole_data.credential_profiles c JOIN wormhole_data.boundaries b ON b.id=c.boundary_id
            WHERE NOT c.deleted AND NOT b.deleted AND c.protocol=family AND c.name COLLATE "C"=p_name COLLATE "C"
            AND (wormhole_data.effective_boundary_permissions(actor.actor,b.id)&2)=2
            AND ((p_scope='personal' AND c.owner_user_id=actor.actor AND b.owner_user_id=actor.actor AND c.provider IN ('local','bitwarden'))
                OR (p_scope='shared' AND c.owner_user_id IS NULL AND b.owner_user_id IS NULL AND c.provider='local'));
        IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;
    END IF;
    IF writing THEN
        IF p_credential IS DISTINCT FROM credential.id OR
            (CASE WHEN choice.deleted THEN NULL::uuid ELSE choice.credential_id END) IS NOT DISTINCT FROM p_credential THEN
            status:='stale'; RETURN NEXT; RETURN;
        END IF;
        SELECT decode(convert_from(e.certificate,'UTF8')::jsonb#>>'{rekey,public,signing}','base64') INTO public_key
            FROM wormhole_data.user_enrollments e JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(e.signing_key_id,e.signing_key_version)
            WHERE e.user_id=actor.actor AND (k.key_id,k.key_version)=(p_signer,p_signer_version)
            AND k.owner_id=actor.actor AND k.kind='user-sign' AND k.status='active';
        message:=format('{"workspaceId":"{{WORKSPACE_ID}}","boundaryId":"%s","suite":2,"record":{"userId":"%s","nodeId":"%s","credentialId":"%s","deleted":%s},"seal":{"formatVersion":1,"signerKeyId":"%s","signerKeyVersion":%s,"capabilityId":null,"revision":%s,"signature":null}}',
            boundary,actor.actor,p_node,coalesce(p_credential::text,''),(p_credential IS NULL)::text,p_signer,p_signer_version,p_revision+1);
        IF wormhole_data.ed25519_verify(public_key,convert_to('wormhole/v1/shared-override','UTF8')||decode('00','hex')||convert_to(message,'UTF8'),p_signature) IS DISTINCT FROM true THEN
            RETURN NEXT; RETURN;
        END IF;
        IF choice.node_id IS NULL THEN
            INSERT INTO wormhole_data.user_node_overrides(user_id,node_id,credential_id,boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal)
                VALUES(actor.actor,p_node,p_credential,boundary,2,p_signer,p_signer_version,p_signature);
        ELSE
            UPDATE wormhole_data.user_node_overrides SET credential_id=p_credential,deleted=(p_credential IS NULL),row_version=p_revision+1,
                seal_signer_key_id=p_signer,seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_signature
                WHERE user_id=actor.actor AND node_id=p_node;
        END IF;
        PERFORM wormhole_data.audit_server_ca(actor.actor,actor.session_id,actor.app_version,'set_node_credential_override','success');
    END IF;
    status:=CASE WHEN writing THEN 'saved' ELSE 'review' END;
    SELECT m.epoch,m.change_seq INTO STRICT epoch,change_seq FROM wormhole_data.workspace_meta m WHERE m.singleton;
    SELECT jsonb_agg(wormhole_data.catalog_projection_wire(to_jsonb(c)||jsonb_build_object(
        'workspace_id','{{WORKSPACE_ID}}','subject_id',c.node_id,'epoch',epoch,'change_seq',change_seq,'record',c.node)) ORDER BY c.depth)
        INTO node_chain FROM wormhole_data.resolution_chain(p_node,epoch,change_seq) c;
    IF writing OR choice.node_id IS NOT NULL THEN
        SELECT wormhole_data.catalog_projection_wire(to_jsonb(o)) INTO STRICT override_row FROM wormhole_data.selection_record('override',p_node,actor.actor,epoch,change_seq) o;
    END IF;
    IF credential.id IS NOT NULL THEN
        SELECT wormhole_data.catalog_projection_wire(to_jsonb(c)) INTO STRICT credential_row FROM wormhole_data.credential_record(credential.id,epoch,change_seq) c;
    END IF;
    IF octet_length(node_chain::text)>16777216 THEN RAISE EXCEPTION 'Connection chain is too large' USING ERRCODE='54000'; END IF;
    RETURN NEXT;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bigint,NULL::bigint,NULL::jsonb,NULL::jsonb,NULL::jsonb;
END
$override$;
REVOKE ALL ON FUNCTION wormhole_api_v1.node_credential_override(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,text,bigint,bigint,bigint,uuid,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.node_credential_override(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,text,text,bigint,bigint,bigint,uuid,bytea)
    TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=101 WHERE singleton;
COMMIT;
