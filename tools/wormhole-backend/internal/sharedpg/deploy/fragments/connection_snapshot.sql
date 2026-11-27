CREATE OR REPLACE FUNCTION wormhole_data.connection_snapshot(p_node uuid,p_user uuid,p_epoch bigint,p_change_seq bigint{{PATH_PARAMETER}})
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $snapshot$
DECLARE meta record; plan jsonb; base_plan jsonb; chain jsonb; chain_body jsonb;
        override_row jsonb; slot_row jsonb; value_row jsonb; credential_row jsonb; gateway_row jsonb;
        boundaries jsonb; required uuid[]; item record; target_slot uuid;
        tunnel_row jsonb; override_id text:=''; result jsonb;
BEGIN
    -- Validates every argument and locks the requested workspace snapshot.
    plan:=wormhole_data.resolve_connection(p_node,p_user,p_epoch,p_change_seq{{PATH_ARG}});
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton;
    SELECT jsonb_agg(wormhole_data.catalog_projection_wire(to_jsonb(c)||jsonb_build_object(
            'workspace_id',meta.workspace_id,'subject_id',c.node_id,'epoch',p_epoch,'change_seq',p_change_seq,'record',c.node)) ORDER BY c.depth),
        jsonb_agg(c.node ORDER BY c.depth),array_agg(c.boundary_id ORDER BY c.depth)
    INTO chain,chain_body,required FROM wormhole_data.resolution_chain(p_node,p_epoch,p_change_seq) c;
{{WEB_SNAPSHOT_ACCOUNTS_BEGIN}}    IF EXISTS(SELECT 1 FROM wormhole_data.user_node_overrides o WHERE o.node_id=p_node AND o.user_id=p_user) THEN
        SELECT * INTO STRICT item FROM wormhole_data.selection_record('override',p_node,p_user,p_epoch,p_change_seq);
        override_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
        IF NOT (item.record->>'deleted')::boolean THEN override_id:=item.record->>'credentialId'; END IF;
    END IF;
    base_plan:=wormhole_data.resolve_chain(chain_body,override_id);
    IF base_plan#>>'{credential,kind}'='slot' THEN
        target_slot:=(base_plan#>>'{credential,id}')::uuid;
        SELECT * INTO STRICT item FROM wormhole_data.selection_record('slot',target_slot,NULL,p_epoch,p_change_seq);
        slot_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
        IF EXISTS(SELECT 1 FROM wormhole_data.credential_slot_values v WHERE v.slot_id=target_slot AND v.user_id=p_user) THEN
            SELECT * INTO STRICT item FROM wormhole_data.selection_record('slot-value',target_slot,p_user,p_epoch,p_change_seq);
            value_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
        END IF;
    END IF;
{{WEB_SNAPSHOT_ACCOUNTS_END}}    IF plan#>>'{credential,kind}' IN ('saved','override') THEN
        SELECT * INTO STRICT item FROM wormhole_data.credential_record((plan#>>'{credential,id}')::uuid,p_epoch,p_change_seq);
        credential_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
    END IF;
    IF plan->>'gatewayCredentialId'<>'' THEN
        SELECT * INTO STRICT item FROM wormhole_data.credential_record((plan->>'gatewayCredentialId')::uuid,p_epoch,p_change_seq);
        gateway_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
    END IF;
    IF plan->>'tunnelId'<>'' THEN
        SELECT * INTO STRICT item FROM wormhole_data.selection_record('tunnel',(plan->>'tunnelId')::uuid,NULL,p_epoch,p_change_seq);
        tunnel_row:=wormhole_data.catalog_projection_wire(to_jsonb(item));required:=array_append(required,item.boundary_id);
    END IF;
    SELECT jsonb_agg(jsonb_build_array(b.workspace_id::text,b.boundary_id::text,b.epoch::text,b.change_seq::text,
        b.version::text,encode(b.body,'hex'),b.signer_key_id::text,b.signer_key_version::text,encode(b.signature,'hex')) ORDER BY b.boundary_id)
    INTO boundaries FROM (SELECT DISTINCT unnest(required) AS id) r
        CROSS JOIN LATERAL wormhole_data.boundary_manifest(r.id,p_epoch,p_change_seq) b;
    result:=jsonb_build_object('formatVersion',3,'workspaceId',meta.workspace_id::text,'userId',p_user::text,
        'nodeId',p_node::text,'epoch',p_epoch::text,'changeSeq',p_change_seq::text,'plan',plan,'chain',chain,
        'override',override_row,'slot',slot_row,'slotValue',value_row,'credential',credential_row,'gateway',gateway_row,'boundaries',boundaries);
    result:=result||jsonb_build_object('tunnel',tunnel_row);
{{PATH_WIRE}}    IF octet_length(result::text)>16777216 THEN RAISE EXCEPTION 'Connection snapshot is too large' USING ERRCODE='54000'; END IF;
    RETURN result;
END
$snapshot$;
