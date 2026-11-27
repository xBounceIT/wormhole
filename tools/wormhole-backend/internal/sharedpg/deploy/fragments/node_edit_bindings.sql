CREATE FUNCTION wormhole_data.node_edit_bindings(p_actor uuid,p_root uuid,p_epoch bigint,p_sequence bigint{{MASK_ARG}})
RETURNS TABLE(binding text,digest bytea,can_reveal boolean)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $bindings$
DECLARE leaf record; member record; path text; paths text[]; chain jsonb; base jsonb; plan jsonb;
    gateway_settings jsonb; slot jsonb; unassigned_slot uuid; affected integer:=0; visited integer:=0; node_mask integer;
BEGIN
    FOR leaf IN
        WITH RECURSIVE subtree(id,kind,boundary_id) AS (
            SELECT n.id,n.kind,n.boundary_id FROM wormhole_data.nodes n WHERE n.id=p_root
            UNION
            SELECT n.id,n.kind,n.boundary_id FROM wormhole_data.nodes n JOIN subtree s ON n.parent_id=s.id
        ) SELECT * FROM subtree
    LOOP
        visited:=visited+1;
        IF visited>8192 THEN RAISE EXCEPTION 'Node edit exceeds catalog limits' USING ERRCODE='54000'; END IF;
        IF leaf.kind<>1 THEN CONTINUE; END IF;
        SELECT jsonb_agg(c.node ORDER BY c.depth) INTO chain FROM wormhole_data.resolution_chain(leaf.id,p_epoch,p_sequence) c;
        base:=wormhole_data.resolve_chain(chain);
        paths:=CASE (base->>'protocol')::integer
            WHEN 0 THEN ARRAY['ssh','sftp','reveal'] WHEN 7 THEN ARRAY['ssh','sftp','reveal']
            WHEN 1 THEN ARRAY['rdp','rdp-gateway','reveal'] WHEN 6 THEN ARRAY['vnc','reveal']
            WHEN 3 THEN ARRAY['web','reveal'] WHEN 4 THEN ARRAY['web','reveal'] ELSE ARRAY['reveal'] END;
        gateway_settings:=NULL;
        IF (base->>'protocol')::integer=1 THEN
            SELECT jsonb_build_array(
                COALESCE((array_agg((n->>'rdpGatewayBypassLocal')::boolean ORDER BY depth)
                    FILTER (WHERE n->>'rdpGatewayBypassLocal' IS NOT NULL))[1],true) AND (base->>'gatewayMethod')::int<>0,
                COALESCE((array_agg((n->>'rdpServerAuthentication')::integer ORDER BY depth)
                    FILTER (WHERE n->>'rdpServerAuthentication' IS NOT NULL))[1],2))
            INTO gateway_settings FROM jsonb_array_elements(chain) WITH ORDINALITY parts(n,depth);
        END IF;
        node_mask:=wormhole_data.effective_permissions(p_actor,leaf.id){{PRIOR_MASK}};
        -- Every current user may have an override. Check the inherited/default
        -- account as well so clearing an override cannot activate an unchecked edit.
        plan:=base;
        unassigned_slot:=NULL;
        IF base#>>'{credential,kind}'='slot' THEN
            SELECT s.record INTO STRICT slot FROM wormhole_data.selection_record('slot',(base#>>'{credential,id}')::uuid,NULL,p_epoch,p_sequence) s;
            IF (slot->>'deleted')::boolean THEN RAISE EXCEPTION 'Invalid slot' USING ERRCODE='WH018'; END IF;
            IF slot->>'defaultCredentialId'='' THEN
                unassigned_slot:=(base#>>'{credential,id}')::uuid;
                plan:=base||jsonb_build_object('credential',jsonb_build_object('kind','none','id','','nodeId',''));
            ELSE
                plan:=wormhole_data.resolve_slot(base,p_actor::text,slot,NULL);
            END IF;
        END IF;
        binding:=leaf.id::text||'/default';
        digest:=sha256(convert_to(jsonb_build_array(base,plan,gateway_settings)::text,'UTF8'));
        can_reveal:=wormhole_data.node_edit_can_reveal(p_actor,node_mask,leaf.boundary_id,plan,(base->>'protocol')::int IN (3,4));
        RETURN NEXT;
        FOR member IN SELECT u.id FROM wormhole_data.users u WHERE {{BINDING_USERS}}
        LOOP
            IF unassigned_slot IS NOT NULL AND NOT EXISTS(SELECT FROM wormhole_data.credential_slot_values v
                WHERE v.slot_id=unassigned_slot AND v.user_id=member.id AND NOT v.deleted) AND
                NOT EXISTS(SELECT FROM wormhole_data.user_node_overrides o WHERE o.node_id=leaf.id AND o.user_id=member.id AND NOT o.deleted)
            THEN CONTINUE; END IF;
            FOREACH path IN ARRAY paths LOOP
                affected:=affected+1;
                IF affected>8192 THEN RAISE EXCEPTION 'Node edit exceeds account limits' USING ERRCODE='54000'; END IF;
                plan:=wormhole_data.resolve_connection(leaf.id,member.id,p_epoch,p_sequence,path);
                binding:=leaf.id::text||'/'||member.id::text||'/'||path;
                digest:=sha256(convert_to(jsonb_build_array(plan,gateway_settings)::text,'UTF8'));
                can_reveal:=wormhole_data.node_edit_can_reveal(p_actor,node_mask,leaf.boundary_id,plan,path='web');
                IF (plan->>'externalRdpClient')::boolean AND member.id<>p_actor THEN can_reveal:=false; END IF;
                RETURN NEXT;
            END LOOP;
        END LOOP;
    END LOOP;
END
$bindings$;
REVOKE ALL ON FUNCTION wormhole_data.node_edit_bindings(uuid,uuid,bigint,bigint{{MASK_TYPE}}) FROM PUBLIC;
