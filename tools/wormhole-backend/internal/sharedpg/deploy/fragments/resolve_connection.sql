CREATE FUNCTION wormhole_data.resolve_connection(p_node uuid,p_user uuid,p_epoch bigint,p_change_seq bigint{{PATH_PARAMETER}})
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $connection$
DECLARE meta record; chain jsonb; selected jsonb; assigned jsonb;
        profile jsonb; override_id text:=''; plan jsonb; target_slot uuid;{{PIN_DECLARATION}}
BEGIN
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_user IS NULL OR p_user='00000000-0000-0000-0000-000000000000'::uuid
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid connection request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN
        RAISE EXCEPTION 'Catalog snapshot changed' USING ERRCODE='WH013';
    END IF;
{{IMPORT_RESOLVER_GUARD}}    SELECT jsonb_agg(c.node ORDER BY c.depth) INTO chain
        FROM wormhole_data.resolution_chain(p_node,p_epoch,p_change_seq) c;
{{WEB_PLAN_RESOLUTION}}    -- Keep tombstones in the eventual response even though they select nothing.
    IF EXISTS(SELECT 1 FROM wormhole_data.user_node_overrides o WHERE o.node_id=p_node AND o.user_id=p_user) THEN
        SELECT r.record INTO STRICT selected FROM wormhole_data.selection_record('override',p_node,p_user,p_epoch,p_change_seq) r;
        IF NOT (selected->>'deleted')::boolean THEN override_id:=selected->>'credentialId'; END IF;
    END IF;
    plan:=wormhole_data.resolve_chain(chain,override_id);
    IF plan#>>'{credential,kind}'='slot' THEN
        target_slot:=(plan#>>'{credential,id}')::uuid;
        SELECT r.record INTO STRICT selected FROM wormhole_data.selection_record('slot',target_slot,NULL,p_epoch,p_change_seq) r;
        IF (selected->>'deleted')::boolean THEN RAISE EXCEPTION 'Credential slot unavailable' USING ERRCODE='WH018'; END IF;
        IF EXISTS(SELECT 1 FROM wormhole_data.credential_slot_values v WHERE v.slot_id=target_slot AND v.user_id=p_user) THEN
            SELECT r.record INTO STRICT assigned FROM wormhole_data.selection_record('slot-value',target_slot,p_user,p_epoch,p_change_seq) r;
            IF (assigned->>'deleted')::boolean THEN assigned:=NULL; END IF;
        END IF;
        plan:=wormhole_data.resolve_slot(plan,p_user::text,selected,assigned);
    END IF;
{{SELECT_PIN}}    IF plan#>>'{credential,kind}' IN ('saved','override') THEN
        SELECT r.record INTO STRICT profile FROM wormhole_data.credential_record((plan#>>'{credential,id}')::uuid,p_epoch,p_change_seq) r;
        IF (profile->>'deleted')::boolean THEN RAISE EXCEPTION 'Credential metadata unavailable' USING ERRCODE='WH018'; END IF;
{{APPLY_PROFILE}}        plan:=wormhole_data.apply_credential(plan,profile->'metadata');
{{APPLY_PROFILE_END}}
    END IF;
    IF plan->>'gatewayCredentialId'<>'' THEN
        SELECT r.record INTO STRICT profile FROM wormhole_data.credential_record((plan->>'gatewayCredentialId')::uuid,p_epoch,p_change_seq) r;
        IF (profile->>'deleted')::boolean OR profile#>>'{metadata,protocol}'<>'rdp' THEN
            RAISE EXCEPTION 'Gateway credential unavailable' USING ERRCODE='WH018';
        END IF;
    END IF;
    RETURN plan;
END
$connection$;
