CREATE OR REPLACE FUNCTION wormhole_data.connection_account_permissions(p_capability bytea,p_node uuid,p_epoch bigint,p_change_seq bigint,p_permission integer{{PATH_PARAMETER}})
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $accounts$
DECLARE identity record; meta record; plan jsonb; target_boundary uuid; credential_id uuid;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_permission IS NULL OR p_permission NOT IN (2,8) OR p_node IS NULL
       OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0 THEN
        RAISE EXCEPTION 'Invalid account permission request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004'; END IF;
    IF p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq THEN RAISE EXCEPTION 'Catalog snapshot changed' USING ERRCODE='WH013'; END IF;
    IF (wormhole_data.effective_permissions(identity.user_id,p_node)&p_permission)<>p_permission THEN
        RAISE EXCEPTION 'Connection permission required' USING ERRCODE='42501';
    END IF;
{{PATH_PERMISSIONS}}    plan:=wormhole_data.resolve_connection(p_node,identity.user_id,p_epoch,p_change_seq{{PATH_ARG}});
    IF plan#>>'{credential,kind}' IN ('saved','override') THEN
        credential_id:=(plan#>>'{credential,id}')::uuid;
        SELECT c.boundary_id INTO STRICT target_boundary FROM wormhole_data.credential_profiles c WHERE c.id=credential_id;
    ELSIF plan#>>'{credential,kind}'='inline' THEN
        SELECT n.boundary_id INTO STRICT target_boundary FROM wormhole_data.nodes n WHERE n.id=p_node;
    END IF;
    IF target_boundary IS NOT NULL AND (wormhole_data.effective_boundary_permissions(identity.user_id,target_boundary)&p_permission)<>p_permission THEN
        RAISE EXCEPTION 'Credential boundary permission required' USING ERRCODE='42501';
    END IF;
    IF plan->>'gatewayCredentialId'<>'' THEN
        SELECT c.boundary_id INTO STRICT target_boundary FROM wormhole_data.credential_profiles c WHERE c.id=(plan->>'gatewayCredentialId')::uuid;
        IF (wormhole_data.effective_boundary_permissions(identity.user_id,target_boundary)&p_permission)<>p_permission THEN
            RAISE EXCEPTION 'Gateway boundary permission required' USING ERRCODE='42501';
        END IF;
    END IF;
    IF plan->>'tunnelId'<>'' THEN
        SELECT t.boundary_id INTO target_boundary FROM wormhole_data.tunnel_profiles t WHERE t.id=(plan->>'tunnelId')::uuid AND NOT t.deleted;
        IF NOT FOUND THEN RAISE EXCEPTION 'Tunnel unavailable' USING ERRCODE='WH018'; END IF;
        IF (wormhole_data.effective_boundary_permissions(identity.user_id,target_boundary)&p_permission)<>p_permission THEN
            RAISE EXCEPTION 'Tunnel boundary permission required' USING ERRCODE='42501';
        END IF;
    END IF;
    RETURN plan;
END
$accounts$;
