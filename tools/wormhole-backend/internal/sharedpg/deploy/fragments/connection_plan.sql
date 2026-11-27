CREATE FUNCTION wormhole_api_v1.{{PLAN_FUNCTION}}(p_capability bytea,p_node uuid{{PATH_PARAMETER}})
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $plan$
DECLARE identity record; meta record; account record; metadata jsonb; result jsonb;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid connection plan request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    PERFORM wormhole_data.connection_account_permissions(p_capability,p_node,meta.epoch,meta.change_seq,{{PLAN_PERMISSION}}{{PATH_ARG}});
    metadata:=wormhole_data.connection_snapshot(p_node,identity.user_id,meta.epoch,meta.change_seq{{PATH_ARG}});
    SELECT s.* INTO account FROM wormhole_data.user_key_states s WHERE s.user_id=identity.user_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key state unavailable' USING ERRCODE='WH010'; END IF;
    result:=jsonb_build_object('formatVersion',1,'profile',encode(meta.signed_profile,'hex'),
        'account',jsonb_build_array(account.state_sequence::text,encode(account.signed_state,'hex')),'metadata',metadata);
    IF octet_length(result::text)>18874368 THEN RAISE EXCEPTION 'Connection plan is too large' USING ERRCODE='54000'; END IF;
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,p_node,meta.epoch,meta.change_seq,result;
END
$plan$;
