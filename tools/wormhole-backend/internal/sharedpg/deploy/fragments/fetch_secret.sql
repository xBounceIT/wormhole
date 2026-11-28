CREATE OR REPLACE FUNCTION wormhole_api_v1.{{FETCH_FUNCTION}}(p_capability bytea,p_node uuid,p_ticket uuid{{PATH_PARAMETER}})
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,
    epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $fetch$
DECLARE identity record; ticket record; claimed record; result jsonb; meta record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_ticket IS NULL OR p_ticket='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid secret release request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    SELECT t.* INTO ticket FROM wormhole_data.use_tickets t WHERE t.device_id=identity.device_id FOR UPDATE NOWAIT;
    IF NOT FOUND OR ticket.ticket_id<>p_ticket OR ticket.node_id<>p_node OR ticket.release_kind<>'{{FETCH_KIND}}'{{FETCH_PATH_MATCH}} THEN
        RAISE EXCEPTION 'Use ticket is unavailable' USING ERRCODE='WH015';
    END IF;
{{FETCH_GRAPH}}
    -- All potentially failing payload work precedes the rollback-resistant claim.
    -- claim_use independently checks committed audit, snapshot, expiry, identity,
    -- capability, session, current Use permission and the single-use generation.
    SELECT * INTO STRICT claimed FROM wormhole_data.{{CLAIM_CALL}};
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,p_node,p_ticket,
        claimed.epoch,claimed.change_seq,result;
END
$fetch$;
