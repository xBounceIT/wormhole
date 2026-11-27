CREATE FUNCTION wormhole_data.claim_use_intent(p_capability bytea,p_node uuid,p_ticket uuid,p_primary uuid,p_fallback uuid{{PATH_PARAMETER}})
RETURNS TABLE(epoch bigint,change_seq bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $claim$
DECLARE identity record; meta record; ticket record; slot record; counter bigint;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    SELECT * INTO ticket FROM wormhole_data.use_tickets t WHERE t.device_id=identity.device_id FOR UPDATE NOWAIT;
    IF NOT FOUND OR p_node IS NULL OR p_ticket IS NULL OR ticket.ticket_id<>p_ticket OR ticket.node_id<>p_node
       OR ticket.release_kind IS DISTINCT FROM (CASE {{TICKET_PATH_KIND}}WHEN p_primary IS NULL THEN 'connection' ELSE 'fallback' END)
{{MATCH_TICKET_PATH}}
       OR ticket.primary_tunnel_id IS DISTINCT FROM p_primary OR ticket.fallback_tunnel_id IS DISTINCT FROM p_fallback
       OR ticket.user_id<>identity.user_id OR ticket.session_role<>session_user
       OR ticket.expires_at<=pg_catalog.clock_timestamp()
       OR ticket.server_started_at<>pg_catalog.pg_postmaster_start_time()
       OR ticket.epoch<>meta.epoch OR ticket.change_seq<>meta.change_seq
       OR NOT EXISTS(SELECT 1 FROM wormhole_data.device_admissions a WHERE a.device_id=identity.device_id
           AND a.session_id=ticket.session_id AND a.capability_hash=ticket.capability_hash) THEN
        RAISE EXCEPTION 'Use ticket is unavailable' USING ERRCODE='WH015';
    END IF;
    IF pg_catalog.pg_xact_status(ticket.transaction_id) IS DISTINCT FROM 'committed' THEN
        RAISE EXCEPTION 'Use ticket is unavailable' USING ERRCODE='WH015';
    END IF;
{{CLAIM_NOTE_PERMISSION}}    IF {{NOT_NOTE_PATH}}(wormhole_data.effective_permissions(identity.user_id,p_node)&2)<>2 THEN
        RAISE EXCEPTION 'Use permission required' USING ERRCODE='42501';
    END IF;
    SELECT * INTO slot FROM wormhole_data.use_counter_slots p WHERE p.slot=ticket.counter_slot FOR UPDATE NOWAIT;
    IF NOT FOUND OR slot.device_id IS DISTINCT FROM identity.device_id OR slot.expires_at<>ticket.expires_at THEN
        RAISE EXCEPTION 'Use ticket is unavailable' USING ERRCODE='WH015';
    END IF;
    counter:=pg_catalog.nextval(pg_catalog.format('wormhole_data.use_counter_%s',ticket.counter_slot)::regclass);
    IF ticket.counter_value=9223372036854775807 OR counter<>ticket.counter_value+1 THEN
        RAISE EXCEPTION 'Use ticket is unavailable' USING ERRCODE='WH015';
    END IF;
    DELETE FROM wormhole_data.use_tickets t WHERE t.device_id=identity.device_id;
    -- Successful commit releases capacity immediately. On rollback this lease
    -- update is undone, but the sequence generation is still irreversibly spent.
    UPDATE wormhole_data.use_counter_slots p SET expires_at=pg_catalog.clock_timestamp() WHERE p.slot=ticket.counter_slot;
    RETURN QUERY SELECT ticket.epoch,ticket.change_seq;
END
$claim$;
