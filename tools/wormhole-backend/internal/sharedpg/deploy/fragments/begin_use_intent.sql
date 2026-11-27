CREATE FUNCTION wormhole_data.begin_use_intent(p_capability bytea,p_node uuid,p_source text,p_primary uuid,p_fallback uuid{{PATH_PARAMETER}})
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,
    epoch bigint,change_seq bigint,expires_at bigint{{PATH_RECEIPT_COLUMN}})
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $begin_use$
DECLARE identity record; meta record; admitted record; session_record record;
        issued timestamptz; expiry timestamptz; ticket uuid; xid xid8; slot_id integer; counter bigint;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_source IS NULL OR p_source NOT IN ('ui','mcp') THEN
        RAISE EXCEPTION 'Invalid use request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF {{NOT_NOTE_PATH}}(wormhole_data.effective_permissions(identity.user_id,p_node)&2)<>2 THEN
        RAISE EXCEPTION 'Use permission required' USING ERRCODE='42501';
    END IF;
    IF p_primary IS NOT NULL OR p_fallback IS NOT NULL THEN
        PERFORM wormhole_data.fallback_permissions(p_capability,p_node,p_primary,p_fallback,meta.epoch,meta.change_seq);
    END IF;
{{BEGIN_PATH_AUTHORIZATION}}    SELECT * INTO STRICT admitted FROM wormhole_data.device_admissions a
        WHERE a.device_id=identity.device_id FOR UPDATE NOWAIT;
    SELECT * INTO STRICT session_record FROM wormhole_data.sessions s WHERE s.id=admitted.session_id;
    issued:=pg_catalog.clock_timestamp(); expiry:=issued+interval '30 seconds';
    ticket:=pg_catalog.gen_random_uuid(); xid:=pg_catalog.pg_current_xact_id();
    SELECT p.slot INTO slot_id FROM wormhole_data.use_counter_slots p
        WHERE p.device_id=identity.device_id OR p.expires_at<=issued
        ORDER BY (p.device_id=identity.device_id) DESC NULLS LAST,p.slot
        LIMIT 1 FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN RAISE EXCEPTION 'Use capacity is busy' USING ERRCODE='55P03'; END IF;
    counter:=pg_catalog.nextval(pg_catalog.format('wormhole_data.use_counter_%s',slot_id)::regclass);
    UPDATE wormhole_data.use_counter_slots p SET device_id=identity.device_id,expires_at=expiry WHERE p.slot=slot_id;
    BEGIN
        INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,
            client_addr,app_version,node_id,ticket_id,transaction_id,primary_tunnel_id,fallback_tunnel_id{{PATH_COLUMN}})
        VALUES(identity.user_id,admitted.session_id,session_user,p_source,CASE {{BEGIN_PATH_ACTION}}WHEN p_primary IS NULL THEN 'begin_use' ELSE 'begin_fallback_use' END,'issued',
            pg_catalog.inet_client_addr(),session_record.app_version,p_node,ticket,xid,p_primary,p_fallback{{PATH_ARG}});
    EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE='WH005'; END;
    INSERT INTO wormhole_data.use_tickets AS t(device_id,ticket_id,user_id,session_id,session_role,
        capability_hash,node_id,epoch,change_seq,issued_at,expires_at,transaction_id,counter_slot,counter_value,server_started_at,release_kind,primary_tunnel_id,fallback_tunnel_id{{PATH_COLUMN}})
    VALUES(identity.device_id,ticket,identity.user_id,admitted.session_id,session_user,
        admitted.capability_hash,p_node,meta.epoch,meta.change_seq,issued,expiry,xid,slot_id,counter,pg_catalog.pg_postmaster_start_time(),CASE {{TICKET_PATH_KIND}}WHEN p_primary IS NULL THEN 'connection' ELSE 'fallback' END,p_primary,p_fallback{{PATH_ARG}})
    ON CONFLICT ON CONSTRAINT use_tickets_pkey DO UPDATE SET
        ticket_id=EXCLUDED.ticket_id,user_id=EXCLUDED.user_id,session_id=EXCLUDED.session_id,
        session_role=EXCLUDED.session_role,capability_hash=EXCLUDED.capability_hash,
        node_id=EXCLUDED.node_id,epoch=EXCLUDED.epoch,change_seq=EXCLUDED.change_seq,
        issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at,transaction_id=EXCLUDED.transaction_id,counter_slot=EXCLUDED.counter_slot,
        counter_value=EXCLUDED.counter_value,server_started_at=EXCLUDED.server_started_at,release_kind=EXCLUDED.release_kind,
        primary_tunnel_id=EXCLUDED.primary_tunnel_id,fallback_tunnel_id=EXCLUDED.fallback_tunnel_id{{UPDATE_PATH_COLUMN}};
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,p_node,ticket,
        meta.epoch,meta.change_seq,pg_catalog.floor(EXTRACT(epoch FROM expiry))::bigint{{PATH_ARG}};
END
$begin_use$;
