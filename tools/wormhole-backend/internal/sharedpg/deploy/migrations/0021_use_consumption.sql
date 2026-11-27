-- Version 21: rollback-resistant use-ticket consumption.
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
DO $migration_lock$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration is already in progress' USING ERRCODE='55P03';
    END IF;
END
$migration_lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>20 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Preallocated capacity, changed only by a versioned deploy migration. Runtime
-- code neither creates sequences nor grants their privileges to application roles.
CREATE TABLE wormhole_data.use_counter_slots (
    slot integer PRIMARY KEY CHECK(slot BETWEEN 1 AND 1024),
    device_id uuid NULL REFERENCES wormhole_data.devices(id) ON DELETE SET NULL,
    expires_at timestamptz NOT NULL DEFAULT '-infinity',
    UNIQUE(device_id)
);
INSERT INTO wormhole_data.use_counter_slots(slot) SELECT generate_series(1,1024);
DO $counters$
DECLARE i integer;
BEGIN
    FOR i IN 1..1024 LOOP
        EXECUTE pg_catalog.format('CREATE SEQUENCE wormhole_data.use_counter_%s AS bigint NO CYCLE CACHE 1',i);
        EXECUTE pg_catalog.format('REVOKE ALL ON SEQUENCE wormhole_data.use_counter_%s FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin',i);
    END LOOP;
END
$counters$;
REVOKE ALL ON TABLE wormhole_data.use_counter_slots FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
-- Old intent receipts lack a counter generation and cannot be consumed.
DELETE FROM wormhole_data.use_tickets;
ALTER TABLE wormhole_data.use_tickets ADD COLUMN counter_slot integer NOT NULL REFERENCES wormhole_data.use_counter_slots(slot);
ALTER TABLE wormhole_data.use_tickets ADD COLUMN counter_value bigint NOT NULL CHECK(counter_value>0);
ALTER TABLE wormhole_data.use_tickets ADD COLUMN server_started_at timestamptz NOT NULL;

CREATE OR REPLACE FUNCTION wormhole_api_v1.begin_use(p_capability bytea,p_node uuid,p_source text)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,
    epoch bigint,change_seq bigint,expires_at bigint)
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
    IF (wormhole_data.effective_permissions(identity.user_id,p_node)&2)<>2 THEN
        RAISE EXCEPTION 'Use permission required' USING ERRCODE='42501';
    END IF;
    SELECT * INTO STRICT admitted FROM wormhole_data.device_admissions a
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
            client_addr,app_version,node_id,ticket_id,transaction_id)
        VALUES(identity.user_id,admitted.session_id,session_user,p_source,'begin_use','issued',
            pg_catalog.inet_client_addr(),session_record.app_version,p_node,ticket,xid);
    EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE='WH005'; END;
    INSERT INTO wormhole_data.use_tickets AS t(device_id,ticket_id,user_id,session_id,session_role,
        capability_hash,node_id,epoch,change_seq,issued_at,expires_at,transaction_id,counter_slot,counter_value,server_started_at)
    VALUES(identity.device_id,ticket,identity.user_id,admitted.session_id,session_user,
        admitted.capability_hash,p_node,meta.epoch,meta.change_seq,issued,expiry,xid,slot_id,counter,pg_catalog.pg_postmaster_start_time())
    ON CONFLICT ON CONSTRAINT use_tickets_pkey DO UPDATE SET
        ticket_id=EXCLUDED.ticket_id,user_id=EXCLUDED.user_id,session_id=EXCLUDED.session_id,
        session_role=EXCLUDED.session_role,capability_hash=EXCLUDED.capability_hash,
        node_id=EXCLUDED.node_id,epoch=EXCLUDED.epoch,change_seq=EXCLUDED.change_seq,
        issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at,transaction_id=EXCLUDED.transaction_id,counter_slot=EXCLUDED.counter_slot,
        counter_value=EXCLUDED.counter_value,server_started_at=EXCLUDED.server_started_at;
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,p_node,ticket,
        meta.epoch,meta.change_seq,pg_catalog.floor(EXTRACT(epoch FROM expiry))::bigint;
END
$begin_use$;

-- Private primitive for fetch_secret, not a public release API. Consume only after
-- the caller has assembled/validated its bounded ciphertext result. Once this
-- succeeds, even a rollback or exception cannot restore the counter generation.
CREATE FUNCTION wormhole_data.claim_use(p_capability bytea,p_node uuid,p_ticket uuid)
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
    IF (wormhole_data.effective_permissions(identity.user_id,p_node)&2)<>2 THEN
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
REVOKE ALL ON FUNCTION wormhole_data.claim_use(bytea,uuid,uuid) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
UPDATE wormhole_data.workspace_meta SET schema_version=21 WHERE singleton;
COMMIT;
