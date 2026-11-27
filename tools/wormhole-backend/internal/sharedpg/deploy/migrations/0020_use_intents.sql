-- Version 20: audited use intent. No ciphertext is released by this API.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>19 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.audit_log ADD COLUMN node_id uuid NULL;
ALTER TABLE wormhole_data.audit_log ADD COLUMN ticket_id uuid NULL;
ALTER TABLE wormhole_data.audit_log ADD COLUMN transaction_id xid8 NULL;

-- At most one outstanding ticket per enrolled device; replacing it invalidates
-- the older ticket. No unbounded expiration sweep runs on the release path.
CREATE TABLE wormhole_data.use_tickets (
    device_id uuid PRIMARY KEY REFERENCES wormhole_data.devices(id) ON DELETE CASCADE,
    ticket_id uuid NOT NULL UNIQUE,
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    session_id uuid NOT NULL REFERENCES wormhole_data.sessions(id),
    session_role text NOT NULL,
    capability_hash bytea NOT NULL CHECK(octet_length(capability_hash)=32),
    node_id uuid NOT NULL REFERENCES wormhole_data.nodes(id) ON DELETE CASCADE,
    epoch bigint NOT NULL CHECK(epoch>=1),
    change_seq bigint NOT NULL CHECK(change_seq>=0),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    transaction_id xid8 NOT NULL,
    CHECK(expires_at=issued_at+interval '30 seconds')
);
REVOKE ALL ON TABLE wormhole_data.use_tickets FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;

CREATE FUNCTION wormhole_api_v1.begin_use(p_capability bytea,p_node uuid,p_source text)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,
    epoch bigint,change_seq bigint,expires_at bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $begin_use$
DECLARE identity record; meta record; admitted record; session_record record;
        issued timestamptz; expiry timestamptz; ticket uuid; xid xid8;
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
    BEGIN
        INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,
            client_addr,app_version,node_id,ticket_id,transaction_id)
        VALUES(identity.user_id,admitted.session_id,session_user,p_source,'begin_use','issued',
            pg_catalog.inet_client_addr(),session_record.app_version,p_node,ticket,xid);
    EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE='WH005'; END;
    INSERT INTO wormhole_data.use_tickets AS t(device_id,ticket_id,user_id,session_id,session_role,
        capability_hash,node_id,epoch,change_seq,issued_at,expires_at,transaction_id)
    VALUES(identity.device_id,ticket,identity.user_id,admitted.session_id,session_user,
        admitted.capability_hash,p_node,meta.epoch,meta.change_seq,issued,expiry,xid)
    ON CONFLICT ON CONSTRAINT use_tickets_pkey DO UPDATE SET
        ticket_id=EXCLUDED.ticket_id,user_id=EXCLUDED.user_id,session_id=EXCLUDED.session_id,
        session_role=EXCLUDED.session_role,capability_hash=EXCLUDED.capability_hash,
        node_id=EXCLUDED.node_id,epoch=EXCLUDED.epoch,change_seq=EXCLUDED.change_seq,
        issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at,transaction_id=EXCLUDED.transaction_id;
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,p_node,ticket,
        meta.epoch,meta.change_seq,pg_catalog.floor(EXTRACT(epoch FROM expiry))::bigint;
END
$begin_use$;
REVOKE ALL ON FUNCTION wormhole_api_v1.begin_use(bytea,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.begin_use(bytea,uuid,text) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=20 WHERE singleton;
COMMIT;
