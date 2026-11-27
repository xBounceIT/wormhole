-- Version 35: audited, connection-scoped encrypted release.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>34 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- No raw credential/key identifier or caller-selected user. The result is still
-- untrusted ciphertext: the native vault verifies every signature and context.
CREATE FUNCTION wormhole_api_v1.fetch_secret(p_capability bytea,p_node uuid,p_ticket uuid)
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
    IF NOT FOUND OR ticket.ticket_id<>p_ticket OR ticket.node_id<>p_node THEN
        RAISE EXCEPTION 'Use ticket is unavailable' USING ERRCODE='WH015';
    END IF;
    PERFORM wormhole_data.connection_account_permissions(p_capability,p_node,ticket.epoch,ticket.change_seq,2);
    result:=wormhole_data.credential_release_graph(p_node,identity.user_id,ticket.epoch,ticket.change_seq);
    -- All potentially failing payload work precedes the rollback-resistant claim.
    -- claim_use independently checks committed audit, snapshot, expiry, identity,
    -- capability, session, current Use permission and the single-use generation.
    SELECT * INTO STRICT claimed FROM wormhole_data.claim_use(p_capability,p_node,p_ticket);
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,p_node,p_ticket,
        claimed.epoch,claimed.change_seq,result;
END
$fetch$;
REVOKE ALL ON FUNCTION wormhole_api_v1.fetch_secret(bytea,uuid,uuid) FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.fetch_secret(bytea,uuid,uuid) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=35 WHERE singleton;
COMMIT;
