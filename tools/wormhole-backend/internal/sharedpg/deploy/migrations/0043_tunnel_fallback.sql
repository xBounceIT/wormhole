-- Version 43: separately audited, purpose-bound IPsec-to-SSL source release.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>42 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;


-- Invalidate pre-migration intents. Ordinary and fallback tickets share the same
-- bounded per-device slot and irreversible counter generation.
DELETE FROM wormhole_data.use_tickets;
ALTER TABLE wormhole_data.use_tickets
 ADD COLUMN release_kind text NOT NULL DEFAULT 'connection',
 ADD COLUMN primary_tunnel_id uuid NULL,
 ADD COLUMN fallback_tunnel_id uuid NULL,
 ADD CONSTRAINT use_ticket_purpose CHECK (
   (release_kind='connection' AND primary_tunnel_id IS NULL AND fallback_tunnel_id IS NULL) OR
   (release_kind='fallback' AND primary_tunnel_id IS NOT NULL AND fallback_tunnel_id IS NOT NULL
    AND primary_tunnel_id<>'00000000-0000-0000-0000-000000000000'::uuid
    AND fallback_tunnel_id<>'00000000-0000-0000-0000-000000000000'::uuid
    AND primary_tunnel_id<>fallback_tunnel_id));
ALTER TABLE wormhole_data.audit_log
 ADD COLUMN primary_tunnel_id uuid NULL,
 ADD COLUMN fallback_tunnel_id uuid NULL;

-- The encrypted reference is authenticated again by Go. SQL independently
-- enforces current node/original-account permissions and secondary boundary Use.
{{FALLBACK_PERMISSIONS_DEFINITION}}

{{BEGIN_USE_DEFINITION}}


-- Existing callers preserve their wire shape; replacement explicitly resets
-- purpose and both source IDs through the common private writer.
CREATE OR REPLACE FUNCTION wormhole_api_v1.begin_use(p_capability bytea,p_node uuid,p_source text)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,epoch bigint,change_seq bigint,expires_at bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $ordinary$
 SELECT * FROM wormhole_data.begin_use_intent(p_capability,p_node,p_source,NULL,NULL)
$ordinary$;

CREATE FUNCTION wormhole_api_v1.begin_fallback_use(p_capability bytea,p_node uuid,p_primary uuid,p_fallback uuid,p_source text)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,epoch bigint,change_seq bigint,expires_at bigint,primary_tunnel_id uuid,fallback_tunnel_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $fallback$
BEGIN
 IF p_primary IS NULL OR p_fallback IS NULL THEN
  RAISE EXCEPTION 'Invalid fallback request' USING ERRCODE='22023';
 END IF;
 RETURN QUERY SELECT i.*,p_primary,p_fallback FROM wormhole_data.begin_use_intent(p_capability,p_node,p_source,p_primary,p_fallback) i;
END
$fallback$;
{{CLAIM_USE_DEFINITION}}

CREATE OR REPLACE FUNCTION wormhole_data.claim_use(p_capability bytea,p_node uuid,p_ticket uuid)
RETURNS TABLE(epoch bigint,change_seq bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $ordinary$
 SELECT * FROM wormhole_data.claim_use_intent(p_capability,p_node,p_ticket,NULL,NULL)
$ordinary$;

{{FETCH_SECRET_DEFINITION}}

-- Separate target record: never retag the signed node or its selected tunnel.
-- Preserve format5 source/enrollment proofs and final recipient key selection.
{{FALLBACK_GRAPH_DEFINITION}}

CREATE FUNCTION wormhole_api_v1.fetch_fallback_secret(p_capability bytea,p_node uuid,p_ticket uuid,p_primary uuid,p_fallback uuid)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,epoch bigint,change_seq bigint,primary_tunnel_id uuid,fallback_tunnel_id uuid,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $fetch$
DECLARE identity record; ticket record; claimed record; result jsonb; meta record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_ticket IS NULL OR p_ticket='00000000-0000-0000-0000-000000000000'::uuid
       OR p_primary IS NULL OR p_fallback IS NULL THEN
        RAISE EXCEPTION 'Invalid fallback release request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    SELECT t.* INTO ticket FROM wormhole_data.use_tickets t WHERE t.device_id=identity.device_id FOR UPDATE NOWAIT;
    IF NOT FOUND OR ticket.ticket_id<>p_ticket OR ticket.node_id<>p_node OR ticket.release_kind<>'fallback'
       OR ticket.primary_tunnel_id IS DISTINCT FROM p_primary OR ticket.fallback_tunnel_id IS DISTINCT FROM p_fallback THEN
        RAISE EXCEPTION 'Use ticket is unavailable' USING ERRCODE='WH015';
    END IF;
    PERFORM wormhole_data.fallback_permissions(p_capability,p_node,p_primary,p_fallback,ticket.epoch,ticket.change_seq);
    result:=wormhole_data.fallback_release_graph(p_node,identity.user_id,p_primary,p_fallback,ticket.epoch,ticket.change_seq);
    -- Only after complete bounded ciphertext: committed audit, identity, expiry,
    -- purpose, both sources, snapshot and irreversible one-use generation.
    SELECT * INTO STRICT claimed FROM wormhole_data.claim_use_intent(p_capability,p_node,p_ticket,p_primary,p_fallback);
    RETURN QUERY SELECT meta.workspace_id,identity.user_id,identity.device_id,p_node,p_ticket,
        claimed.epoch,claimed.change_seq,p_primary,p_fallback,result;
END
$fetch$;


REVOKE ALL ON FUNCTION wormhole_data.fallback_permissions(bytea,uuid,uuid,uuid,bigint,bigint),
 wormhole_data.begin_use_intent(bytea,uuid,text,uuid,uuid),
 wormhole_data.claim_use_intent(bytea,uuid,uuid,uuid,uuid),
 wormhole_data.fallback_release_graph(uuid,uuid,uuid,uuid,bigint,bigint),
 wormhole_data.claim_use(bytea,uuid,uuid)
FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_api_v1.begin_use(bytea,uuid,text),
 wormhole_api_v1.fetch_secret(bytea,uuid,uuid),
 wormhole_api_v1.begin_fallback_use(bytea,uuid,uuid,uuid,text),
 wormhole_api_v1.fetch_fallback_secret(bytea,uuid,uuid,uuid,uuid)
FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.begin_use(bytea,uuid,text),
 wormhole_api_v1.fetch_secret(bytea,uuid,uuid),
 wormhole_api_v1.begin_fallback_use(bytea,uuid,uuid,uuid,text),
 wormhole_api_v1.fetch_fallback_secret(bytea,uuid,uuid,uuid,uuid) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=43 WHERE singleton;
COMMIT;
