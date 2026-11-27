-- Version 83: audited tunnel settings for browsing imported HTTP(S) targets.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>82 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_data.node_default_plan_path(p_node uuid,p_epoch bigint,p_change_seq bigint) RETURNS text
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $path$
    SELECT CASE WHEN (c.node->>'protocol')::integer IN (3,4) THEN 'web'
                ELSE wormhole_data.default_use_path((c.node->>'protocol')::integer) END
    FROM wormhole_data.resolution_chain(p_node,p_epoch,p_change_seq) c
    WHERE c.node->>'protocol' IS NOT NULL ORDER BY c.depth LIMIT 1;
$path$;
REVOKE ALL ON FUNCTION wormhole_data.node_default_plan_path(uuid,bigint,bigint)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;

ALTER TABLE wormhole_data.audit_log DROP CONSTRAINT audit_log_protocol_path_check,
    ADD CONSTRAINT audit_log_protocol_path_check CHECK(protocol_path IN ('ssh','sftp','vnc','rdp','notes','web'));
ALTER TABLE wormhole_data.use_tickets DROP CONSTRAINT use_ticket_purpose,
    ADD CONSTRAINT use_ticket_purpose CHECK (
    (release_kind='connection' AND primary_tunnel_id IS NULL AND fallback_tunnel_id IS NULL AND protocol_path IS NULL) OR
    (release_kind='fallback' AND primary_tunnel_id IS NOT NULL AND fallback_tunnel_id IS NOT NULL AND protocol_path IS NULL
        AND primary_tunnel_id<>'00000000-0000-0000-0000-000000000000'::uuid
        AND fallback_tunnel_id<>'00000000-0000-0000-0000-000000000000'::uuid
        AND primary_tunnel_id<>fallback_tunnel_id) OR
    (release_kind='connection_path' AND primary_tunnel_id IS NULL AND fallback_tunnel_id IS NULL
        AND protocol_path IS NOT NULL AND protocol_path IN ('ssh','sftp','vnc','rdp','notes','web')));

{{WEB_CONNECTION_DEFINITIONS}}
{{WEB_TICKET_DEFINITIONS}}
{{WEB_FALLBACK_DEFINITION}}

CREATE OR REPLACE FUNCTION wormhole_api_v1.begin_use_path(p_capability bytea,p_node uuid,p_source text,p_path text)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,
    epoch bigint,change_seq bigint,expires_at bigint,protocol_path text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $path$
BEGIN
    IF p_path IS NULL OR p_path IN ('notes','web') THEN
        RAISE EXCEPTION 'Invalid credential path' USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT * FROM wormhole_data.begin_use_intent(p_capability,p_node,p_source,NULL,NULL,p_path);
END
$path$;

-- Only the tunnel consumer opts into a web ticket. The ordinary credential
-- API continues to choose account paths and cannot issue a web ticket.
CREATE FUNCTION wormhole_api_v1.begin_tunnel_use(p_capability bytea,p_node uuid,p_source text)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,
    epoch bigint,change_seq bigint,expires_at bigint,protocol_path text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $tunnel$
DECLARE identity record; meta record; path text:='default'; plan jsonb;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF (wormhole_data.effective_permissions(identity.user_id,p_node)&2)<>2 THEN
        RAISE EXCEPTION 'Use permission required' USING ERRCODE='42501';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF wormhole_data.node_default_plan_path(p_node,meta.epoch,meta.change_seq)='web' THEN
        path:='web';
        plan:=wormhole_data.connection_account_permissions(p_capability,p_node,meta.epoch,meta.change_seq,2,path);
        IF plan->>'tunnelId'='' THEN
            RAISE EXCEPTION 'Tunnel unavailable' USING ERRCODE='WH018';
        END IF;
    END IF;
    RETURN QUERY SELECT * FROM wormhole_data.begin_use_intent(p_capability,p_node,p_source,NULL,NULL,path);
END
$tunnel$;
REVOKE ALL ON FUNCTION wormhole_api_v1.begin_tunnel_use(bytea,uuid,text)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.begin_tunnel_use(bytea,uuid,text) TO wh_{{TAG}}_user;

{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=83 WHERE singleton;
COMMIT;
