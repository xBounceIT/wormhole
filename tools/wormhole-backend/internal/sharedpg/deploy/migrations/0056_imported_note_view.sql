-- Version 56: audited View of shared notes and boundary view-key imports.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>55 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE OR REPLACE FUNCTION wormhole_data.valid_import_reference(p_reference jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $reference$
    SELECT COALESCE(pg_catalog.jsonb_typeof(p_reference)='object' AND p_reference ?& ARRAY['digest','retainedPins']
      AND p_reference-ARRAY['digest','retainedPins','noteVersion']='{}'::jsonb AND p_reference->>'digest'~'^[0-9a-f]{64}$'
      AND pg_catalog.jsonb_typeof(p_reference->'retainedPins')='boolean'
      AND (NOT p_reference ? 'noteVersion' OR p_reference->'noteVersion'='1'::jsonb),false);
$reference$;

ALTER TABLE wormhole_data.audit_log DROP CONSTRAINT audit_log_protocol_path_check,
    ADD CONSTRAINT audit_log_protocol_path_check CHECK(protocol_path IN ('ssh','sftp','vnc','rdp','notes'));
ALTER TABLE wormhole_data.use_tickets DROP CONSTRAINT use_ticket_purpose,
    ADD CONSTRAINT use_ticket_purpose CHECK (
    (release_kind='connection' AND primary_tunnel_id IS NULL AND fallback_tunnel_id IS NULL AND protocol_path IS NULL) OR
    (release_kind='fallback' AND primary_tunnel_id IS NOT NULL AND fallback_tunnel_id IS NOT NULL AND protocol_path IS NULL
        AND primary_tunnel_id<>'00000000-0000-0000-0000-000000000000'::uuid
        AND fallback_tunnel_id<>'00000000-0000-0000-0000-000000000000'::uuid
        AND primary_tunnel_id<>fallback_tunnel_id) OR
    (release_kind='connection_path' AND primary_tunnel_id IS NULL AND fallback_tunnel_id IS NULL
        AND protocol_path IS NOT NULL AND protocol_path IN ('ssh','sftp','vnc','rdp','notes')));

-- The caller holds the workspace snapshot lock. New notes have their field
-- revision in the node seal and need no account-pin projection. A legacy note
-- shares its digest with the pins, so returning that attachment still needs
-- the same authorization as an ordinary imported-node metadata read.
CREATE FUNCTION wormhole_data.note_view_target(p_user uuid,p_node uuid)
RETURNS wormhole_data.nodes LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $target$
DECLARE item wormhole_data.nodes;
BEGIN
    SELECT n.* INTO item FROM wormhole_data.nodes n WHERE n.id=p_node;
    IF NOT FOUND OR item.seal IS NULL OR item.name IS NULL OR item.encrypted_metadata IS NOT NULL
        OR (wormhole_data.effective_permissions(p_user,p_node)&1)<>1
        OR (wormhole_data.effective_boundary_permissions(p_user,item.boundary_id)&1)<>1 THEN
        RAISE EXCEPTION 'Node note unavailable' USING ERRCODE='42501';
    END IF;
    IF item.imported->'retainedPins'='true'::jsonb AND NOT item.imported ? 'noteVersion' THEN
        IF (wormhole_data.effective_permissions(p_user,p_node)&2)<>2
            OR (wormhole_data.effective_boundary_permissions(p_user,item.boundary_id)&2)<>2 THEN
            RAISE EXCEPTION 'Legacy node note unavailable' USING ERRCODE='42501';
        END IF;
        PERFORM wormhole_data.require_imported_pin_permissions(p_user,wormhole_data.imported_node_body(p_node),2);
    END IF;
    RETURN item;
END
$target$;
{{NOTE_TICKET_DEFINITIONS}}

CREATE OR REPLACE FUNCTION wormhole_api_v1.begin_use_path(p_capability bytea,p_node uuid,p_source text,p_path text)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,
    epoch bigint,change_seq bigint,expires_at bigint,protocol_path text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $path$
BEGIN
    IF p_path IS NULL OR p_path='notes' THEN
        RAISE EXCEPTION 'Invalid credential path' USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT * FROM wormhole_data.begin_use_intent(p_capability,p_node,p_source,NULL,NULL,p_path);
END
$path$;

CREATE FUNCTION wormhole_api_v1.begin_note_view(p_capability bytea,p_node uuid,p_revision bigint)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,
    epoch bigint,change_seq bigint,expires_at bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $begin$
DECLARE identity record; item wormhole_data.nodes;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    PERFORM FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    BEGIN
        item:=wormhole_data.note_view_target(identity.user_id,p_node);
    EXCEPTION WHEN insufficient_privilege OR SQLSTATE 'WH014' THEN
        RETURN;
    END;
    IF item.row_version IS DISTINCT FROM p_revision THEN
        RETURN;
    END IF;
    RETURN QUERY SELECT i.workspace_id,i.user_id,i.device_id,i.node_id,i.ticket_id,i.epoch,i.change_seq,i.expires_at
        FROM wormhole_data.begin_use_intent(p_capability,p_node,'ui',NULL,NULL,'notes') i;
END
$begin$;

{{NODE_NOTE_GRAPH_DEFINITION}}

{{FETCH_NOTE_DEFINITION}}
{{COMMIT_WORKSPACE_IMPORT_DEFINITION}}
{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_data.note_view_target(uuid,uuid),wormhole_data.node_note_graph(uuid,uuid,bigint,bigint)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.begin_note_view(bytea,uuid,bigint),wormhole_api_v1.fetch_note(bytea,uuid,uuid)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.begin_note_view(bytea,uuid,bigint),wormhole_api_v1.fetch_note(bytea,uuid,uuid) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=56 WHERE singleton;
COMMIT;
