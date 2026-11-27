-- Version 55: atomic publication of a certified, encrypted local import.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>54 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_data.valid_import_reference(p_reference jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $reference$
    SELECT COALESCE(pg_catalog.jsonb_typeof(p_reference)='object' AND p_reference ?& ARRAY['digest','retainedPins']
      AND p_reference-ARRAY['digest','retainedPins']='{}'::jsonb AND p_reference->>'digest'~'^[0-9a-f]{64}$'
      AND pg_catalog.jsonb_typeof(p_reference->'retainedPins')='boolean',false);
$reference$;
ALTER TABLE wormhole_data.nodes ADD COLUMN imported jsonb CHECK(imported IS NULL OR wormhole_data.valid_import_reference(imported));
CREATE TABLE wormhole_data.node_import_data (
    node_id uuid PRIMARY KEY REFERENCES wormhole_data.nodes(id),
    body bytea NOT NULL CHECK(octet_length(body) BETWEEN 2 AND 32768)
);
CREATE TABLE wormhole_data.workspace_import_receipts (
    request_id uuid PRIMARY KEY CHECK(request_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    actor_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    digest bytea NOT NULL CHECK(octet_length(digest)=32),
    signature bytea NOT NULL CHECK(octet_length(signature)=64),
    committed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
REVOKE ALL ON TABLE wormhole_data.node_import_data,wormhole_data.workspace_import_receipts
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
{{NODE_METADATA_DEFINITION}}
{{RESOLVER_NODE_VALID_DEFINITION}}
{{RESOLVE_CONNECTION_DEFINITION}}
{{EXPORT_WORKSPACE_DEFINITION}}
{{RESTORE_WORKSPACE_DEFINITION}}

-- Called only while the workspace snapshot is locked.
CREATE FUNCTION wormhole_data.imported_node_body(p_node uuid) RETURNS bytea
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $attachment$
DECLARE reference jsonb; data bytea;
BEGIN
    SELECT n.imported,d.body INTO reference,data FROM wormhole_data.nodes n
    LEFT JOIN wormhole_data.node_import_data d ON d.node_id=n.id WHERE n.id=p_node;
    IF (reference IS NULL) IS DISTINCT FROM (data IS NULL)
       OR reference->>'digest' IS DISTINCT FROM pg_catalog.encode(pg_catalog.sha256(data),'hex') THEN
        RAISE EXCEPTION 'Invalid imported node data' USING ERRCODE='WH025';
    END IF;
    RETURN data;
END
$attachment$;

CREATE FUNCTION wormhole_data.require_imported_pin_permissions(p_user uuid,p_data bytea,p_permission integer) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $permissions$
BEGIN
    IF EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(pg_catalog.convert_from(p_data,'UTF8')::jsonb->'pins') pin
        LEFT JOIN wormhole_data.credential_profiles c ON c.id=(pin->>'credentialId')::uuid AND NOT c.deleted
        WHERE pin->>'sourceKind'='saved'
          AND ((CASE WHEN c.id IS NULL THEN 0 ELSE wormhole_data.effective_boundary_permissions(p_user,c.boundary_id) END)&p_permission)<>p_permission) THEN
        RAISE EXCEPTION 'Node metadata unavailable' USING ERRCODE='WH014';
    END IF;
END
$permissions$;

CREATE FUNCTION wormhole_data.account_path_allowed(p_protocol integer,p_path text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $path$
    SELECT CASE p_path WHEN 'ssh' THEN p_protocol IN (0,7) WHEN 'sftp' THEN p_protocol IN (0,7)
        WHEN 'rdp' THEN p_protocol=1 WHEN 'rdp-gateway' THEN p_protocol=1 WHEN 'vnc' THEN p_protocol=6
        WHEN 'reveal' THEN p_protocol IN (0,1,3,4,5,6,7) ELSE false END;
$path$;

CREATE FUNCTION wormhole_data.default_use_path(p_protocol integer) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $path$
    SELECT CASE p_protocol WHEN 0 THEN 'ssh' WHEN 7 THEN 'sftp' WHEN 6 THEN 'vnc' WHEN 1 THEN 'rdp' END;
$path$;

CREATE FUNCTION wormhole_data.node_default_use_path(p_node uuid,p_epoch bigint,p_change_seq bigint) RETURNS text
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $path$
DECLARE chosen text;
BEGIN
    SELECT wormhole_data.default_use_path((c.node->>'protocol')::integer) INTO chosen
    FROM wormhole_data.resolution_chain(p_node,p_epoch,p_change_seq) c
    WHERE c.node->>'protocol' IS NOT NULL ORDER BY c.depth LIMIT 1;
    IF chosen IS NULL AND EXISTS(SELECT FROM wormhole_data.nodes n WHERE n.id=p_node AND n.imported->'retainedPins'='true'::jsonb) THEN
        RAISE EXCEPTION 'Imported resolver pins require a compatible client and server' USING ERRCODE='WH026';
    END IF;
    RETURN chosen;
END
$path$;

CREATE FUNCTION wormhole_data.retained_account(p_plan jsonb,p_path text,p_data bytea) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $pin$
DECLARE protocol integer:=(p_plan->>'protocol')::integer; candidate jsonb; selected jsonb;
BEGIN
    IF wormhole_data.account_path_allowed(protocol,p_path) IS NOT TRUE THEN
        RAISE EXCEPTION 'Invalid account path' USING ERRCODE='WH018';
    END IF;
    FOR candidate IN SELECT value FROM pg_catalog.jsonb_array_elements(pg_catalog.convert_from(p_data,'UTF8')::jsonb->'pins') LOOP
        IF wormhole_data.account_path_allowed(protocol,candidate->>'protocolPath') IS NOT TRUE THEN
            RAISE EXCEPTION 'Invalid imported account path' USING ERRCODE='WH025';
        END IF;
        IF candidate->>'protocolPath'=p_path THEN
            IF selected IS NOT NULL THEN RAISE EXCEPTION 'Duplicate imported account path' USING ERRCODE='WH025'; END IF;
            selected:=candidate;
        END IF;
    END LOOP;
    IF p_plan#>>'{credential,kind}'='override'
       AND (p_path<>'rdp-gateway' OR p_plan->'gatewaySameCredentials'='true'::jsonb) THEN
        RETURN NULL;
    END IF;
    RETURN selected;
END
$pin$;

CREATE FUNCTION wormhole_data.apply_retained_account(p_plan jsonb,p_pin jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $pin$
DECLARE source text:=p_pin->>'sourceKind'; choice jsonb;
BEGIN
    IF source='system' THEN
        p_plan:=p_plan||pg_catalog.jsonb_build_object('externalRdpClient',true);
        choice:=pg_catalog.jsonb_build_object('kind','none','id','','nodeId','');
    ELSE
        choice:=pg_catalog.jsonb_build_object('kind',source,'id',p_pin->>'credentialId','nodeId',p_pin->>'nodeId');
    END IF;
    RETURN p_plan||pg_catalog.jsonb_build_object('credential',choice,'username',p_pin->>'username','domain',p_pin->>'domain');
END
$pin$;

CREATE FUNCTION wormhole_data.gateway_candidate(p_plan jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $candidate$
DECLARE choice jsonb;
BEGIN
    IF p_plan->'gatewayMethod'<>'0'::jsonb AND p_plan->'gatewaySameCredentials'='true'::jsonb THEN RETURN p_plan; END IF;
    IF p_plan->'gatewayMethod'<>'0'::jsonb AND p_plan->>'gatewayCredentialId'<>'' THEN
        choice:=pg_catalog.jsonb_build_object('kind','saved','id',p_plan->>'gatewayCredentialId','nodeId',p_plan->>'nodeId');
    ELSE
        choice:=pg_catalog.jsonb_build_object('kind','none','id','','nodeId','');
    END IF;
    RETURN p_plan||pg_catalog.jsonb_build_object('credential',choice,'username','','domain','');
END
$candidate$;

{{CONNECTION_PATH_DEFINITIONS}}
REVOKE ALL ON FUNCTION wormhole_data.imported_node_body(uuid),wormhole_data.require_imported_pin_permissions(uuid,bytea,integer),
    wormhole_data.account_path_allowed(integer,text),wormhole_data.default_use_path(integer),
    wormhole_data.node_default_use_path(uuid,bigint,bigint),wormhole_data.retained_account(jsonb,text,bytea),
    wormhole_data.apply_retained_account(jsonb,jsonb),wormhole_data.gateway_candidate(jsonb),
    wormhole_data.resolve_connection(uuid,uuid,bigint,bigint,text),wormhole_data.connection_snapshot(uuid,uuid,bigint,bigint,text),
    wormhole_data.connection_account_permissions(bytea,uuid,bigint,bigint,integer,text)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.connection_plan_path(bytea,uuid,text)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.connection_plan_path(bytea,uuid,text) TO wh_{{TAG}}_user;

-- Explicit paths use the same rollback-resistant counter as ordinary and
-- fallback releases. Both the committed audit and one-use ticket name the path.
ALTER TABLE wormhole_data.audit_log ADD COLUMN protocol_path text CHECK(protocol_path IN ('ssh','sftp','vnc','rdp'));
ALTER TABLE wormhole_data.use_tickets
 ADD COLUMN protocol_path text,
 DROP CONSTRAINT use_ticket_purpose,
 ADD CONSTRAINT use_ticket_purpose CHECK (
    (release_kind='connection' AND primary_tunnel_id IS NULL AND fallback_tunnel_id IS NULL AND protocol_path IS NULL) OR
    (release_kind='fallback' AND primary_tunnel_id IS NOT NULL AND fallback_tunnel_id IS NOT NULL AND protocol_path IS NULL
        AND primary_tunnel_id<>'00000000-0000-0000-0000-000000000000'::uuid
        AND fallback_tunnel_id<>'00000000-0000-0000-0000-000000000000'::uuid
        AND primary_tunnel_id<>fallback_tunnel_id) OR
    (release_kind='connection_path' AND primary_tunnel_id IS NULL AND fallback_tunnel_id IS NULL
        AND protocol_path IS NOT NULL AND protocol_path IN ('ssh','sftp','vnc','rdp')));

{{PATH_RELEASE_DEFINITIONS}}

-- A single RDP ticket authorizes both selected accounts in the same locked
-- snapshot. The gateway path has no independent ticket or fetch entry point.
CREATE FUNCTION wormhole_data.path_release_permissions(p_capability bytea,p_node uuid,p_epoch bigint,p_change_seq bigint,p_path text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $permissions$
DECLARE primary_plan jsonb;
BEGIN
    primary_plan:=wormhole_data.connection_account_permissions(p_capability,p_node,p_epoch,p_change_seq,2,p_path);
    IF primary_plan->'protocol'='1'::jsonb AND primary_plan->'gatewayMethod'<>'0'::jsonb THEN
        PERFORM wormhole_data.connection_account_permissions(p_capability,p_node,p_epoch,p_change_seq,2,'rdp-gateway');
    END IF;
    RETURN primary_plan;
END
$permissions$;

CREATE FUNCTION wormhole_data.rdp_release_graph(p_node uuid,p_user uuid,p_epoch bigint,p_change_seq bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $rdp$
DECLARE primary_graph jsonb; gateway_graph jsonb; result jsonb;
BEGIN
    primary_graph:=wormhole_data.credential_release_graph(p_node,p_user,p_epoch,p_change_seq,'rdp');
    IF primary_graph#>'{metadata,plan,gatewayMethod}'<>'0'::jsonb THEN
        gateway_graph:=wormhole_data.credential_release_graph(p_node,p_user,p_epoch,p_change_seq,'rdp-gateway');
    END IF;
    result:=pg_catalog.jsonb_build_object('formatVersion',6,'primary',primary_graph,'gateway',gateway_graph);
    IF octet_length(result::text)>67108864 THEN RAISE EXCEPTION 'RDP release graph is too large' USING ERRCODE='54000'; END IF;
    RETURN result;
END
$rdp$;

CREATE OR REPLACE FUNCTION wormhole_data.begin_use_intent(p_capability bytea,p_node uuid,p_source text,p_primary uuid,p_fallback uuid)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,epoch bigint,change_seq bigint,expires_at bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $ordinary$
    SELECT i.workspace_id,i.user_id,i.device_id,i.node_id,i.ticket_id,i.epoch,i.change_seq,i.expires_at
    FROM wormhole_data.begin_use_intent(p_capability,p_node,p_source,p_primary,p_fallback,NULL) i
$ordinary$;

CREATE FUNCTION wormhole_api_v1.begin_use_path(p_capability bytea,p_node uuid,p_source text,p_path text)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,ticket_id uuid,epoch bigint,
    change_seq bigint,expires_at bigint,protocol_path text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $path$
BEGIN
    IF p_path IS NULL THEN RAISE EXCEPTION 'Missing credential path' USING ERRCODE='22023'; END IF;
    RETURN QUERY SELECT * FROM wormhole_data.begin_use_intent(p_capability,p_node,p_source,NULL,NULL,p_path);
END
$path$;

REVOKE ALL ON FUNCTION wormhole_data.credential_release_graph(uuid,uuid,bigint,bigint,text),
    wormhole_data.begin_use_intent(bytea,uuid,text,uuid,uuid,text),wormhole_data.claim_use_intent(bytea,uuid,uuid,uuid,uuid,text),
    wormhole_data.path_release_permissions(bytea,uuid,bigint,bigint,text),wormhole_data.rdp_release_graph(uuid,uuid,bigint,bigint)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.begin_use_path(bytea,uuid,text,text),wormhole_api_v1.fetch_secret_path(bytea,uuid,uuid,text)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.begin_use_path(bytea,uuid,text,text),wormhole_api_v1.fetch_secret_path(bytea,uuid,uuid,text)
    TO wh_{{TAG}}_user;

-- A point read from a single workspace snapshot. The attachment is account
-- metadata only. Secret values and key copies require their own release.
CREATE FUNCTION wormhole_api_v1.imported_node_data(p_capability bytea,p_node uuid)
RETURNS TABLE(user_id uuid,device_id uuid,projection jsonb,body bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $node_data$
DECLARE identity record; meta record; item wormhole_data.nodes; author record; data bytea;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    SELECT n.* INTO item FROM wormhole_data.nodes n WHERE n.id=p_node;
    IF NOT FOUND OR item.seal IS NULL OR item.name IS NULL OR item.encrypted_metadata IS NOT NULL THEN
        RAISE EXCEPTION 'Node metadata unavailable' USING ERRCODE='WH014';
    END IF;
    IF (wormhole_data.effective_permissions(identity.user_id,p_node)&3)<>3
       OR (wormhole_data.effective_boundary_permissions(identity.user_id,item.boundary_id)&2)<>2 THEN
        RAISE EXCEPTION 'Node metadata unavailable' USING ERRCODE='WH014';
    END IF;
    data:=wormhole_data.imported_node_body(p_node);
    PERFORM wormhole_data.require_imported_pin_permissions(identity.user_id,data,2);
    SELECT * INTO STRICT author FROM wormhole_data.node_author_material(item.seal_signer_key_id,item.seal_signer_key_version);
    RETURN QUERY SELECT identity.user_id,identity.device_id,wormhole_data.catalog_projection_wire(
        pg_catalog.to_jsonb(author)||pg_catalog.jsonb_build_object(
        'workspace_id',meta.workspace_id,'subject_id',item.id,'epoch',meta.epoch,'change_seq',meta.change_seq,
        'boundary_id',item.boundary_id,'row_version',item.row_version,'seal_suite',item.seal_suite,
        'seal_signer_key_id',item.seal_signer_key_id,'seal_signer_key_version',item.seal_signer_key_version,
        'seal_capability_id',item.seal_capability_id,'seal',item.seal,'record',wormhole_data.node_metadata(item))),data;
END
$node_data$;
REVOKE ALL ON FUNCTION wormhole_api_v1.imported_node_data(bytea,uuid)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.imported_node_data(bytea,uuid) TO wh_{{TAG}}_user;

CREATE FUNCTION wormhole_data.import_columns(p_row jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $columns$
    SELECT pg_catalog.jsonb_object_agg(pg_catalog.lower(pg_catalog.regexp_replace(key,'([A-Z])','_\1','g') COLLATE "C"),value)
    FROM pg_catalog.jsonb_each(p_row);
$columns$;

CREATE FUNCTION wormhole_data.import_seal(p_item jsonb,p_signer uuid,p_signer_version integer) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $seal$
DECLARE signature bytea;
BEGIN
    IF p_item->'formatVersion' IS DISTINCT FROM '1'::jsonb OR p_item->'revision' IS DISTINCT FROM '1'::jsonb
       OR p_item->>'signerKeyId' IS DISTINCT FROM p_signer::text
       OR p_item->'signerKeyVersion' IS DISTINCT FROM pg_catalog.to_jsonb(p_signer_version)
       OR p_item->'capabilityId' IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'Invalid import seal' USING ERRCODE='WH025';
    END IF;
    signature:=pg_catalog.decode(p_item->>'signature','base64');
    IF octet_length(signature) IS DISTINCT FROM 64 THEN
        RAISE EXCEPTION 'Invalid import seal' USING ERRCODE='WH025';
    END IF;
    RETURN signature;
END
$seal$;

{{COMMIT_WORKSPACE_IMPORT_DEFINITION}}

REVOKE ALL ON FUNCTION wormhole_data.import_columns(jsonb),wormhole_data.import_seal(jsonb,uuid,integer),wormhole_data.valid_import_reference(jsonb)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_api_v1.commit_workspace_import(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.commit_workspace_import(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,text,bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=55 WHERE singleton;
COMMIT;
