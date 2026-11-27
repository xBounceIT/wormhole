-- Version 98: signed, scoped credential slot choices for a writable node.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>97 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;
{{NODE_EDIT_BINDINGS}}

CREATE FUNCTION wormhole_api_v1.node_slot_choices(p_capability bytea,p_node uuid,p_revision bigint,p_epoch bigint,p_sequence bigint,
    p_after uuid,p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $choices$
DECLARE actor record; meta record; candidate uuid; wire jsonb; items jsonb:='[]'; count_rows integer:=0;
    page_bytes integer:=2; wire_bytes integer; outcome text:='ready';
BEGIN
    IF p_node IS NULL OR p_revision IS NULL OR p_revision<1 OR p_epoch IS NULL OR p_epoch<1 OR p_sequence IS NULL OR p_sequence<0
        OR p_after='00000000-0000-0000-0000-000000000000'::uuid
        OR octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_account_state) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid node slot page' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' OR (meta.epoch,meta.change_seq)<>(p_epoch,p_sequence)
        OR sha256(meta.signed_profile) IS DISTINCT FROM p_policy
        OR NOT EXISTS(SELECT FROM wormhole_data.current_connection_tls() t WHERE t.ssl)
        OR NOT EXISTS(SELECT FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id
            AND sha256(s.signed_state)=p_account_state AND convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true' FOR SHARE NOWAIT)
        OR NOT EXISTS(SELECT FROM wormhole_data.nodes n WHERE n.id=p_node AND n.row_version=p_revision AND n.seal IS NOT NULL
            AND n.encrypted_metadata IS NULL AND (n.kind<>1 OR n.use_inline_password IS NOT TRUE)
            AND (wormhole_data.effective_permissions(actor.user_id,n.id)&5)=5) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
{{VISIBLE_SLOT_PAGE}}
END
$choices$;
REVOKE ALL ON FUNCTION wormhole_api_v1.node_slot_choices(bytea,uuid,bigint,bigint,bigint,uuid,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.node_slot_choices(bytea,uuid,bigint,bigint,bigint,uuid,bytea,bytea) TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=98 WHERE singleton;
COMMIT;
