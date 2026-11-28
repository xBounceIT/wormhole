-- Version 88: authorize a signed whole-node edit against the resulting accounts.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>87 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

{{ED25519_VERIFY}}
{{NODE_EDIT_MESSAGE}}

-- Check authority on the resulting account, even when it was selected for
-- another user. Group grants and personal boundaries retain their normal rules.
CREATE FUNCTION wormhole_data.node_edit_can_reveal(p_actor uuid,p_mask integer,p_boundary uuid,p_plan jsonb,p_web boolean)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $reveal$
DECLARE item record; kind text:=p_plan#>>'{credential,kind}';
BEGIN
    IF kind NOT IN ('none','inline','saved','override') OR kind IS NULL THEN RETURN false; END IF;
    IF (kind='inline' OR p_web) AND ((p_mask&8)<>8 OR
        (wormhole_data.effective_boundary_permissions(p_actor,p_boundary)&8)<>8) THEN RETURN false; END IF;
    FOR item IN SELECT c.boundary_id,c.owner_user_id FROM unnest(ARRAY[
            CASE WHEN kind IN ('saved','override') THEN (p_plan#>>'{credential,id}')::uuid END,
            NULLIF(p_plan->>'gatewayCredentialId','')::uuid]) AS selected(credential_id)
            LEFT JOIN wormhole_data.credential_profiles c ON c.id=selected.credential_id AND NOT c.deleted WHERE selected.credential_id IS NOT NULL
    LOOP
        IF (p_mask&8)<>8 OR item.boundary_id IS NULL OR (item.owner_user_id IS NOT NULL AND item.owner_user_id<>p_actor) OR
            (wormhole_data.effective_boundary_permissions(p_actor,item.boundary_id)&8)<>8 THEN RETURN false; END IF;
    END LOOP;
    IF p_plan->>'tunnelId'<>'' THEN
        SELECT t.boundary_id INTO item FROM wormhole_data.tunnel_profiles t WHERE t.id=(p_plan->>'tunnelId')::uuid AND NOT t.deleted;
        IF NOT FOUND OR (p_mask&8)<>8 OR (wormhole_data.effective_boundary_permissions(p_actor,item.boundary_id)&8)<>8 THEN RETURN false; END IF;
    END IF;
    RETURN true;
END
$reveal$;
REVOKE ALL ON FUNCTION wormhole_data.node_edit_can_reveal(uuid,integer,uuid,jsonb,boolean) FROM PUBLIC;

-- A folder's inherited settings may change different accounts for different
-- descendants. Only public resolution metadata is read. No account identity or
-- projection leaves this private function. The writer holds the catalog lock.
{{NODE_EDIT_BINDINGS}}

-- Return the same public node shape used by get_tree, plus the optional
-- signed field manifest. Neither a connection nor Use access is required to
-- edit a visible writable folder.
{{READ_NODE_EDIT}}
REVOKE ALL ON FUNCTION wormhole_api_v1.read_node_edit(bytea,uuid,bigint,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.read_node_edit(bytea,uuid,bigint,bytea,bytea) TO wh_{{TAG}}_user;

CREATE FUNCTION wormhole_api_v1.update_node(p_capability bytea,p_node uuid,p_epoch bigint,p_sequence bigint,p_revision bigint,
    p_metadata jsonb,p_signer uuid,p_signer_version integer,p_seal bytea,p_fields_seal bytea,p_policy bytea,p_state bytea)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $edit$
DECLARE actor record; meta wormhole_data.workspace_meta; original wormhole_data.nodes; updated wormhole_data.nodes;
    old_metadata jsonb; fields wormhole_data.node_secret_manifests; has_fields boolean; compare_bindings boolean;
    previous jsonb; live_sequence bigint; session_row record; public_key bytea;
BEGIN
    IF p_node IS NULL OR p_epoch IS NULL OR p_epoch<1 OR p_sequence IS NULL OR p_sequence<0 OR
        p_revision IS NULL OR p_revision NOT BETWEEN 1 AND 9223372036854775806 OR
        jsonb_typeof(p_metadata) IS DISTINCT FROM 'object' OR octet_length(p_metadata::text)>524288 OR
        p_signer IS NULL OR p_signer_version IS NULL OR p_signer_version<1 OR octet_length(p_seal) IS DISTINCT FROM 64 OR
        octet_length(p_fields_seal)<>64 OR octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_state) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid node edit' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF meta.state<>'ready' OR meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 OR
        (meta.epoch,meta.change_seq)<>(p_epoch,p_sequence) OR sha256(meta.signed_profile) IS DISTINCT FROM p_policy OR
        NOT EXISTS(SELECT FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id AND sha256(s.signed_state)=p_state
            AND convert_from(s.signed_state,'UTF8')::jsonb->'active'='true'::jsonb) THEN RETURN 'stale'; END IF;
    SELECT * INTO original FROM wormhole_data.nodes WHERE id=p_node;
    IF NOT FOUND OR original.seal IS NULL OR original.encrypted_metadata IS NOT NULL OR
        (wormhole_data.effective_permissions(actor.user_id,p_node)&5)<>5 THEN RETURN 'unavailable'; END IF;
    IF original.row_version<>p_revision THEN RETURN 'stale'; END IF;
    old_metadata:=wormhole_data.node_metadata(original);
    IF NOT wormhole_data.resolver_node_valid(p_metadata) OR old_metadata=p_metadata OR
        (p_metadata->'id',p_metadata->'parentId',p_metadata->'kind',p_metadata->'ownerUserId',p_metadata->'imported',p_metadata->'sshKnownHostFingerprint')
        IS DISTINCT FROM (old_metadata->'id',old_metadata->'parentId',old_metadata->'kind',old_metadata->'ownerUserId',old_metadata->'imported',old_metadata->'sshKnownHostFingerprint') THEN RETURN 'unavailable'; END IF;
    SELECT * INTO updated FROM jsonb_populate_record(NULL::wormhole_data.nodes,wormhole_data.import_columns(p_metadata));
    IF wormhole_data.node_metadata(updated) IS DISTINCT FROM p_metadata THEN RETURN 'unavailable'; END IF;
    SELECT * INTO fields FROM wormhole_data.node_secret_manifests WHERE node_id=p_node;
    has_fields:=FOUND;
    IF has_fields<>(p_fields_seal IS NOT NULL) OR (updated.use_inline_password IS TRUE)<>EXISTS(
        SELECT FROM jsonb_array_elements(fields.fields) f WHERE f->>'field'='inlinePassword' AND (f->>'present')::boolean) OR
       (has_fields AND (fields.deleted OR (fields.row_version,fields.boundary_id)<>(p_revision,original.boundary_id))) THEN RETURN 'stale'; END IF;
{{NODE_EDIT_VERIFY_SEALS}}
    compare_bindings:=(old_metadata-'name'-'sortOrder')<>(p_metadata-'name'-'sortOrder');
    IF compare_bindings THEN
        SELECT jsonb_object_agg(b.binding,encode(b.digest,'hex')) INTO previous
            FROM wormhole_data.node_edit_bindings(actor.user_id,p_node,p_epoch,p_sequence) b;
    END IF;
    -- Assign only writable metadata columns. The row identity, authenticated
    -- attachments, encryption metadata and structural links stay with the row.
    UPDATE wormhole_data.nodes SET (name,sort_order,protocol,host,
        port,http_path,username,credential_id,
        credential_mode,credential_slot_id,use_inline_password,ssh_auto_sudo,
        http_ignore_cert_errors,tunnel_enabled,tunnel_config_id,serial_baud_rate,
        serial_data_bits,serial_stop_bits,serial_parity,serial_flow_control,
        ssh_key_file_name,rdp_domain,rdp_screen_size,rdp_full_screen,
        rdp_color_depth,rdp_use_all_monitors,rdp_audio_mode,rdp_audio_capture_mode,
        rdp_keyboard_hook_mode,rdp_redirect_clipboard,rdp_redirect_printers,rdp_redirect_smart_cards,
        rdp_redirect_ports,rdp_redirect_devices,rdp_redirect_drives,rdp_connection_speed,
        rdp_desktop_background,rdp_font_smoothing,rdp_desktop_composition,rdp_window_drag,
        rdp_menu_animation,rdp_visual_styles,rdp_bitmap_caching,rdp_auto_reconnect,
        rdp_server_authentication,rdp_gateway_usage_method,rdp_gateway_hostname,rdp_gateway_credential_id,
        rdp_gateway_bypass_local,rdp_gateway_use_same_creds,rdp_use_external_client)=(updated.name,updated.sort_order,updated.protocol,updated.host,
        updated.port,updated.http_path,updated.username,updated.credential_id,
        updated.credential_mode,updated.credential_slot_id,updated.use_inline_password,updated.ssh_auto_sudo,
        updated.http_ignore_cert_errors,updated.tunnel_enabled,updated.tunnel_config_id,updated.serial_baud_rate,
        updated.serial_data_bits,updated.serial_stop_bits,updated.serial_parity,updated.serial_flow_control,
        updated.ssh_key_file_name,updated.rdp_domain,updated.rdp_screen_size,updated.rdp_full_screen,
        updated.rdp_color_depth,updated.rdp_use_all_monitors,updated.rdp_audio_mode,updated.rdp_audio_capture_mode,
        updated.rdp_keyboard_hook_mode,updated.rdp_redirect_clipboard,updated.rdp_redirect_printers,updated.rdp_redirect_smart_cards,
        updated.rdp_redirect_ports,updated.rdp_redirect_devices,updated.rdp_redirect_drives,updated.rdp_connection_speed,
        updated.rdp_desktop_background,updated.rdp_font_smoothing,updated.rdp_desktop_composition,updated.rdp_window_drag,
        updated.rdp_menu_animation,updated.rdp_visual_styles,updated.rdp_bitmap_caching,updated.rdp_auto_reconnect,
        updated.rdp_server_authentication,updated.rdp_gateway_usage_method,updated.rdp_gateway_hostname,updated.rdp_gateway_credential_id,
        updated.rdp_gateway_bypass_local,updated.rdp_gateway_use_same_creds,updated.rdp_use_external_client),
        row_version=p_revision+1,seal_signer_key_id=p_signer,seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_seal
        WHERE id=p_node;
    IF has_fields THEN
        UPDATE wormhole_data.node_secret_manifests SET row_version=p_revision+1,seal_signer_key_id=p_signer,
            seal_signer_key_version=p_signer_version,seal_capability_id=NULL,seal=p_fields_seal WHERE node_id=p_node;
    END IF;
    IF compare_bindings THEN
        SELECT change_seq INTO STRICT live_sequence FROM wormhole_data.workspace_meta WHERE singleton;
        IF EXISTS(SELECT FROM wormhole_data.node_edit_bindings(actor.user_id,p_node,p_epoch,live_sequence) b
            WHERE previous->>b.binding IS DISTINCT FROM encode(b.digest,'hex') AND b.can_reveal IS NOT TRUE) THEN
            RAISE EXCEPTION 'Node edit requires Reveal' USING ERRCODE='42501';
        END IF;
    END IF;
    SELECT s.id,s.app_version INTO STRICT session_row FROM wormhole_data.device_admissions a JOIN wormhole_data.sessions s ON s.id=a.session_id
        WHERE a.device_id=actor.device_id AND s.user_id=actor.user_id;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,node_id)
        VALUES(actor.user_id,session_row.id,session_user,'ui','update_node','success',inet_client_addr(),session_row.app_version,p_node);
    RETURN 'changed';
EXCEPTION WHEN lock_not_available THEN RETURN 'busy';
    WHEN insufficient_privilege OR no_data_found OR SQLSTATE 'WH014' OR SQLSTATE 'WH016' OR SQLSTATE 'WH017' OR SQLSTATE 'WH018' OR SQLSTATE 'WH019' OR SQLSTATE 'WH025' THEN RETURN 'unavailable';
END
$edit$;
REVOKE ALL ON FUNCTION wormhole_api_v1.update_node(bytea,uuid,bigint,bigint,bigint,jsonb,uuid,integer,bytea,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.update_node(bytea,uuid,bigint,bigint,bigint,jsonb,uuid,integer,bytea,bytea,bytea,bytea) TO wh_{{TAG}}_user;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=88 WHERE singleton;
COMMIT;
