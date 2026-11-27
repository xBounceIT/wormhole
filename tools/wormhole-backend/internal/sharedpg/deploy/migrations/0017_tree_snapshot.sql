-- Version 17: node metadata and view-filtered snapshot paging. No runtime writes.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>16 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.nodes
    ADD COLUMN name text NULL CHECK (name IS NULL OR pg_catalog.octet_length(name)<=1024),
    ADD COLUMN sort_order bigint NOT NULL DEFAULT 0,
    ADD COLUMN protocol integer NULL,
    ADD COLUMN host text NULL CHECK (host IS NULL OR pg_catalog.octet_length(host)<=16384),
    ADD COLUMN port integer NULL,
    ADD COLUMN http_path text NULL CHECK (http_path IS NULL OR pg_catalog.octet_length(http_path)<=16384),
    ADD COLUMN username text NULL CHECK (username IS NULL OR pg_catalog.octet_length(username)<=2048),
    ADD COLUMN credential_id uuid NULL CHECK (credential_id IS NULL OR credential_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    ADD COLUMN credential_mode integer NULL,
    ADD COLUMN credential_slot_id uuid NULL CHECK (credential_slot_id IS NULL OR credential_slot_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    ADD COLUMN use_inline_password boolean NULL,
    ADD COLUMN ssh_auto_sudo boolean NULL,
    ADD COLUMN http_ignore_cert_errors boolean NULL,
    ADD COLUMN tunnel_enabled boolean NULL,
    ADD COLUMN tunnel_config_id uuid NULL CHECK (tunnel_config_id IS NULL OR tunnel_config_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    ADD COLUMN serial_baud_rate integer NULL,
    ADD COLUMN serial_data_bits integer NULL,
    ADD COLUMN serial_stop_bits integer NULL,
    ADD COLUMN serial_parity integer NULL,
    ADD COLUMN serial_flow_control integer NULL,
    ADD COLUMN ssh_key_file_name text NULL CHECK (ssh_key_file_name IS NULL OR pg_catalog.octet_length(ssh_key_file_name)<=1024),
    ADD COLUMN ssh_known_host_fingerprint text NULL CHECK (ssh_known_host_fingerprint IS NULL OR pg_catalog.octet_length(ssh_known_host_fingerprint)<=128),
    ADD COLUMN rdp_domain text NULL CHECK (rdp_domain IS NULL OR pg_catalog.octet_length(rdp_domain)<=2048),
    ADD COLUMN rdp_screen_size text NULL CHECK (rdp_screen_size IS NULL OR pg_catalog.octet_length(rdp_screen_size)<=128),
    ADD COLUMN rdp_full_screen boolean NULL,
    ADD COLUMN rdp_color_depth integer NULL,
    ADD COLUMN rdp_use_all_monitors boolean NULL,
    ADD COLUMN rdp_audio_mode integer NULL,
    ADD COLUMN rdp_audio_capture_mode integer NULL,
    ADD COLUMN rdp_keyboard_hook_mode integer NULL,
    ADD COLUMN rdp_redirect_clipboard boolean NULL,
    ADD COLUMN rdp_redirect_printers boolean NULL,
    ADD COLUMN rdp_redirect_smart_cards boolean NULL,
    ADD COLUMN rdp_redirect_ports boolean NULL,
    ADD COLUMN rdp_redirect_devices boolean NULL,
    ADD COLUMN rdp_redirect_drives text NULL CHECK (rdp_redirect_drives IS NULL OR pg_catalog.octet_length(rdp_redirect_drives)<=512),
    ADD COLUMN rdp_connection_speed integer NULL,
    ADD COLUMN rdp_desktop_background boolean NULL,
    ADD COLUMN rdp_font_smoothing boolean NULL,
    ADD COLUMN rdp_desktop_composition boolean NULL,
    ADD COLUMN rdp_window_drag boolean NULL,
    ADD COLUMN rdp_menu_animation boolean NULL,
    ADD COLUMN rdp_visual_styles boolean NULL,
    ADD COLUMN rdp_bitmap_caching boolean NULL,
    ADD COLUMN rdp_auto_reconnect boolean NULL,
    ADD COLUMN rdp_server_authentication integer NULL,
    ADD COLUMN rdp_gateway_usage_method integer NULL,
    ADD COLUMN rdp_gateway_hostname text NULL CHECK (rdp_gateway_hostname IS NULL OR pg_catalog.octet_length(rdp_gateway_hostname)<=4096),
    ADD COLUMN rdp_gateway_credential_id uuid NULL CHECK (rdp_gateway_credential_id IS NULL OR rdp_gateway_credential_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    ADD COLUMN rdp_gateway_bypass_local boolean NULL,
    ADD COLUMN rdp_gateway_use_same_creds boolean NULL,
    ADD COLUMN rdp_use_external_client boolean NULL,
    ADD COLUMN boundary_id uuid NULL CHECK(boundary_id IS NULL OR boundary_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    ADD COLUMN seal_suite smallint NULL CHECK(seal_suite=2),
    ADD COLUMN seal_signer_key_id uuid NULL,
    ADD COLUMN seal_signer_key_version integer NULL,
    ADD COLUMN seal_capability_id uuid NULL CHECK(seal_capability_id IS NULL OR seal_capability_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    ADD COLUMN seal bytea NULL CHECK(pg_catalog.octet_length(seal)=64),
    ADD COLUMN encrypted_metadata bytea NULL CHECK(pg_catalog.octet_length(encrypted_metadata) BETWEEN 16 AND 131072),
    ADD COLUMN metadata_key_id uuid NULL,
    ADD COLUMN metadata_key_version integer NULL,
    ADD COLUMN name_blind_index bytea NULL CHECK(pg_catalog.octet_length(name_blind_index)=32),
    ADD FOREIGN KEY(seal_signer_key_id,seal_signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version) MATCH FULL,
    ADD FOREIGN KEY(metadata_key_id,metadata_key_version) REFERENCES wormhole_data.keys(key_id,key_version) MATCH FULL,
    ADD CHECK(pg_catalog.num_nonnulls(boundary_id,seal_suite,seal_signer_key_id,seal_signer_key_version,seal) IN (0,5)),
    ADD CHECK(seal_capability_id IS NULL OR seal IS NOT NULL),
    ADD CHECK(pg_catalog.num_nonnulls(encrypted_metadata,metadata_key_id,metadata_key_version,name_blind_index) IN (0,4));

-- All hierarchy/permission writes invalidate a page sequence before touching
-- rows. Readers hold workspace_meta FOR SHARE, preventing a mixed page snapshot.
CREATE FUNCTION wormhole_data.tree_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $changed$
DECLARE workspace uuid;
BEGIN
    UPDATE wormhole_data.workspace_meta SET change_seq=change_seq+1 WHERE singleton RETURNING workspace_id INTO STRICT workspace;
    PERFORM pg_catalog.pg_notify('wormhole_changes',workspace::text);
    RETURN NULL;
END
$changed$;
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.nodes
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.grants
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.groups
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.group_members
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
CREATE TRIGGER tree_changed BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON wormhole_data.users
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.tree_changed();
REVOKE ALL ON FUNCTION wormhole_data.tree_changed() FROM PUBLIC;

CREATE FUNCTION wormhole_api_v1.get_tree(p_capability bytea,p_after uuid DEFAULT NULL,
    p_epoch bigint DEFAULT NULL,p_change_seq bigint DEFAULT NULL,p_limit integer DEFAULT 32)
RETURNS TABLE(workspace_id uuid,user_id uuid,epoch bigint,change_seq bigint,resolver_version integer,
    has_more boolean,node jsonb,permissions integer,boundary_id uuid,row_version bigint,
    seal_suite smallint,seal_signer_key_id uuid,seal_signer_key_version integer,seal_capability_id uuid,seal bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $tree$
DECLARE identity record; meta record; ids uuid[]; masks integer[]; count integer; i integer; item record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_limit IS NULL OR p_limit<1 OR p_limit>32
       OR (p_after IS NULL AND (p_epoch IS NOT NULL OR p_change_seq IS NOT NULL))
       OR (p_after IS NOT NULL AND (p_after='00000000-0000-0000-0000-000000000000'::uuid OR p_epoch IS NULL OR p_epoch<1 OR p_change_seq IS NULL OR p_change_seq<0)) THEN
        RAISE EXCEPTION 'Invalid tree page request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_after IS NOT NULL AND (p_epoch<>meta.epoch OR p_change_seq<>meta.change_seq) THEN
        RAISE EXCEPTION 'Tree snapshot changed' USING ERRCODE='WH013';
    END IF;
    SELECT pg_catalog.array_agg(visible.id ORDER BY visible.id),pg_catalog.array_agg(visible.mask ORDER BY visible.id)
    INTO ids,masks FROM (
        SELECT n.id,p.mask FROM wormhole_data.nodes n
        CROSS JOIN LATERAL (SELECT wormhole_data.effective_permissions(identity.user_id,n.id) AS mask OFFSET 0) p
        WHERE (p_after IS NULL OR n.id>p_after) AND (p.mask & 1)=1
        ORDER BY n.id LIMIT p_limit+1
    ) visible;
    count:=COALESCE(pg_catalog.cardinality(ids),0);
    workspace_id:=meta.workspace_id; user_id:=identity.user_id;
    epoch:=meta.epoch; change_seq:=meta.change_seq; resolver_version:=meta.resolver_version;
    has_more:=count>p_limit;
    IF count=0 THEN RETURN NEXT; RETURN; END IF;
    FOR i IN 1..LEAST(count,p_limit) LOOP
        SELECT n.* INTO STRICT item FROM wormhole_data.nodes n WHERE n.id=ids[i];
        IF item.encrypted_metadata IS NOT NULL THEN
            RAISE EXCEPTION 'Encrypted tree projection is not available' USING ERRCODE='0A000';
        END IF;
        IF item.seal IS NULL OR item.name IS NULL THEN
            RAISE EXCEPTION 'Node metadata is not provisioned' USING ERRCODE='WH014';
        END IF;
        SELECT pg_catalog.to_jsonb(metadata) INTO node FROM (
            SELECT n.id AS "id",
                n.parent_id AS "parentId",
                n.owner_user_id AS "ownerUserId",
                n.name AS "name",
                n.kind AS "kind",
                n.sort_order AS "sortOrder",
                n.protocol AS "protocol",
                n.host AS "host",
                n.port AS "port",
                n.http_path AS "httpPath",
                n.username AS "username",
                n.credential_id AS "credentialId",
                n.credential_mode AS "credentialMode",
                n.credential_slot_id AS "credentialSlotId",
                n.use_inline_password AS "useInlinePassword",
                n.ssh_auto_sudo AS "sshAutoSudo",
                n.http_ignore_cert_errors AS "httpIgnoreCertErrors",
                n.tunnel_enabled AS "tunnelEnabled",
                n.tunnel_config_id AS "tunnelConfigId",
                n.serial_baud_rate AS "serialBaudRate",
                n.serial_data_bits AS "serialDataBits",
                n.serial_stop_bits AS "serialStopBits",
                n.serial_parity AS "serialParity",
                n.serial_flow_control AS "serialFlowControl",
                n.ssh_key_file_name AS "sshKeyFileName",
                n.ssh_known_host_fingerprint AS "sshKnownHostFingerprint",
                n.rdp_domain AS "rdpDomain",
                n.rdp_screen_size AS "rdpScreenSize",
                n.rdp_full_screen AS "rdpFullScreen",
                n.rdp_color_depth AS "rdpColorDepth",
                n.rdp_use_all_monitors AS "rdpUseAllMonitors",
                n.rdp_audio_mode AS "rdpAudioMode",
                n.rdp_audio_capture_mode AS "rdpAudioCaptureMode",
                n.rdp_keyboard_hook_mode AS "rdpKeyboardHookMode",
                n.rdp_redirect_clipboard AS "rdpRedirectClipboard",
                n.rdp_redirect_printers AS "rdpRedirectPrinters",
                n.rdp_redirect_smart_cards AS "rdpRedirectSmartCards",
                n.rdp_redirect_ports AS "rdpRedirectPorts",
                n.rdp_redirect_devices AS "rdpRedirectDevices",
                n.rdp_redirect_drives AS "rdpRedirectDrives",
                n.rdp_connection_speed AS "rdpConnectionSpeed",
                n.rdp_desktop_background AS "rdpDesktopBackground",
                n.rdp_font_smoothing AS "rdpFontSmoothing",
                n.rdp_desktop_composition AS "rdpDesktopComposition",
                n.rdp_window_drag AS "rdpWindowDrag",
                n.rdp_menu_animation AS "rdpMenuAnimation",
                n.rdp_visual_styles AS "rdpVisualStyles",
                n.rdp_bitmap_caching AS "rdpBitmapCaching",
                n.rdp_auto_reconnect AS "rdpAutoReconnect",
                n.rdp_server_authentication AS "rdpServerAuthentication",
                n.rdp_gateway_usage_method AS "rdpGatewayUsageMethod",
                n.rdp_gateway_hostname AS "rdpGatewayHostname",
                n.rdp_gateway_credential_id AS "rdpGatewayCredentialId",
                n.rdp_gateway_bypass_local AS "rdpGatewayBypassLocal",
                n.rdp_gateway_use_same_creds AS "rdpGatewayUseSameCreds",
                n.rdp_use_external_client AS "rdpUseExternalClient"
            FROM wormhole_data.nodes n WHERE n.id=ids[i]
        ) metadata;
        permissions:=masks[i]; boundary_id:=item.boundary_id; row_version:=item.row_version;
        seal_suite:=item.seal_suite; seal_signer_key_id:=item.seal_signer_key_id;
        seal_signer_key_version:=item.seal_signer_key_version; seal_capability_id:=item.seal_capability_id; seal:=item.seal;
        RETURN NEXT;
    END LOOP;
END
$tree$;
REVOKE ALL ON FUNCTION wormhole_api_v1.get_tree(bytea,uuid,bigint,bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.get_tree(bytea,uuid,bigint,bigint,integer) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=17 WHERE singleton;
COMMIT;
