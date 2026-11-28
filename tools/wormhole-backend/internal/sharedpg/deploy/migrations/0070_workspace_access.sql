-- Version 70: suspend accounts and revoke individual device access.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>69 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.audit_log ADD COLUMN access_account_id uuid, ADD COLUMN access_device_id uuid,
    ADD CHECK(access_device_id IS NULL OR access_account_id IS NOT NULL);

CREATE FUNCTION wormhole_api_v1.workspace_access(p_capability bytea,p_action text,p_target uuid,p_revision bigint,
    p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $access$
DECLARE actor record; meta wormhole_data.workspace_meta; target_account wormhole_data.users;
    target_device wormhole_data.devices; target_role record; target_user uuid; target_revision bigint;
    session_row record; reset_offer uuid; target_label text; writing boolean:=p_revision IS NOT NULL;
    revoke_device boolean:=p_action='revoke-device';
BEGIN
    IF p_action IS NULL OR p_action NOT IN ('disable-account','enable-account','revoke-device')
        OR p_target IS NULL OR p_target='00000000-0000-0000-0000-000000000000'::uuid
        OR p_revision<1 OR octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_account_state) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid workspace access request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    SELECT u.is_admin INTO STRICT actor.is_admin FROM wormhole_data.users u WHERE u.id=actor.user_id;
    IF NOT EXISTS(SELECT FROM wormhole_data.current_connection_tls() tls WHERE tls.ssl)
        OR (NOT revoke_device AND (NOT actor.is_admin OR p_target=actor.user_id)) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb;
        RETURN;
    END IF;
    IF writing THEN
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    ELSE
        SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    END IF;
    IF meta.state<>'ready' OR pg_catalog.sha256(meta.signed_profile) IS DISTINCT FROM p_policy OR NOT EXISTS(
        SELECT FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id
            AND pg_catalog.sha256(s.signed_state)=p_account_state
            AND pg_catalog.convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true' FOR SHARE NOWAIT) THEN
        RETURN QUERY SELECT 'stale'::text,NULL::jsonb;
        RETURN;
    END IF;
    IF revoke_device THEN
        SELECT d.user_id INTO target_user FROM wormhole_data.devices d
            WHERE d.id=p_target AND (d.user_id=actor.user_id OR actor.is_admin);
    ELSE
        target_user:=p_target;
    END IF;
    -- Keep the principal/device order used by admission and password changes.
    IF writing AND NOT revoke_device THEN
        SELECT * INTO target_account FROM wormhole_data.users u WHERE u.id=target_user FOR UPDATE NOWAIT;
    ELSE
        SELECT * INTO target_account FROM wormhole_data.users u WHERE u.id=target_user FOR SHARE NOWAIT;
    END IF;
    IF NOT FOUND THEN RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb; RETURN; END IF;
    IF revoke_device THEN
        IF writing THEN
            SELECT * INTO target_device FROM wormhole_data.devices d WHERE d.id=p_target AND d.user_id=target_user FOR UPDATE NOWAIT;
        ELSE
            SELECT * INTO target_device FROM wormhole_data.devices d WHERE d.id=p_target AND d.user_id=target_user FOR SHARE NOWAIT;
        END IF;
        IF NOT FOUND THEN RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb; RETURN; END IF;
        target_revision:=target_device.row_version;
        target_label:=target_device.name;
    ELSE
        target_revision:=target_account.row_version;
        target_label:=target_account.name;
    END IF;
    IF writing AND p_revision<>target_revision THEN RETURN QUERY SELECT 'stale'::text,NULL::jsonb; RETURN; END IF;
    IF (revoke_device AND target_device.status='revoked') OR
        (NOT revoke_device AND target_account.disabled=(p_action='disable-account')) THEN
        RETURN QUERY SELECT 'unchanged'::text,NULL::jsonb;
        RETURN;
    END IF;
    IF target_revision=9223372036854775807 THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb;
        RETURN;
    END IF;
    IF NOT writing THEN
        RETURN QUERY SELECT 'review'::text,pg_catalog.jsonb_build_array(p_action,p_target,target_revision::text,
            target_account.login_name,coalesce(target_label,''),(p_target=actor.device_id AND revoke_device)::text);
        RETURN;
    END IF;
    SELECT s.id,s.app_version INTO STRICT session_row FROM wormhole_data.device_admissions a
        JOIN wormhole_data.sessions s ON s.id=a.session_id WHERE a.device_id=actor.device_id AND s.user_id=actor.user_id;
    IF revoke_device THEN
        SELECT r.* INTO target_role FROM pg_catalog.pg_roles r WHERE r.rolname=target_device.role_name;
        IF FOUND THEN
            IF target_role.rolsuper OR target_role.rolcreatedb OR target_role.rolcreaterole OR target_role.rolreplication
                OR target_role.rolbypassrls OR NOT pg_catalog.pg_has_role(target_role.oid,'wh_{{TAG}}_user','MEMBER')
                OR EXISTS(SELECT FROM wormhole_data.device_confirmations c
                    WHERE c.device_id=p_target AND c.role_oid<>target_role.oid) THEN
                RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb;
                RETURN;
            END IF;
            EXECUTE pg_catalog.format('ALTER ROLE %I NOLOGIN PASSWORD NULL',target_device.role_name);
        END IF;
        UPDATE wormhole_data.devices SET status='revoked',row_version=target_revision+1 WHERE id=p_target;
        DELETE FROM wormhole_data.session_challenges WHERE device_id=p_target;
        DELETE FROM wormhole_data.device_admissions WHERE device_id=p_target;
        PERFORM pg_catalog.pg_notify('wormhole_changes',meta.workspace_id::text);
    ELSE
        UPDATE wormhole_data.users SET disabled=(p_action='disable-account'),row_version=target_revision+1 WHERE id=target_user;
        IF p_action='disable-account' THEN
            SELECT r.id INTO reset_offer FROM wormhole_data.account_reset_offers r
                WHERE r.user_id=target_user AND r.retired_at IS NULL;
            IF FOUND THEN PERFORM wormhole_data.retire_account_reset(reset_offer); END IF;
            DELETE FROM wormhole_data.session_challenges c USING wormhole_data.devices d WHERE c.device_id=d.id AND d.user_id=target_user;
            DELETE FROM wormhole_data.device_admissions a USING wormhole_data.devices d WHERE a.device_id=d.id AND d.user_id=target_user;
        END IF;
    END IF;
    BEGIN
        INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,
            access_account_id,access_device_id)
        VALUES(actor.user_id,session_row.id,session_user,'ui',replace(p_action,'-','_'),'success',pg_catalog.inet_client_addr(),
            session_row.app_version,target_user,CASE WHEN revoke_device THEN p_target END);
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE='WH005';
    END;
    RETURN QUERY SELECT 'changed'::text,NULL::jsonb;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::jsonb;
END
$access$;

{{CHANGE_PASSWORD_DEFINITION}}
{{ADMIN_INVENTORY_DEFINITION}}
{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_api_v1.workspace_access(bytea,text,uuid,bigint,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.workspace_access(bytea,text,uuid,bigint,bytea,bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=70 WHERE singleton;
COMMIT;
