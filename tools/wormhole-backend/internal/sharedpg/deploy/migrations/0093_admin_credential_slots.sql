-- Version 93: paged, signed credential slot metadata for workspace administrators.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>92 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.admin_credential_slots(p_capability bytea,p_after uuid,p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET bytea_output='hex' AS $slots$
DECLARE actor record; meta record; candidate uuid; wire jsonb; items jsonb:='[]'; count_rows integer:=0;
    page_bytes integer:=2; wire_bytes integer; outcome text:='ready';
BEGIN
    IF p_after='00000000-0000-0000-0000-000000000000'::uuid
        OR octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_account_state) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid credential slot page' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin AND NOT u.disabled)
        OR NOT EXISTS(SELECT FROM wormhole_data.current_connection_tls() t WHERE t.ssl) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' OR sha256(meta.signed_profile) IS DISTINCT FROM p_policy OR NOT EXISTS(
        SELECT FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id
            AND sha256(s.signed_state)=p_account_state
            AND convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true' FOR SHARE NOWAIT) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
{{VISIBLE_SLOT_PAGE}}
END
$slots$;
REVOKE ALL ON FUNCTION wormhole_api_v1.admin_credential_slots(bytea,uuid,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.admin_credential_slots(bytea,uuid,bytea,bytea) TO wh_{{TAG}}_user;

{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=93 WHERE singleton;
COMMIT;
