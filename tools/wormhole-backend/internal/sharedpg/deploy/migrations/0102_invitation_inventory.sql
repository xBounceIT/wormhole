-- Version 102: enrollment invitation status for workspace administrators.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>101 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.admin_invitations(p_capability bytea,p_after uuid)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' SET timezone='UTC' AS $invitations$
DECLARE actor record; result jsonb;
BEGIN
    IF p_after='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid invitation cursor' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin AND NOT u.disabled)
        OR NOT EXISTS(SELECT FROM wormhole_data.current_connection_tls() tls WHERE tls.ssl) THEN
        RETURN QUERY SELECT '{{WORKSPACE_ID}}'::uuid,actor.user_id,actor.device_id,NULL::jsonb;
        RETURN;
    END IF;
    SELECT jsonb_agg(jsonb_build_array(x.id,x.login_name,x.name,x.status,
        to_char(x.expires_at,'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) ORDER BY x.id)
    INTO result FROM (
        SELECT i.id,u.login_name,coalesce(u.name,'') AS name,i.expires_at,
            CASE WHEN u.disabled THEN 'suspended'
                 WHEN i.used_at IS NOT NULL THEN
                    CASE WHEN EXISTS(SELECT FROM wormhole_data.devices d
                        JOIN wormhole_data.device_confirmations c ON c.device_id=d.id
                        WHERE d.user_id=u.id AND d.status='active') THEN 'active' ELSE 'redeemed' END
                 WHEN i.expires_at<=statement_timestamp() THEN 'expired'
                 WHEN i.attempts>=5 THEN 'locked'
                 WHEN EXISTS(SELECT FROM wormhole_data.user_enrollments e WHERE e.user_id=u.id) THEN 'superseded'
                 ELSE 'pending' END AS status
        FROM wormhole_data.invites i JOIN wormhole_data.users u ON u.id=i.user_id
        WHERE i.kind='invite' AND (p_after IS NULL OR i.id>p_after)
        ORDER BY i.id LIMIT 26
    ) x;
    RETURN QUERY SELECT '{{WORKSPACE_ID}}'::uuid,actor.user_id,actor.device_id,coalesce(result,'[]'::jsonb);
END
$invitations$;
REVOKE ALL ON FUNCTION wormhole_api_v1.admin_invitations(bytea,uuid)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.admin_invitations(bytea,uuid) TO wh_{{TAG}}_user;

{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=102 WHERE singleton;
COMMIT;
