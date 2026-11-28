-- Version 60: administration of groups and unkeyed membership.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>59 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE INDEX grants_group ON wormhole_data.grants(group_id) WHERE group_id IS NOT NULL;
ALTER TABLE wormhole_data.audit_log ADD COLUMN admin_group_id uuid, ADD COLUMN admin_subject_id uuid,
    ADD CHECK(admin_subject_id IS NULL OR admin_group_id IS NOT NULL);

CREATE FUNCTION wormhole_api_v1.admin_groups(p_capability bytea,p_action text,p_group uuid,p_revision bigint,
    p_name text,p_login text,p_member uuid,p_after uuid,p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $groups$
DECLARE actor record; meta wormhole_data.workspace_meta; selected wormhole_data.groups;
    session_row record; subject uuid; result jsonb; op text; changed_rows integer;
    writing boolean := p_action NOT IN ('list','members');
BEGIN
    IF p_action IS NULL OR p_action NOT IN ('list','members','create','rename','add-member','remove-member','delete')
        OR ((p_action='list')<>(p_group IS NULL))
        OR p_group='00000000-0000-0000-0000-000000000000'::uuid
        OR ((p_action IN ('list','create'))<>(p_revision IS NULL))
        OR p_revision<1
        OR (p_after IS NOT NULL AND (writing OR p_after='00000000-0000-0000-0000-000000000000'::uuid))
        OR ((p_action IN ('create','rename'))<>(p_name IS NOT NULL))
        OR (p_name IS NOT NULL AND (octet_length(p_name) NOT BETWEEN 1 AND 256 OR p_name<>btrim(p_name)
            OR p_name !~ '[^[:space:]]' OR p_name ~ '[[:cntrl:]]'))
        OR ((p_action='add-member')<>(p_login IS NOT NULL))
        OR (p_login IS NOT NULL AND (octet_length(p_login) NOT BETWEEN 1 AND 256 OR p_login ~ '[[:cntrl:]]'))
        OR ((p_action='remove-member')<>(p_member IS NOT NULL)) OR p_member='00000000-0000-0000-0000-000000000000'::uuid
        OR octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_account_state) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid group administration request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin AND NOT u.disabled)
        OR NOT EXISTS(SELECT FROM wormhole_data.current_connection_tls() tls WHERE tls.ssl) THEN
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
    IF p_action='list' THEN
        SELECT jsonb_agg(jsonb_build_array(g.id,g.name,g.row_version::text) ORDER BY g.id) INTO result FROM (
            SELECT id,name,row_version FROM wormhole_data.groups WHERE p_after IS NULL OR id>p_after
            ORDER BY id LIMIT 26
        ) g;
        RETURN QUERY SELECT 'ready'::text,coalesce(result,'[]'::jsonb);
        RETURN;
    END IF;
    SELECT * INTO selected FROM wormhole_data.groups g WHERE g.id=p_group;
    IF p_action='create' THEN
        IF FOUND THEN
            RETURN QUERY SELECT CASE WHEN selected.name COLLATE "C"=p_name THEN 'unchanged' ELSE 'stale' END,NULL::jsonb;
            RETURN;
        END IF;
        INSERT INTO wormhole_data.groups(id,name) VALUES(p_group,p_name);
    ELSE
        IF NOT FOUND OR selected.row_version<>p_revision THEN
            RETURN QUERY SELECT 'stale'::text,NULL::jsonb;
            RETURN;
        END IF;
        IF p_action='members' THEN
            SELECT jsonb_agg(jsonb_build_array(m.user_id,m.login_name,m.disabled::text) ORDER BY m.user_id) INTO result FROM (
                SELECT gm.user_id,u.login_name,u.disabled FROM wormhole_data.group_members gm
                JOIN wormhole_data.users u ON u.id=gm.user_id WHERE gm.group_id=p_group
                    AND (p_after IS NULL OR gm.user_id>p_after) ORDER BY gm.user_id LIMIT 26
            ) m;
            RETURN QUERY SELECT 'ready'::text,coalesce(result,'[]'::jsonb);
            RETURN;
        END IF;
        IF p_action='rename' AND selected.name COLLATE "C"=p_name THEN
            RETURN QUERY SELECT 'unchanged'::text,NULL::jsonb;
            RETURN;
        END IF;
        IF p_action IN ('add-member','remove-member','delete') AND (
            EXISTS(SELECT FROM wormhole_data.boundary_grants WHERE group_id=p_group)
            OR EXISTS(SELECT FROM wormhole_data.keys WHERE kind='group' AND owner_id=p_group)
            OR EXISTS(SELECT FROM wormhole_data.group_members WHERE group_id=p_group AND signature IS NOT NULL)
        ) THEN
            -- A managed key graph must change with membership and cannot be
            -- bypassed through the unkeyed administration path.
            RETURN QUERY SELECT 'key-change-required'::text,NULL::jsonb;
            RETURN;
        END IF;
        CASE p_action
        WHEN 'delete' THEN
            IF EXISTS(SELECT FROM wormhole_data.grants WHERE group_id=p_group)
                OR EXISTS(SELECT FROM wormhole_data.group_members WHERE group_id=p_group) THEN
                RETURN QUERY SELECT 'group-in-use'::text,NULL::jsonb;
                RETURN;
            END IF;
            DELETE FROM wormhole_data.groups WHERE id=p_group;
        WHEN 'add-member' THEN
            SELECT u.id INTO subject FROM wormhole_data.users u
            WHERE u.login_name=p_login AND u.login_name COLLATE "C"=p_login AND NOT u.disabled FOR SHARE NOWAIT;
            IF NOT FOUND THEN
                RETURN QUERY SELECT 'account-unavailable'::text,NULL::jsonb;
                RETURN;
            END IF;
            IF EXISTS(SELECT FROM wormhole_data.group_members WHERE group_id=p_group AND user_id=subject) THEN
                RETURN QUERY SELECT 'unchanged'::text,NULL::jsonb;
                RETURN;
            END IF;
            INSERT INTO wormhole_data.group_members(group_id,user_id) VALUES(p_group,subject);
        WHEN 'remove-member' THEN
            subject:=p_member;
            IF NOT EXISTS(SELECT FROM wormhole_data.group_members WHERE group_id=p_group AND user_id=subject) THEN
                RETURN QUERY SELECT 'unchanged'::text,NULL::jsonb;
                RETURN;
            END IF;
            DELETE FROM wormhole_data.group_members WHERE group_id=p_group AND user_id=subject;
        ELSE NULL;
        END CASE;
        IF p_action<>'delete' THEN
            UPDATE wormhole_data.groups SET name=coalesce(p_name,name),row_version=row_version+1
                WHERE id=p_group AND row_version<9223372036854775807;
            GET DIAGNOSTICS changed_rows=ROW_COUNT;
            IF changed_rows<>1 THEN RAISE EXCEPTION 'Group revision exhausted' USING ERRCODE='22003'; END IF;
        END IF;
    END IF;
    SELECT s.id,s.app_version INTO STRICT session_row FROM wormhole_data.device_admissions a
        JOIN wormhole_data.sessions s ON s.id=a.session_id WHERE a.device_id=actor.device_id AND s.user_id=actor.user_id;
    op:='group_'||replace(p_action,'-','_');
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,
        admin_group_id,admin_subject_id)
    VALUES(actor.user_id,session_row.id,session_user,'ui',op,'success',pg_catalog.inet_client_addr(),session_row.app_version,p_group,subject);
    RETURN QUERY SELECT 'changed'::text,NULL::jsonb;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::jsonb;
END
$groups$;

{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_api_v1.admin_groups(bytea,text,uuid,bigint,text,text,uuid,uuid,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.admin_groups(bytea,text,uuid,bigint,text,text,uuid,uuid,bytea,bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=60 WHERE singleton;
COMMIT;
