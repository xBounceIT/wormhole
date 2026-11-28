-- Version 61: direct grants on shared nodes, gated by current Manage.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>60 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.audit_log ADD COLUMN admin_grant_subject_id uuid,
    ADD COLUMN admin_grant_subject_kind text CHECK(admin_grant_subject_kind IN ('account','group')),
    ADD COLUMN admin_grant_before integer CHECK(admin_grant_before BETWEEN 0 AND 31),
    ADD COLUMN admin_grant_after integer CHECK(admin_grant_after BETWEEN 0 AND 31),
    ADD CHECK(pg_catalog.num_nonnulls(admin_grant_subject_id,admin_grant_subject_kind,admin_grant_before,admin_grant_after) IN (0,4));

CREATE FUNCTION wormhole_api_v1.manage_node_grants(p_capability bytea,p_node uuid,p_node_revision bigint,p_kind text,
    p_after uuid,p_epoch bigint,p_sequence bigint,p_subject uuid,p_login text,p_grant_revision bigint,p_mask integer,
    p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,epoch bigint,change_seq bigint,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $manage$
DECLARE actor record; meta wormhole_data.workspace_meta; target wormhole_data.nodes; selected wormhole_data.grants;
    actor_mask integer; previous_mask integer; subject_id uuid; session_row record; result jsonb;
    writing boolean := p_mask IS NOT NULL;
    missing uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF p_node IS NULL OR p_node=missing OR p_node_revision IS NULL OR p_node_revision<1
        OR p_kind IS NULL OR p_kind NOT IN ('account','group') OR p_after=missing OR p_subject=missing
        OR (p_epoch IS NULL)<>(p_sequence IS NULL) OR p_epoch<1 OR p_sequence<0
        OR octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_account_state) IS DISTINCT FROM 32
        OR (writing AND (p_epoch IS NULL OR p_after IS NOT NULL OR p_mask NOT BETWEEN 0 AND 31
            OR p_grant_revision IS NULL OR p_grant_revision<0 OR num_nonnulls(p_subject,p_login)<>1
            OR (p_login IS NOT NULL AND (p_kind<>'account' OR p_grant_revision<>0
                OR octet_length(p_login) NOT BETWEEN 1 AND 256 OR p_login ~ '[[:cntrl:]]'))
            OR (p_grant_revision=0 AND p_mask=0)))
        OR (NOT writing AND (num_nonnulls(p_subject,p_login,p_grant_revision)<>0 OR (p_after IS NULL)<>(p_epoch IS NULL)))
    THEN RAISE EXCEPTION 'Invalid grant administration request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin AND NOT u.disabled)
        OR NOT EXISTS(SELECT FROM wormhole_data.current_connection_tls() tls WHERE tls.ssl) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
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
        RETURN QUERY SELECT 'stale'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    SELECT * INTO target FROM wormhole_data.nodes n WHERE n.id=p_node FOR SHARE NOWAIT;
    IF NOT FOUND OR NOT EXISTS(SELECT FROM wormhole_data.boundaries b WHERE b.id=target.boundary_id AND
        b.owner_user_id IS NULL AND NOT b.deleted) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    actor_mask:=wormhole_data.effective_permissions(actor.user_id,p_node);
    IF (actor_mask&16)<>16 OR EXISTS(
        WITH RECURSIVE ancestry(id,parent_id,owner_user_id) AS (
            SELECT n.id,n.parent_id,n.owner_user_id FROM wormhole_data.nodes n WHERE n.id=p_node
            UNION ALL
            SELECT n.id,n.parent_id,n.owner_user_id FROM ancestry a JOIN wormhole_data.nodes n ON n.id=a.parent_id
        ) SELECT FROM ancestry WHERE owner_user_id IS NOT NULL) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    IF target.row_version<>p_node_revision OR (p_epoch IS NOT NULL AND (meta.epoch,meta.change_seq)<>(p_epoch,p_sequence)) THEN
        RETURN QUERY SELECT 'stale'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    IF NOT writing THEN
        IF p_kind='account' THEN
            SELECT jsonb_agg(jsonb_build_array(x.id,x.label,x.permissions::text,x.row_version::text) ORDER BY x.id)
            INTO result FROM (
                SELECT r.user_id AS id,u.login_name AS label,r.permissions,r.row_version
                FROM wormhole_data.grants r JOIN wormhole_data.users u ON u.id=r.user_id
                WHERE r.node_id=p_node AND (p_after IS NULL OR r.user_id>p_after) ORDER BY r.user_id LIMIT 26
            ) x;
        ELSE
            SELECT jsonb_agg(jsonb_build_array(x.id,x.label,x.permissions::text,x.row_version::text) ORDER BY x.id)
            INTO result FROM (
                SELECT r.group_id AS id,g.name AS label,r.permissions,r.row_version
                FROM wormhole_data.grants r JOIN wormhole_data.groups g ON g.id=r.group_id
                WHERE r.node_id=p_node AND (p_after IS NULL OR r.group_id>p_after) ORDER BY r.group_id LIMIT 26
            ) x;
        END IF;
        RETURN QUERY SELECT 'ready'::text,meta.epoch,meta.change_seq,coalesce(result,'[]'::jsonb);
        RETURN;
    END IF;
    IF p_kind='account' THEN
        SELECT u.id INTO subject_id FROM wormhole_data.users u WHERE
            (u.id=p_subject OR (u.login_name=p_login AND u.login_name COLLATE "C"=p_login))
            AND (p_grant_revision>0 OR NOT u.disabled) FOR SHARE NOWAIT;
    ELSE
        SELECT g.id INTO subject_id FROM wormhole_data.groups g WHERE g.id=p_subject FOR SHARE NOWAIT;
    END IF;
    IF subject_id IS NULL THEN
        RETURN QUERY SELECT 'subject-unavailable'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    SELECT * INTO selected FROM wormhole_data.grants r WHERE r.node_id=p_node AND
        (CASE WHEN p_kind='account' THEN r.user_id=subject_id ELSE r.group_id=subject_id END);
    IF coalesce(selected.row_version,0)<>p_grant_revision THEN
        RETURN QUERY SELECT 'stale'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    previous_mask:=coalesce(selected.permissions,0);
    IF p_mask=previous_mask THEN
        RETURN QUERY SELECT 'unchanged'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    IF selected.signature IS NOT NULL THEN
        RETURN QUERY SELECT 'signed-grant'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    IF (p_mask & ~previous_mask & ~actor_mask)<>0 THEN
        RETURN QUERY SELECT 'cannot-delegate'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
        RETURN;
    END IF;
    IF p_grant_revision=0 THEN
        INSERT INTO wormhole_data.grants(node_id,user_id,group_id,permissions)
        VALUES(p_node,CASE WHEN p_kind='account' THEN subject_id END,CASE WHEN p_kind='group' THEN subject_id END,p_mask);
    ELSIF p_mask=0 THEN
        DELETE FROM wormhole_data.grants r WHERE r.node_id=p_node
            AND (r.user_id,r.group_id) IS NOT DISTINCT FROM (selected.user_id,selected.group_id);
    ELSE
        UPDATE wormhole_data.grants r SET permissions=p_mask,row_version=r.row_version+1 WHERE r.node_id=p_node
            AND (r.user_id,r.group_id) IS NOT DISTINCT FROM (selected.user_id,selected.group_id);
    END IF;
    SELECT s.id,s.app_version INTO STRICT session_row FROM wormhole_data.device_admissions a
        JOIN wormhole_data.sessions s ON s.id=a.session_id WHERE a.device_id=actor.device_id AND s.user_id=actor.user_id;
    INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version,
        node_id,admin_grant_subject_id,admin_grant_subject_kind,admin_grant_before,admin_grant_after)
    VALUES(actor.user_id,session_row.id,session_user,'ui','node_grant_change','success',pg_catalog.inet_client_addr(),
        session_row.app_version,p_node,subject_id,p_kind,previous_mask,p_mask);
    RETURN QUERY SELECT 'changed'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::bigint,NULL::bigint,NULL::jsonb;
END
$manage$;

{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_api_v1.manage_node_grants(bytea,uuid,bigint,text,uuid,bigint,bigint,uuid,text,bigint,integer,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.manage_node_grants(bytea,uuid,bigint,text,uuid,bigint,bigint,uuid,text,bigint,integer,bytea,bytea)
    TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=61 WHERE singleton;
COMMIT;
