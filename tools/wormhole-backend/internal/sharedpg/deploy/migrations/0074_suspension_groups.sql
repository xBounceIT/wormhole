-- Version 74: review and resume the groups captured at account suspension.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>73 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_data.suspension_group_page(p_actor uuid,p_account uuid,p_after bigint) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $groups$
    WITH captured AS MATERIALIZED (
        SELECT captured.group_id,r.boundary_id
        FROM wormhole_data.account_suspension_roots r CROSS JOIN LATERAL unnest(r.groups) AS captured(group_id)
        WHERE r.account_id=p_account
    ), ranked AS (
        SELECT group_id,row_number() OVER (ORDER BY group_id) AS position FROM (SELECT DISTINCT group_id FROM captured) q
    ), page AS (
        SELECT * FROM ranked WHERE position>coalesce(p_after,0) ORDER BY position LIMIT 26
    )
    SELECT jsonb_agg(CASE WHEN g.id IS NOT NULL AND EXISTS (
        SELECT FROM captured c JOIN wormhole_data.boundaries b ON b.id=c.boundary_id
        WHERE c.group_id=page.group_id AND b.owner_user_id IS NULL AND NOT b.deleted
            AND (wormhole_data.effective_boundary_permissions(p_actor,b.id)&17)=17
    ) THEN jsonb_build_array(page.position::text,g.id,g.name,g.row_version::text,
        CASE WHEN job.removed_user_id=p_account THEN 'queued'
             WHEN job.id IS NOT NULL THEN 'waiting'
             WHEN member.user_id IS NOT NULL THEN 'needs-removal'
             ELSE 'resolved' END,
        CASE WHEN job.removed_user_id=p_account THEN job.id END)
    ELSE jsonb_build_array(page.position::text,NULL,NULL,NULL,NULL,NULL) END ORDER BY page.position)
    FROM page
    LEFT JOIN wormhole_data.groups g ON g.id=page.group_id
    LEFT JOIN wormhole_data.group_members member ON member.group_id=g.id AND member.user_id=p_account
    LEFT JOIN wormhole_data.group_member_rotation_jobs job ON job.group_id=g.id AND NOT job.complete
$groups$;

{{ACCOUNT_GROUP_INVENTORY_DEFINITION}}
CREATE FUNCTION wormhole_api_v1.account_suspension_groups(p_capability bytea,p_account uuid,
    p_revision bigint,p_after bigint,p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,payload jsonb)
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $review_groups$
    SELECT * FROM wormhole_api_v1.account_suspension_inventory(
        p_capability,p_account,'groups',p_revision,p_after,p_policy,p_account_state)
$review_groups$;

REVOKE ALL ON FUNCTION wormhole_data.suspension_group_page(uuid,uuid,bigint),
    wormhole_api_v1.account_suspension_groups(bytea,uuid,bigint,bigint,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_suspension_groups(bytea,uuid,bigint,bigint,bytea,bytea)
    TO wh_{{TAG}}_user;
{{SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=74 WHERE singleton;
COMMIT;
