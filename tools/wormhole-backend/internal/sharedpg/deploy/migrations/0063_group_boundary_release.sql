-- Version 63: resolve group-wrapped View and Secret roots inside audited release.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>62 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Private helper. Every caller has already checked its committed ticket,
-- the node and relevant boundary permissions within the locked snapshot.
CREATE FUNCTION wormhole_data.boundary_release_root(p_boundary uuid,p_user uuid,p_key uuid,p_version integer,
    p_holder uuid,p_holder_version integer,p_epoch bigint,p_sequence bigint,p_permission integer)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $root$
DECLARE item record; selected record; root jsonb;
BEGIN
    IF EXISTS(SELECT FROM wormhole_data.key_copies c
        WHERE (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version)=(p_key,p_version,p_holder,p_holder_version)) THEN
        SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(p_key,p_version,p_holder,p_holder_version,p_epoch,p_sequence);
        RETURN wormhole_data.key_copy_wire(to_jsonb(item));
    END IF;
    IF p_permission IS NULL OR p_permission NOT IN (1,2) OR NOT EXISTS(
        SELECT FROM wormhole_data.keys k JOIN wormhole_data.boundaries b ON k.owner_id=b.id
        WHERE (k.key_id,k.key_version)=(p_key,p_version) AND b.id=p_boundary AND b.owner_user_id IS NULL AND NOT b.deleted
            AND k.kind=CASE WHEN p_permission=1 THEN 'boundary-view' ELSE 'boundary-secret' END
    ) THEN
        RAISE EXCEPTION 'Boundary key copy unavailable' USING ERRCODE='WH010';
    END IF;
    SELECT g.id,g.key_manifest,k.key_id,k.key_version INTO selected
    FROM wormhole_data.boundary_grants r
    JOIN wormhole_data.groups g ON g.id=r.group_id
    JOIN wormhole_data.group_members m ON m.group_id=g.id AND m.user_id=p_user
    JOIN wormhole_data.keys k ON k.owner_id=g.id AND k.kind='group' AND k.status='active' AND k.suite=2
    JOIN wormhole_data.key_copies c
        ON (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version)=(p_key,p_version,k.key_id,k.key_version)
    JOIN wormhole_data.key_copies e
        ON (e.key_id,e.key_version,e.holder_key_id,e.holder_key_version)=(k.key_id,k.key_version,p_holder,p_holder_version)
    WHERE r.boundary_id=p_boundary AND (r.permissions & p_permission)=p_permission AND g.key_manifest IS NOT NULL
    ORDER BY g.id LIMIT 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'Boundary key copy unavailable' USING ERRCODE='WH010'; END IF;
    SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(p_key,p_version,selected.key_id,selected.key_version,p_epoch,p_sequence);
    root:=wormhole_data.key_copy_wire(to_jsonb(item));
    SELECT * INTO STRICT item FROM wormhole_data.key_copy_record(selected.key_id,selected.key_version,p_holder,p_holder_version,p_epoch,p_sequence);
    RETURN jsonb_build_object('groupId',selected.id,'manifest',encode(selected.key_manifest,'hex'),
        'groupCopy',wormhole_data.key_copy_wire(to_jsonb(item)),'rootCopy',root);
END
$root$;

{{GROUP_BOUNDARY_RELEASE_DEFINITIONS}}
{{RESTORE_WORKSPACE_DEFINITION}}
REVOKE ALL ON FUNCTION wormhole_data.boundary_release_root(uuid,uuid,uuid,integer,uuid,integer,bigint,bigint,integer)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
UPDATE wormhole_data.workspace_meta SET schema_version=63 WHERE singleton;
COMMIT;
