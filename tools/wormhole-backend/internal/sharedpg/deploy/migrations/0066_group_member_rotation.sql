-- Version 66: replace a group's key and remember which boundary roots it held.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>65 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.group_member_rotation_jobs (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
    group_id uuid NOT NULL REFERENCES wormhole_data.groups(id),
    removed_user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    group_revision bigint NOT NULL CHECK(group_revision>0),
    review_digest bytea NOT NULL CHECK(octet_length(review_digest)=32),
    key_id uuid NOT NULL,
    retired_version integer NOT NULL CHECK(retired_version BETWEEN 1 AND 2147483646),
    complete boolean NOT NULL DEFAULT false,
    FOREIGN KEY (key_id,retired_version) REFERENCES wormhole_data.keys(key_id,key_version)
);
CREATE UNIQUE INDEX one_pending_member_rotation ON wormhole_data.group_member_rotation_jobs(group_id) WHERE NOT complete;

CREATE TABLE wormhole_data.group_boundary_rotation_queue (
    job_id uuid NOT NULL REFERENCES wormhole_data.group_member_rotation_jobs(id),
    boundary_id uuid NOT NULL REFERENCES wormhole_data.boundaries(id),
    purpose integer NOT NULL CHECK(purpose IN (1,2)),
    root_id uuid NOT NULL,
    root_version integer NOT NULL CHECK(root_version BETWEEN 1 AND 2147483646),
    PRIMARY KEY(job_id,boundary_id,purpose),
    UNIQUE(root_id,root_version),
    FOREIGN KEY (root_id,root_version) REFERENCES wormhole_data.keys(key_id,key_version)
);
CREATE INDEX group_boundary_rotation_by_boundary ON wormhole_data.group_boundary_rotation_queue(boundary_id);

-- Newly written data must not use a root the removed member could still hold.
-- The rotation publisher writes copies under the next version and then retires
-- the old copies. A grant or value writer uses the existing root and is refused.
CREATE FUNCTION wormhole_data.guard_pending_rotation_copy() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
    IF EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q
        WHERE (q.root_id,q.root_version) IN ((NEW.key_id,NEW.key_version),(NEW.holder_key_id,NEW.holder_key_version))) THEN
        RAISE EXCEPTION 'Boundary root is awaiting member rotation' USING ERRCODE='WH020';
    END IF;
    RETURN NEW;
END
$guard$;
CREATE TRIGGER guard_pending_rotation_copy BEFORE INSERT OR UPDATE ON wormhole_data.key_copies
    FOR EACH ROW EXECUTE FUNCTION wormhole_data.guard_pending_rotation_copy();

CREATE FUNCTION wormhole_data.guard_pending_rotation_value() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
    IF EXISTS(SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.group_boundary_rotation_queue q
        ON (c.holder_key_id,c.holder_key_version)=(q.root_id,q.root_version)
        WHERE (c.key_id,c.key_version)=(NEW.dek_id,NEW.dek_version)) THEN
        RAISE EXCEPTION 'Boundary value is awaiting member rotation' USING ERRCODE='WH020';
    END IF;
    RETURN NEW;
END
$guard$;
CREATE TRIGGER guard_pending_rotation_value BEFORE INSERT OR UPDATE OF dek_id,dek_version,envelope ON wormhole_data.secret_values
    FOR EACH ROW EXECUTE FUNCTION wormhole_data.guard_pending_rotation_value();

-- Allow archive restoration only when the persisted queue exactly accounts for
-- every boundary copy held by an old group key for an unfinished job.
CREATE FUNCTION wormhole_data.group_rotation_queue_recoverable() RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $valid$
    SELECT NOT EXISTS(
        SELECT FROM wormhole_data.group_member_rotation_jobs j
        JOIN wormhole_data.groups g ON g.id=j.group_id
        JOIN wormhole_data.keys old ON (old.key_id,old.key_version)=(j.key_id,j.retired_version)
        WHERE old.owner_id IS DISTINCT FROM j.group_id OR old.kind<>'group' OR old.status<>'retired'
          OR EXISTS(SELECT FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version)=(j.key_id,j.retired_version))
          OR j.complete IS DISTINCT FROM (NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=j.id))
          OR EXISTS(SELECT FROM wormhole_data.key_copies c WHERE (c.holder_key_id,c.holder_key_version)=(j.key_id,j.retired_version)
              AND NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q WHERE q.job_id=j.id AND (q.root_id,q.root_version)=(c.key_id,c.key_version)))
          OR (NOT j.complete AND (
              (convert_from(g.key_manifest,'UTF8')::jsonb#>'{key,key}') IS DISTINCT FROM
                  jsonb_build_object('id',j.key_id,'version',j.retired_version+1)
              OR EXISTS(SELECT FROM wormhole_data.group_members m WHERE m.group_id=j.group_id AND m.user_id=j.removed_user_id)
          ))
    ) AND NOT EXISTS(
        SELECT FROM wormhole_data.group_boundary_rotation_queue q JOIN wormhole_data.group_member_rotation_jobs j ON j.id=q.job_id
        JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(q.root_id,q.root_version)
        WHERE k.owner_id IS DISTINCT FROM q.boundary_id OR k.status<>'active'
          OR k.kind<>CASE WHEN q.purpose=1 THEN 'boundary-view' ELSE 'boundary-secret' END
          OR NOT EXISTS(SELECT FROM wormhole_data.key_copies c WHERE (c.key_id,c.key_version,c.holder_key_id,c.holder_key_version)
              =(q.root_id,q.root_version,j.key_id,j.retired_version))
    ) AND NOT EXISTS(
        SELECT FROM wormhole_data.key_copies c JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(c.holder_key_id,c.holder_key_version)
        WHERE k.kind='group' AND k.status='retired'
          AND NOT EXISTS(SELECT FROM wormhole_data.group_boundary_rotation_queue q JOIN wormhole_data.group_member_rotation_jobs j ON j.id=q.job_id
              WHERE (q.root_id,q.root_version,j.key_id,j.retired_version)=(c.key_id,c.key_version,c.holder_key_id,c.holder_key_version))
    )
$valid$;

{{POST_REMOVAL_ROSTER_DEFINITION}}
{{GROUP_MEMBER_ROTATION_API}}
{{MEMBER_BOUNDARY_WORKER}}
{{ROTATION_EXPORT_DEFINITION}}
{{RESTORE_WORKSPACE_DEFINITION}}
{{PENDING_ROTATION_GUARDS}}

REVOKE ALL ON TABLE wormhole_data.group_member_rotation_jobs,wormhole_data.group_boundary_rotation_queue
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_data.guard_pending_rotation_copy(),wormhole_data.guard_pending_rotation_value(),
    wormhole_data.group_rotation_queue_recoverable(),wormhole_data.group_key_roster_after_removal(uuid,uuid)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
UPDATE wormhole_data.workspace_meta SET schema_version=66 WHERE singleton;
COMMIT;
