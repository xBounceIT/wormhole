-- Version 71: capture the key and password exposure at account suspension.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>70 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.account_suspensions (
    account_id uuid PRIMARY KEY REFERENCES wormhole_data.users(id),
    revision bigint NOT NULL CHECK(revision>0)
);
CREATE TABLE wormhole_data.account_suspension_roots (
    account_id uuid NOT NULL REFERENCES wormhole_data.account_suspensions(account_id) ON DELETE CASCADE,
    position bigint NOT NULL CHECK(position>0),
    boundary_id uuid NOT NULL REFERENCES wormhole_data.boundaries(id),
    purpose smallint NOT NULL CHECK(purpose IN (1,2)),
    root_id uuid NOT NULL,
    root_version integer NOT NULL,
    held_directly boolean NOT NULL,
    groups uuid[] NOT NULL,
    PRIMARY KEY(account_id,position),
    UNIQUE(account_id,boundary_id,purpose),
    FOREIGN KEY(root_id,root_version) REFERENCES wormhole_data.keys(key_id,key_version),
    CHECK(held_directly OR cardinality(groups)>0),
    CHECK(coalesce(array_ndims(groups),1)=1 AND array_position(groups,NULL::uuid) IS NULL)
);
CREATE TABLE wormhole_data.account_suspension_passwords (
    account_id uuid NOT NULL REFERENCES wormhole_data.account_suspensions(account_id) ON DELETE CASCADE,
    position bigint NOT NULL CHECK(position>0),
    boundary_id uuid NOT NULL REFERENCES wormhole_data.boundaries(id),
    owner_kind text NOT NULL CHECK(owner_kind IN ('credential','node','tunnel','slot-value')),
    owner_id uuid NOT NULL CHECK(owner_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    PRIMARY KEY(account_id,position),
    UNIQUE(account_id,boundary_id,owner_kind,owner_id)
);

CREATE INDEX secret_values_by_dek ON wormhole_data.secret_values(dek_id,dek_version);
CREATE INDEX user_encryption_keys_by_owner ON wormhole_data.keys(owner_id) WHERE kind='user-enc';
CREATE INDEX pending_group_rotations_by_subject ON wormhole_data.group_member_rotation_jobs(removed_user_id) WHERE NOT complete;

CREATE FUNCTION wormhole_data.account_suspensions_recoverable() RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $archive$
    SELECT NOT EXISTS(
        SELECT FROM wormhole_data.account_suspensions s JOIN wormhole_data.users u ON u.id=s.account_id
        WHERE s.revision>u.row_version
    ) AND NOT EXISTS(
        SELECT FROM wormhole_data.account_suspension_roots r
        JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(r.root_id,r.root_version)
        WHERE k.owner_id IS DISTINCT FROM r.boundary_id
            OR k.kind<>CASE r.purpose WHEN 1 THEN 'boundary-view' ELSE 'boundary-secret' END
    ) AND NOT EXISTS(
        SELECT FROM wormhole_data.account_suspension_roots r GROUP BY r.account_id
        HAVING min(r.position)<>1 OR max(r.position)<>count(*)
    ) AND NOT EXISTS(
        SELECT FROM wormhole_data.account_suspension_passwords p GROUP BY p.account_id
        HAVING min(p.position)<>1 OR max(p.position)<>count(*)
    )
$archive$;

-- This runs with the scope and disabled state in the same transaction. Track
-- actual key copies, even when a grant has already been removed. A pending
-- group rotation may already have removed the account's group copy.
CREATE FUNCTION wormhole_data.capture_account_suspension() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $capture$
BEGIN
    DELETE FROM wormhole_data.account_suspensions s WHERE s.account_id=NEW.id;
    INSERT INTO wormhole_data.account_suspensions(account_id,revision) VALUES(NEW.id,NEW.row_version);
    WITH copies AS MATERIALIZED (
        SELECT c.key_id,c.key_version FROM wormhole_data.keys k
        JOIN wormhole_data.key_copies c ON (c.holder_key_id,c.holder_key_version)=(k.key_id,k.key_version)
        WHERE k.owner_id=NEW.id AND k.kind='user-enc'
    ), paths AS (
        SELECT c.key_id,c.key_version,NULL::uuid AS group_id FROM copies c
        UNION ALL
        SELECT c.key_id,c.key_version,k.owner_id FROM copies member
        JOIN wormhole_data.keys k USING(key_id,key_version)
        JOIN wormhole_data.key_copies c ON (c.holder_key_id,c.holder_key_version)=(k.key_id,k.key_version)
        WHERE k.kind='group' AND k.owner_id IS NOT NULL
        UNION ALL
        SELECT q.root_id,q.root_version,j.group_id FROM wormhole_data.group_member_rotation_jobs j
        JOIN wormhole_data.group_boundary_rotation_queue q ON q.job_id=j.id
        WHERE j.removed_user_id=NEW.id AND NOT j.complete
    ), roots AS (
        SELECT b.id AS boundary,k.key_id,k.key_version,
            CASE k.kind WHEN 'boundary-view' THEN 1 ELSE 2 END AS purpose,
            bool_or(p.group_id IS NULL) AS direct,
            coalesce(array_agg(DISTINCT p.group_id ORDER BY p.group_id) FILTER(WHERE p.group_id IS NOT NULL),'{}') AS groups
        FROM paths p JOIN wormhole_data.keys k USING(key_id,key_version)
        JOIN wormhole_data.boundaries b ON b.id=k.owner_id
        WHERE k.kind IN ('boundary-view','boundary-secret') AND k.status='active'
        GROUP BY b.id,k.key_id,k.key_version,k.kind
    )
    INSERT INTO wormhole_data.account_suspension_roots(account_id,position,boundary_id,purpose,root_id,root_version,held_directly,groups)
        SELECT NEW.id,row_number() OVER (ORDER BY boundary,purpose),boundary,purpose,key_id,key_version,direct,groups FROM roots;

    WITH passwords AS (
        SELECT DISTINCT q.boundary_id,s.owner_kind,s.owner_id
        FROM wormhole_data.account_suspension_roots q
        JOIN wormhole_data.key_copies c ON (c.holder_key_id,c.holder_key_version)=(q.root_id,q.root_version)
        JOIN wormhole_data.secret_values s ON (s.dek_id,s.dek_version)=(c.key_id,c.key_version)
        WHERE q.account_id=NEW.id AND q.purpose=2 AND s.field IN ('password','inlinePassword')
    )
    INSERT INTO wormhole_data.account_suspension_passwords(account_id,position,boundary_id,owner_kind,owner_id)
        SELECT NEW.id,row_number() OVER (ORDER BY boundary_id,owner_kind,owner_id),boundary_id,owner_kind,owner_id FROM passwords;
    RETURN NULL;
END
$capture$;

-- A v70 suspension predates this capture and has no reconstructible history.
CREATE TRIGGER capture_account_suspension AFTER UPDATE OF disabled ON wormhole_data.users
    FOR EACH ROW WHEN (NOT OLD.disabled AND NEW.disabled)
    EXECUTE FUNCTION wormhole_data.capture_account_suspension();

CREATE FUNCTION wormhole_api_v1.account_suspension_inventory(p_capability bytea,p_account uuid,p_kind text,
    p_revision bigint,p_after bigint,p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,payload jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $inventory$
DECLARE actor record; selected wormhole_data.account_suspensions; meta record; entries jsonb;
BEGIN
    IF p_account IS NULL OR p_account='00000000-0000-0000-0000-000000000000'::uuid OR
        p_kind IS NULL OR p_kind NOT IN ('roots','passwords') OR
        (p_revision IS NULL)<>(p_after IS NULL) OR p_revision<1 OR p_after<1 OR
        octet_length(p_policy) IS DISTINCT FROM 32 OR octet_length(p_account_state) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'Invalid account suspension review request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT actor FROM wormhole_data.require_device(p_capability);
    IF NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=actor.user_id AND u.is_admin)
        OR NOT EXISTS(SELECT FROM wormhole_data.current_connection_tls() tls WHERE tls.ssl) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb;
        RETURN;
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta m WHERE m.singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' OR sha256(meta.signed_profile) IS DISTINCT FROM p_policy OR NOT EXISTS(
        SELECT FROM wormhole_data.user_key_states s WHERE s.user_id=actor.user_id
            AND sha256(s.signed_state)=p_account_state
            AND convert_from(s.signed_state,'UTF8')::jsonb->>'active'='true' FOR SHARE NOWAIT) THEN
        RETURN QUERY SELECT 'stale'::text,NULL::jsonb;
        RETURN;
    END IF;
    IF NOT EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=p_account AND u.disabled) THEN
        RETURN QUERY SELECT 'unavailable'::text,NULL::jsonb;
        RETURN;
    END IF;
    SELECT s.* INTO selected FROM wormhole_data.account_suspensions s WHERE s.account_id=p_account;
    IF NOT FOUND THEN RETURN QUERY SELECT 'not-recorded'::text,NULL::jsonb; RETURN; END IF;
    IF p_revision IS NOT NULL AND selected.revision<>p_revision THEN
        RETURN QUERY SELECT 'stale'::text,NULL::jsonb;
        RETURN;
    END IF;
    IF p_kind='roots' THEN
        SELECT jsonb_agg(
            CASE WHEN (wormhole_data.effective_boundary_permissions(actor.user_id,q.boundary_id)&17)=17
                THEN jsonb_build_array(q.position::text,q.boundary_id,q.purpose::text,q.root_id,q.root_version::text,
                    q.held_directly::text,cardinality(q.groups)::text,k.status)
                ELSE jsonb_build_array(q.position::text,NULL,NULL,NULL,NULL,NULL,NULL,NULL) END
            ORDER BY q.position) INTO entries
        FROM (SELECT * FROM wormhole_data.account_suspension_roots s
            WHERE s.account_id=p_account AND s.position>coalesce(p_after,0) ORDER BY s.position LIMIT 26) q
        JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(q.root_id,q.root_version);
    ELSE
        SELECT jsonb_agg(
            CASE WHEN (wormhole_data.effective_boundary_permissions(actor.user_id,q.boundary_id)&17)=17
                AND CASE q.owner_kind WHEN 'node' THEN
                    CASE WHEN n.id IS NULL THEN false ELSE (wormhole_data.effective_permissions(actor.user_id,q.owner_id)&1)=1 END
                    WHEN 'credential' THEN c.id IS NOT NULL ELSE true END
                THEN jsonb_build_array(q.position::text,q.boundary_id,q.owner_kind,q.owner_id,
                    coalesce(c.name,n.name,''))
                ELSE jsonb_build_array(q.position::text,NULL,NULL,NULL,NULL) END
            ORDER BY q.position) INTO entries
        FROM (SELECT * FROM wormhole_data.account_suspension_passwords s
            WHERE s.account_id=p_account AND s.position>coalesce(p_after,0) ORDER BY s.position LIMIT 26) q
        LEFT JOIN wormhole_data.credential_profiles c ON q.owner_kind='credential' AND c.id=q.owner_id AND c.boundary_id=q.boundary_id
            AND (c.owner_user_id IS NULL OR c.owner_user_id=actor.user_id)
        LEFT JOIN wormhole_data.nodes n ON q.owner_kind='node' AND n.id=q.owner_id AND n.boundary_id=q.boundary_id;
    END IF;
    RETURN QUERY SELECT 'ready'::text,jsonb_build_object('accountId',p_account,'kind',p_kind,'revision',selected.revision::text,
        'entries',coalesce(entries,'[]'));
EXCEPTION WHEN lock_not_available THEN
    RETURN QUERY SELECT 'busy'::text,NULL::jsonb;
END
$inventory$;

{{SUSPENSION_EXPORT_DEFINITION}}
{{SUSPENSION_RESTORE_DEFINITION}}
REVOKE ALL ON TABLE wormhole_data.account_suspensions,wormhole_data.account_suspension_roots,wormhole_data.account_suspension_passwords
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_data.capture_account_suspension(),
    wormhole_data.account_suspensions_recoverable(),
    wormhole_api_v1.account_suspension_inventory(bytea,uuid,text,bigint,bigint,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_suspension_inventory(bytea,uuid,text,bigint,bigint,bytea,bytea)
    TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=71 WHERE singleton;
COMMIT;
