-- Version 16: private hierarchy and additive permission foundation.
-- Node payloads, signed writes, tree projection and secret release are separate APIs.
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
    IF NOT FOUND OR meta.workspace_id <> '{{WORKSPACE_ID}}'::uuid OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 15 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.nodes (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    parent_id uuid NULL REFERENCES wormhole_data.nodes(id),
    kind smallint NOT NULL CHECK(kind IN (0,1)),
    owner_user_id uuid NULL REFERENCES wormhole_data.users(id),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1),
    CHECK(parent_id IS NULL OR parent_id<>id)
);
CREATE INDEX nodes_parent ON wormhole_data.nodes(parent_id);
CREATE TABLE wormhole_data.groups (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    name text NOT NULL CHECK(pg_catalog.octet_length(name) BETWEEN 1 AND 1024),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1)
);
CREATE TABLE wormhole_data.group_members (
    group_id uuid NOT NULL REFERENCES wormhole_data.groups(id),
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1),
    signer_key_id uuid NULL,
    signer_key_version integer NULL,
    signature bytea NULL CHECK(signature IS NULL OR pg_catalog.octet_length(signature)=64),
    PRIMARY KEY(group_id,user_id),
    FOREIGN KEY(signer_key_id,signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version) MATCH FULL,
    CHECK(pg_catalog.num_nonnulls(signer_key_id,signer_key_version,signature) IN (0,3))
);
CREATE INDEX group_members_user ON wormhole_data.group_members(user_id,group_id);
CREATE TABLE wormhole_data.grants (
    node_id uuid NOT NULL REFERENCES wormhole_data.nodes(id),
    user_id uuid NULL REFERENCES wormhole_data.users(id),
    group_id uuid NULL REFERENCES wormhole_data.groups(id),
    permissions integer NOT NULL CHECK(permissions BETWEEN 1 AND 31),
    row_version bigint NOT NULL DEFAULT 1 CHECK(row_version>=1),
    signer_key_id uuid NULL,
    signer_key_version integer NULL,
    signature bytea NULL CHECK(signature IS NULL OR pg_catalog.octet_length(signature)=64),
    CHECK(pg_catalog.num_nonnulls(user_id,group_id)=1),
    FOREIGN KEY(signer_key_id,signer_key_version) REFERENCES wormhole_data.keys(key_id,key_version) MATCH FULL,
    CHECK(pg_catalog.num_nonnulls(signer_key_id,signer_key_version,signature) IN (0,3)),
    UNIQUE NULLS NOT DISTINCT(node_id,user_id,group_id)
);

-- Private evaluator. The public wrapper obtains the user only from audited
-- device admission; callers cannot select another user's effective permissions.
CREATE FUNCTION wormhole_data.effective_permissions(p_user uuid,p_node uuid) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $permissions$
DECLARE current_id uuid:=p_node; item record; path uuid[]:='{}'::uuid[]; restricted boolean:=false; result integer;
BEGIN
    IF p_user IS NULL OR p_user='00000000-0000-0000-0000-000000000000'::uuid OR p_node IS NULL THEN
        RAISE EXCEPTION 'Invalid permission snapshot' USING ERRCODE='22023';
    END IF;
    LOOP
        IF current_id=ANY(path) OR pg_catalog.cardinality(path)>=128 THEN
            RAISE EXCEPTION 'Invalid permission snapshot' USING ERRCODE='22023';
        END IF;
        SELECT n.id,n.parent_id,n.kind,n.owner_user_id INTO item FROM wormhole_data.nodes n WHERE n.id=current_id FOR SHARE NOWAIT;
        IF NOT FOUND OR (pg_catalog.cardinality(path)>0 AND item.kind<>0) THEN
            RAISE EXCEPTION 'Invalid permission snapshot' USING ERRCODE='22023';
        END IF;
        path:=pg_catalog.array_append(path,item.id);
        restricted:=restricted OR (item.owner_user_id IS NOT NULL AND item.owner_user_id<>p_user);
        EXIT WHEN item.parent_id IS NULL;
        current_id:=item.parent_id;
    END LOOP;
    IF restricted THEN RETURN 0; END IF;
    SELECT COALESCE(pg_catalog.bit_or(g.permissions),0) INTO result FROM wormhole_data.grants g
    WHERE g.node_id=ANY(path) AND (g.user_id=p_user OR EXISTS(
        SELECT 1 FROM wormhole_data.group_members m WHERE m.group_id=g.group_id AND m.user_id=p_user));
    RETURN result;
END
$permissions$;

CREATE FUNCTION wormhole_api_v1.node_permissions(p_capability bytea,p_node uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $node_permissions$
DECLARE identity record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    RETURN wormhole_data.effective_permissions(identity.user_id,p_node);
END
$node_permissions$;

REVOKE ALL ON TABLE wormhole_data.nodes,wormhole_data.groups,wormhole_data.group_members,wormhole_data.grants
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin;
REVOKE ALL ON FUNCTION wormhole_data.effective_permissions(uuid,uuid),wormhole_api_v1.node_permissions(bytea,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.node_permissions(bytea,uuid) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=16 WHERE singleton;
COMMIT;
