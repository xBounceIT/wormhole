-- Version 81: track continuous View authority for device-local web archives.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>80 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- This live authority is deliberately omitted from workspace recovery archives.
CREATE TABLE wormhole_data.web_session_views (
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id) ON DELETE CASCADE,
    node_id uuid NOT NULL REFERENCES wormhole_data.nodes(id) ON DELETE CASCADE,
    generation uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    PRIMARY KEY (user_id,node_id)
);
CREATE INDEX web_session_views_node ON wormhole_data.web_session_views(node_id);
REVOKE ALL ON wormhole_data.web_session_views FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;

-- Evaluate the same inherited View decision as get_tree after each permission
-- mutation. The existing BEFORE tree_changed trigger serializes these writes
-- against the workspace row locked by the APIs below.
CREATE FUNCTION wormhole_data.retire_web_session_views() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $retire$
BEGIN
    DELETE FROM wormhole_data.web_session_views watched
    WHERE CASE WHEN EXISTS (SELECT FROM wormhole_data.users u WHERE u.id=watched.user_id AND NOT u.disabled)
                    AND EXISTS (SELECT FROM wormhole_data.nodes n WHERE n.id=watched.node_id)
               THEN (wormhole_data.effective_permissions(watched.user_id,watched.node_id)&1)=0
               ELSE true END;
    RETURN NULL;
END
$retire$;
CREATE TRIGGER retire_web_session_views AFTER UPDATE OF node_id,user_id,group_id,permissions OR DELETE OR TRUNCATE ON wormhole_data.grants
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.retire_web_session_views();
CREATE TRIGGER retire_web_session_views AFTER UPDATE OF group_id,user_id OR DELETE OR TRUNCATE ON wormhole_data.group_members
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.retire_web_session_views();
CREATE TRIGGER retire_web_session_views AFTER UPDATE OF parent_id,kind,owner_user_id ON wormhole_data.nodes
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.retire_web_session_views();
CREATE TRIGGER retire_web_session_views AFTER UPDATE OF disabled ON wormhole_data.users
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.retire_web_session_views();

CREATE FUNCTION wormhole_api_v1.open_web_session_view(p_capability bytea,p_node uuid)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,generation uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $open$
DECLARE identity record; meta record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_node IS NULL OR p_node='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid web session node' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=identity.user_id AND u.disabled) THEN
        RAISE EXCEPTION 'Account is unavailable' USING ERRCODE='WH001';
    END IF;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    workspace_id:=meta.workspace_id; user_id:=identity.user_id; device_id:=identity.device_id; node_id:=p_node;
    IF EXISTS(SELECT FROM wormhole_data.nodes n WHERE n.id=p_node AND n.kind=1) THEN
        IF (wormhole_data.effective_permissions(identity.user_id,p_node)&3)=3 THEN
            INSERT INTO wormhole_data.web_session_views AS watched(user_id,node_id) VALUES(identity.user_id,p_node)
            ON CONFLICT ON CONSTRAINT web_session_views_pkey DO UPDATE SET generation=watched.generation
            RETURNING watched.generation INTO generation;
        END IF;
    END IF;
    RETURN NEXT;
END
$open$;

CREATE FUNCTION wormhole_api_v1.check_web_session_views(p_capability bytea,p_nodes uuid[])
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,generations jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $check$
DECLARE identity record; meta record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_nodes IS NULL OR pg_catalog.array_ndims(p_nodes) IS DISTINCT FROM 1 OR
       pg_catalog.cardinality(p_nodes) NOT BETWEEN 1 AND 32 OR
       EXISTS(SELECT FROM pg_catalog.unnest(p_nodes) requested(id)
              WHERE requested.id IS NULL OR requested.id='00000000-0000-0000-0000-000000000000'::uuid)
       OR (SELECT pg_catalog.count(DISTINCT id) FROM pg_catalog.unnest(p_nodes) requested(id))<>pg_catalog.cardinality(p_nodes) THEN
        RAISE EXCEPTION 'Invalid web session node batch' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF EXISTS(SELECT FROM wormhole_data.users u WHERE u.id=identity.user_id AND u.disabled) THEN
        RAISE EXCEPTION 'Account is unavailable' USING ERRCODE='WH001';
    END IF;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    workspace_id:=meta.workspace_id; user_id:=identity.user_id; device_id:=identity.device_id;
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(watched.node_id,watched.generation)
                                       ORDER BY watched.node_id),'[]'::jsonb)
      INTO generations
      FROM wormhole_data.web_session_views watched
      WHERE watched.user_id=identity.user_id AND watched.node_id=ANY(p_nodes)
        AND (wormhole_data.effective_permissions(identity.user_id,watched.node_id)&1)=1;
    RETURN NEXT;
END
$check$;

REVOKE ALL ON FUNCTION wormhole_data.retire_web_session_views(),
    wormhole_api_v1.open_web_session_view(bytea,uuid),wormhole_api_v1.check_web_session_views(bytea,uuid[])
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.open_web_session_view(bytea,uuid),
    wormhole_api_v1.check_web_session_views(bytea,uuid[]) TO wh_{{TAG}}_user;

{{SUSPENSION_ENROLLMENT_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=81 WHERE singleton;
COMMIT;
