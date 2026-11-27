-- Version 19: bounded, View-filtered catalog invalidations.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>18 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.workspace_meta ADD COLUMN catalog_reset_seq bigint NOT NULL DEFAULT 0 CHECK(catalog_reset_seq>=0);
UPDATE wormhole_data.workspace_meta SET catalog_reset_seq=change_seq WHERE singleton;
CREATE TABLE wormhole_data.catalog_changes (
    node_id uuid PRIMARY KEY,
    change_seq bigint NOT NULL CHECK(change_seq>=1)
);
CREATE INDEX catalog_changes_sequence ON wormhole_data.catalog_changes(change_seq);
REVOKE ALL ON wormhole_data.catalog_changes FROM PUBLIC, wh_{{TAG}}_user, wh_{{TAG}}_enroll;

CREATE OR REPLACE FUNCTION wormhole_data.tree_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $changed$
DECLARE workspace uuid; seq bigint;
BEGIN
    UPDATE wormhole_data.workspace_meta SET change_seq=change_seq+1 WHERE singleton
        RETURNING workspace_id,change_seq INTO STRICT workspace,seq;
    IF TG_TABLE_NAME<>'nodes' OR TG_OP IN ('DELETE','TRUNCATE') THEN
        UPDATE wormhole_data.workspace_meta SET catalog_reset_seq=seq WHERE singleton;
        DELETE FROM wormhole_data.catalog_changes;
    END IF;
    PERFORM pg_catalog.pg_notify('wormhole_changes',workspace::text);
    RETURN NULL;
END
$changed$;

CREATE FUNCTION wormhole_data.catalog_node_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $node$
DECLARE seq bigint; reset_seq bigint;
BEGIN
    SELECT m.change_seq,m.catalog_reset_seq INTO STRICT seq,reset_seq FROM wormhole_data.workspace_meta m WHERE singleton;
    IF TG_OP='UPDATE' AND (OLD.id IS DISTINCT FROM NEW.id OR OLD.parent_id IS DISTINCT FROM NEW.parent_id
        OR OLD.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR OLD.kind IS DISTINCT FROM NEW.kind) THEN
        UPDATE wormhole_data.workspace_meta SET catalog_reset_seq=seq WHERE singleton;
        DELETE FROM wormhole_data.catalog_changes;
    ELSIF reset_seq<seq THEN
        INSERT INTO wormhole_data.catalog_changes(node_id,change_seq) VALUES(NEW.id,seq)
        ON CONFLICT(node_id) DO UPDATE SET change_seq=EXCLUDED.change_seq;
    END IF;
    RETURN NULL;
END
$node$;
CREATE TRIGGER catalog_node_changed AFTER INSERT OR UPDATE ON wormhole_data.nodes
    FOR EACH ROW EXECUTE FUNCTION wormhole_data.catalog_node_changed();

CREATE FUNCTION wormhole_data.catalog_changes_bound() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
AS $bound$
BEGIN
    IF (SELECT pg_catalog.count(*) FROM wormhole_data.catalog_changes)>4096 THEN
        UPDATE wormhole_data.workspace_meta SET catalog_reset_seq=change_seq WHERE singleton;
        DELETE FROM wormhole_data.catalog_changes;
    END IF;
    RETURN NULL;
END
$bound$;
CREATE TRIGGER catalog_changes_bound AFTER INSERT OR UPDATE ON wormhole_data.nodes
    FOR EACH STATEMENT EXECUTE FUNCTION wormhole_data.catalog_changes_bound();
REVOKE ALL ON FUNCTION wormhole_data.catalog_node_changed(),wormhole_data.catalog_changes_bound() FROM PUBLIC;

CREATE FUNCTION wormhole_api_v1.get_changes_since(p_capability bytea,p_epoch bigint,p_since bigint)
RETURNS TABLE(workspace_id uuid,user_id uuid,epoch bigint,change_seq bigint,resolver_version integer,
    reset_required boolean,node_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s'
AS $changes$
DECLARE identity record; meta record; ids uuid[]; item uuid;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF p_epoch IS NULL OR p_epoch<0 OR p_since IS NULL OR p_since<0 OR (p_epoch=0 AND p_since<>0) THEN
        RAISE EXCEPTION 'Invalid change cursor' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    IF p_epoch>meta.epoch OR (p_epoch=meta.epoch AND p_since>meta.change_seq) THEN
        RAISE EXCEPTION 'Tree snapshot changed' USING ERRCODE='WH013';
    END IF;
    workspace_id:=meta.workspace_id; user_id:=identity.user_id;
    epoch:=meta.epoch; change_seq:=meta.change_seq; resolver_version:=meta.resolver_version;
    reset_required:=p_epoch<>meta.epoch OR p_since<meta.catalog_reset_seq;
    IF reset_required THEN RETURN NEXT; RETURN; END IF;
    SELECT pg_catalog.array_agg(changed.node_id ORDER BY changed.node_id) INTO ids FROM (
        SELECT c.node_id FROM wormhole_data.catalog_changes c JOIN wormhole_data.nodes n ON n.id=c.node_id
        WHERE c.change_seq>p_since AND (wormhole_data.effective_permissions(identity.user_id,c.node_id)&1)=1
        ORDER BY c.node_id LIMIT 33
    ) changed;
    IF pg_catalog.cardinality(ids)>32 THEN reset_required:=true; RETURN NEXT; RETURN; END IF;
    IF ids IS NULL THEN RETURN NEXT; RETURN; END IF;
    FOREACH item IN ARRAY ids LOOP node_id:=item; RETURN NEXT; END LOOP;
END
$changes$;
REVOKE ALL ON FUNCTION wormhole_api_v1.get_changes_since(bytea,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.get_changes_since(bytea,bigint,bigint) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=19 WHERE singleton;
COMMIT;
