-- Version 84: capture reported device-local web checkpoints at suspension.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>83 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.web_session_checkpoints (
    user_id uuid NOT NULL,
    node_id uuid NOT NULL,
    device_id uuid NOT NULL REFERENCES wormhole_data.devices(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id,node_id,device_id),
    FOREIGN KEY (user_id,node_id) REFERENCES wormhole_data.web_session_views(user_id,node_id) ON DELETE CASCADE
);
CREATE INDEX web_session_checkpoints_device ON wormhole_data.web_session_checkpoints(device_id);
CREATE TABLE wormhole_data.account_suspension_web_reports (
    account_id uuid PRIMARY KEY REFERENCES wormhole_data.account_suspensions(account_id) ON DELETE CASCADE
);
CREATE TABLE wormhole_data.account_suspension_web_targets (
    account_id uuid NOT NULL REFERENCES wormhole_data.account_suspension_web_reports(account_id) ON DELETE CASCADE,
    position bigint NOT NULL CHECK(position>0),
    boundary_id uuid NOT NULL REFERENCES wormhole_data.boundaries(id),
    node_id uuid NOT NULL CHECK(node_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    PRIMARY KEY (account_id,position),
    UNIQUE (account_id,node_id)
);
REVOKE ALL ON TABLE wormhole_data.web_session_checkpoints,wormhole_data.account_suspension_web_reports,
    wormhole_data.account_suspension_web_targets FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;

CREATE FUNCTION wormhole_api_v1.set_web_session_checkpoint(p_capability bytea,p_node uuid,p_generation uuid,p_present boolean)
RETURNS TABLE(workspace_id uuid,user_id uuid,device_id uuid,node_id uuid,generation uuid,accepted boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $checkpoint$
DECLARE identity record; meta record;
BEGIN
    IF p_node IS NULL OR p_generation IS NULL OR p_present IS NULL
       OR p_node='00000000-0000-0000-0000-000000000000'::uuid
       OR p_generation='00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'Invalid web checkpoint request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR SHARE NOWAIT;
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    IF meta.state<>'ready' THEN RAISE EXCEPTION 'Workspace is not ready' USING ERRCODE='WH002'; END IF;
    IF meta.min_api>1 OR meta.max_api<1 OR meta.resolver_version<>1 THEN
        RAISE EXCEPTION 'Workspace API is not supported' USING ERRCODE='WH004';
    END IF;
    workspace_id:=meta.workspace_id; user_id:=identity.user_id; device_id:=identity.device_id;
    node_id:=p_node; generation:=p_generation; accepted:=false;
    IF EXISTS(SELECT FROM wormhole_data.web_session_views v
        WHERE v.user_id=identity.user_id AND v.node_id=p_node AND v.generation=p_generation) THEN
        IF NOT p_present THEN
            DELETE FROM wormhole_data.web_session_checkpoints c
            WHERE c.user_id=identity.user_id AND c.node_id=p_node AND c.device_id=identity.device_id;
            accepted:=true;
        ELSIF (wormhole_data.effective_permissions(identity.user_id,p_node)&3)=3 AND
            wormhole_data.node_default_plan_path(p_node,meta.epoch,meta.change_seq)='web' THEN
            INSERT INTO wormhole_data.web_session_checkpoints(user_id,node_id,device_id)
            VALUES(identity.user_id,p_node,identity.device_id) ON CONFLICT ON CONSTRAINT web_session_checkpoints_pkey DO NOTHING;
            accepted:=true;
        END IF;
    END IF;
    RETURN NEXT;
END
$checkpoint$;

-- Run after capture_account_suspension for each row, before the statement
-- trigger retires the disabled account's View generations and live markers.
CREATE FUNCTION wormhole_data.capture_web_suspension() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $capture$
BEGIN
    INSERT INTO wormhole_data.account_suspension_web_reports(account_id) VALUES(NEW.id);
    INSERT INTO wormhole_data.account_suspension_web_targets(account_id,position,boundary_id,node_id)
    SELECT NEW.id,row_number() OVER (ORDER BY n.id),n.boundary_id,n.id
    FROM wormhole_data.nodes n JOIN (
        SELECT DISTINCT c.node_id FROM wormhole_data.web_session_checkpoints c WHERE c.user_id=NEW.id
    ) c ON c.node_id=n.id;
    RETURN NULL;
END
$capture$;
CREATE TRIGGER capture_web_suspension AFTER UPDATE OF disabled ON wormhole_data.users
    FOR EACH ROW WHEN (NOT OLD.disabled AND NEW.disabled) EXECUTE FUNCTION wormhole_data.capture_web_suspension();

CREATE FUNCTION wormhole_data.suspension_web_page(p_actor uuid,p_account uuid,p_after bigint) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $web$
    SELECT jsonb_agg(CASE WHEN n.id IS NOT NULL AND
        (wormhole_data.effective_boundary_permissions(p_actor,q.boundary_id)&17)=17 AND
        (wormhole_data.effective_permissions(p_actor,q.node_id)&1)=1
        THEN jsonb_build_array(q.position::text,q.boundary_id,'web-target',q.node_id,n.name)
        ELSE jsonb_build_array(q.position::text,NULL,NULL,NULL,NULL) END ORDER BY q.position)
    FROM (SELECT * FROM wormhole_data.account_suspension_web_targets t
          WHERE t.account_id=p_account AND t.position>coalesce(p_after,0) ORDER BY t.position LIMIT 26) q
    LEFT JOIN wormhole_data.nodes n ON n.id=q.node_id AND n.boundary_id=q.boundary_id;
$web$;

CREATE FUNCTION wormhole_data.web_suspension_inventory_recoverable() RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $archive$
    SELECT NOT EXISTS(SELECT FROM wormhole_data.account_suspension_web_targets GROUP BY account_id
        HAVING min(position)<>1 OR max(position)<>count(*));
$archive$;

{{ACCOUNT_WEB_INVENTORY_DEFINITION}}
CREATE FUNCTION wormhole_api_v1.account_suspension_web_sessions(p_capability bytea,p_account uuid,
    p_revision bigint,p_after bigint,p_policy bytea,p_account_state bytea)
RETURNS TABLE(status text,payload jsonb)
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $review_web$
    SELECT * FROM wormhole_api_v1.account_suspension_inventory(
        p_capability,p_account,'web-sessions',p_revision,p_after,p_policy,p_account_state)
$review_web$;
REVOKE ALL ON FUNCTION wormhole_data.capture_web_suspension(),wormhole_data.suspension_web_page(uuid,uuid,bigint),
    wormhole_data.web_suspension_inventory_recoverable(),wormhole_api_v1.set_web_session_checkpoint(bytea,uuid,uuid,boolean),
    wormhole_api_v1.account_suspension_web_sessions(bytea,uuid,bigint,bigint,bytea,bytea)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.set_web_session_checkpoint(bytea,uuid,uuid,boolean),
    wormhole_api_v1.account_suspension_web_sessions(bytea,uuid,bigint,bigint,bytea,bytea) TO wh_{{TAG}}_user;

{{WEB_SUSPENSION_EXPORT_DEFINITION}}
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=84 WHERE singleton;
COMMIT;
