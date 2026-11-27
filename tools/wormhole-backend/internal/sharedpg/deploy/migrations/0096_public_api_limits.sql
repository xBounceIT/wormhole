-- Version 96: retire account roles on deletion and pin the remaining public API wrappers.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_try_advisory_xact_lock(hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>95 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_data.account_group_role_name(p_login text) RETURNS name
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $name$
    SELECT ('wh_{{TAG}}_u_'||string_agg(substr('abcdefghijklmnopqrstuvwxyz234567',
        1+substring(b.bits FROM i*5+1 FOR 5)::integer,1),'' ORDER BY i))::name
    FROM (SELECT ('x'||encode(sha256(convert_to('{{TAG}}'||p_login,'UTF8')),'hex'))::bit(256) AS bits) b
    CROSS JOIN generate_series(0,19) i;
$name$;
REVOKE ALL ON FUNCTION wormhole_data.account_group_role_name(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION wormhole_data.create_account_group(p_user uuid) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp
SET createrole_self_grant='' SET lock_timeout='2s' SET statement_timeout='15s' AS $create_group$
DECLARE target name;
BEGIN
    SELECT wormhole_data.account_group_role_name(login_name) INTO STRICT target FROM wormhole_data.users WHERE id=p_user;
    EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',target);
    INSERT INTO wormhole_data.account_group_roles(user_id,role_name,role_oid)
        VALUES(p_user,target,quote_ident(target)::regrole::oid);
END
$create_group$;

CREATE FUNCTION wormhole_data.retire_account_group() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $retire_group$
DECLARE saved wormhole_data.account_group_roles;
BEGIN
    SELECT * INTO STRICT saved FROM wormhole_data.account_group_roles WHERE user_id=OLD.id FOR UPDATE NOWAIT;
    IF saved.role_name<>wormhole_data.account_group_role_name(OLD.login_name) THEN
        RAISE EXCEPTION 'Account group name changed' USING ERRCODE='WH009';
    END IF;
    IF NOT EXISTS(SELECT FROM pg_roles WHERE oid=saved.role_oid OR rolname=saved.role_name) THEN
        RETURN OLD;
    END IF;
    IF NOT EXISTS(SELECT FROM pg_roles r WHERE r.oid=saved.role_oid AND r.rolname=saved.role_name AND NOT
        (r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)) THEN
        RAISE EXCEPTION 'Account group identity changed' USING ERRCODE='WH009';
    END IF;
    -- Take the role catalog row lock before the final identity check. A concurrent
    -- rename or replacement must roll the whole transaction back.
    EXECUTE format('ALTER ROLE %I NOLOGIN',saved.role_name);
    IF NOT EXISTS(SELECT FROM pg_roles r WHERE r.oid=saved.role_oid AND r.rolname=saved.role_name AND NOT
        (r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls))
        OR EXISTS(SELECT FROM pg_auth_members m WHERE m.member=saved.role_oid OR (m.roleid=saved.role_oid AND
            (m.member<>current_user::regrole OR NOT m.admin_option OR m.inherit_option OR m.set_option))) THEN
        RAISE EXCEPTION 'Account group has unexpected membership or identity' USING ERRCODE='WH009';
    END IF;
    EXECUTE format('DROP ROLE %I',saved.role_name);
    RETURN OLD;
END
$retire_group$;
REVOKE ALL ON FUNCTION wormhole_data.retire_account_group() FROM PUBLIC;
CREATE TRIGGER retire_account_group BEFORE DELETE ON wormhole_data.users
    FOR EACH ROW EXECUTE FUNCTION wormhole_data.retire_account_group();

-- The four routing functions call fixed, schema-qualified APIs which derive
-- identity from session_user and the capability. The logging preflight reads
-- only the current connection settings; the invitation role also uses it.
ALTER FUNCTION wormhole_api_v1.account_reset_publication_ready()
    SECURITY DEFINER SET lock_timeout='2s' SET statement_timeout='15s';
ALTER FUNCTION wormhole_api_v1.account_suspension_groups(bytea,uuid,bigint,bigint,bytea,bytea)
    SECURITY DEFINER SET lock_timeout='2s' SET statement_timeout='15s';
ALTER FUNCTION wormhole_api_v1.account_suspension_web_sessions(bytea,uuid,bigint,bigint,bytea,bytea)
    SECURITY DEFINER SET lock_timeout='2s' SET statement_timeout='15s';
ALTER FUNCTION wormhole_api_v1.rotate_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,uuid,bytea,jsonb)
    SECURITY DEFINER SET lock_timeout='2s' SET statement_timeout='30s';
ALTER FUNCTION wormhole_api_v1.web_connection_plan(bytea,uuid)
    SECURITY DEFINER SET lock_timeout='2s' SET statement_timeout='15s';

{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=96 WHERE singleton;
COMMIT;
