-- Version 94: represent each account by a workspace-scoped, non-login PostgreSQL role.
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
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>93 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Cluster OIDs are local to an installation. Recovery recreates these roles
-- from the restored users; it never imports a role OID from the archive.
CREATE TABLE wormhole_data.account_group_roles (
    user_id uuid PRIMARY KEY REFERENCES wormhole_data.users(id) ON DELETE CASCADE,
    role_name name NOT NULL UNIQUE,
    role_oid oid NOT NULL UNIQUE
);
REVOKE ALL ON wormhole_data.account_group_roles FROM PUBLIC;

CREATE FUNCTION wormhole_data.create_account_group(p_user uuid) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp
SET createrole_self_grant='' SET lock_timeout='2s' SET statement_timeout='15s' AS $create_group$
DECLARE digest_bits bit(256); target name;
BEGIN
    SELECT ('x'||encode(sha256(convert_to('{{TAG}}'||u.login_name,'UTF8')),'hex'))::bit(256)
    INTO STRICT digest_bits FROM wormhole_data.users u WHERE u.id=p_user;
    -- RFC 4648 base32, first 100 bits, lowercase and without padding.
    SELECT 'wh_{{TAG}}_u_'||string_agg(substr('abcdefghijklmnopqrstuvwxyz234567',
        1+substring(digest_bits FROM i*5+1 FOR 5)::integer,1),'' ORDER BY i)
    INTO target FROM generate_series(0,19) i;
    -- Never adopt an existing cluster role, including one from another database.
    EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',target);
    INSERT INTO wormhole_data.account_group_roles(user_id,role_name,role_oid)
        VALUES(p_user,target,quote_ident(target)::regrole::oid);
END
$create_group$;

CREATE FUNCTION wormhole_data.sync_account_device_group(p_device uuid) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $sync_group$
DECLARE device record; account_role record;
BEGIN
    SELECT d.user_id,r.rolname,r.oid,(d.status='active' AND NOT u.disabled AND r.rolcanlogin) AS active
    INTO device FROM wormhole_data.devices d JOIN wormhole_data.users u ON u.id=d.user_id
        JOIN wormhole_data.device_confirmations c ON c.device_id=d.id
        JOIN pg_roles r ON r.oid=c.role_oid AND r.rolname=d.role_name
        WHERE d.id=p_device AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)
          AND pg_has_role(r.oid,'wh_{{TAG}}_user','MEMBER');
    IF NOT FOUND THEN RETURN; END IF;
    SELECT r.rolname,r.oid INTO account_role FROM wormhole_data.account_group_roles g
        JOIN pg_roles r ON r.oid=g.role_oid AND r.rolname=g.role_name
        WHERE g.user_id=device.user_id AND NOT (r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolcreatedb
            OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls);
    IF NOT FOUND THEN
        -- A missing group must not prevent disabling an existing device.
        IF NOT device.active THEN RETURN; END IF;
        RAISE EXCEPTION 'Account group identity changed' USING ERRCODE='WH009';
    END IF;
    IF device.active THEN
        -- Affiliation only. Access remains governed by the authenticated API.
        EXECUTE format('GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET FALSE',account_role.rolname,device.rolname);
        IF NOT EXISTS(SELECT FROM pg_auth_members WHERE roleid=account_role.oid AND member=device.oid
                      AND grantor=current_user::regrole AND NOT (admin_option OR inherit_option OR set_option)) THEN
            RAISE EXCEPTION 'Account group membership changed' USING ERRCODE='WH009';
        END IF;
    ELSIF EXISTS(SELECT FROM pg_auth_members WHERE roleid=account_role.oid AND member=device.oid AND grantor=current_user::regrole) THEN
        EXECUTE format('REVOKE %I FROM %I',account_role.rolname,device.rolname);
    END IF;
END
$sync_group$;

CREATE FUNCTION wormhole_data.account_group_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $changed$
DECLARE device uuid;
BEGIN
    IF TG_TABLE_NAME='users' AND TG_OP='INSERT' THEN
        PERFORM wormhole_data.create_account_group(NEW.id);
    ELSIF TG_TABLE_NAME='users' THEN
        FOR device IN SELECT id FROM wormhole_data.devices WHERE user_id=NEW.id AND status='active' ORDER BY id LOOP
            PERFORM wormhole_data.sync_account_device_group(device);
        END LOOP;
    ELSIF TG_TABLE_NAME='devices' THEN
        PERFORM wormhole_data.sync_account_device_group(NEW.id);
    ELSE
        PERFORM wormhole_data.sync_account_device_group(NEW.device_id);
    END IF;
    RETURN NULL;
END
$changed$;
REVOKE ALL ON FUNCTION wormhole_data.create_account_group(uuid),wormhole_data.sync_account_device_group(uuid),
    wormhole_data.account_group_changed() FROM PUBLIC;
CREATE TRIGGER create_account_group AFTER INSERT ON wormhole_data.users
    FOR EACH ROW EXECUTE FUNCTION wormhole_data.account_group_changed();
CREATE TRIGGER update_account_group AFTER UPDATE OF disabled ON wormhole_data.users
    FOR EACH ROW WHEN (OLD.disabled IS DISTINCT FROM NEW.disabled)
    EXECUTE FUNCTION wormhole_data.account_group_changed();
CREATE TRIGGER confirm_account_group AFTER INSERT ON wormhole_data.device_confirmations
    FOR EACH ROW EXECUTE FUNCTION wormhole_data.account_group_changed();
CREATE TRIGGER retire_account_group AFTER UPDATE OF status ON wormhole_data.devices
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status='revoked')
    EXECUTE FUNCTION wormhole_data.account_group_changed();

DO $upgrade$
DECLARE item uuid;
BEGIN
    PERFORM wormhole_data.configure_relation_rls('wormhole_data.account_group_roles'::regclass,
        (SELECT relforcerowsecurity FROM pg_class WHERE oid='wormhole_data.users'::regclass));
    FOR item IN SELECT id FROM wormhole_data.users ORDER BY id LOOP
        PERFORM wormhole_data.create_account_group(item);
    END LOOP;
    FOR item IN SELECT device_id FROM wormhole_data.device_confirmations ORDER BY device_id LOOP
        PERFORM wormhole_data.sync_account_device_group(item);
    END LOOP;
END
$upgrade$;
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=94 WHERE singleton;
COMMIT;
