-- Version 92: give each enrolled device a three-connection role budget.
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
DO $upgrade$
DECLARE meta record; device record;
BEGIN
    SELECT * INTO STRICT meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>91 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
    -- A role name alone is insufficient: bind to the confirmed cluster OID.
    -- Pending devices from earlier versions are resized at confirmation.
    FOR device IN
        SELECT r.rolname FROM wormhole_data.devices d
        JOIN wormhole_data.device_confirmations c ON c.device_id=d.id
        JOIN pg_roles r ON r.oid=c.role_oid AND r.rolname=d.role_name
        WHERE d.status='active' AND r.rolcanlogin AND r.rolconnlimit=2
            AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)
            AND pg_has_role(r.oid,'wh_{{TAG}}_user','MEMBER')
        ORDER BY r.rolname
    LOOP
        EXECUTE format('ALTER ROLE %I CONNECTION LIMIT 3',device.rolname);
    END LOOP;
END
$upgrade$;

{{COMMIT_INVITATION}}
{{REDEEM_ACCOUNT_RESET}}
{{REDEEM_ACCOUNT_REENROLLMENT}}
{{CONFIRM_ENROLLMENT}}
{{WEB_SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=92 WHERE singleton;
COMMIT;
