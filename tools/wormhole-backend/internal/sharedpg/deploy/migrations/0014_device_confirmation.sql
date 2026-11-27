-- Version 14: audited confirmation of the first device's temporary login.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='30s';
DO $lock$
BEGIN
    IF NOT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('wormhole/schema/{{WORKSPACE_ID}}',0)) THEN
        RAISE EXCEPTION 'Workspace migration is already in progress' USING ERRCODE='55P03';
    END IF;
END
$lock$;
SET LOCAL ROLE wh_{{TAG}}_owner;
DO $guard$
DECLARE meta record;
BEGIN
    SELECT * INTO meta FROM wormhole_data.workspace_meta WHERE singleton FOR UPDATE NOWAIT;
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>13 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.device_confirmations (
    device_id uuid PRIMARY KEY REFERENCES wormhole_data.devices(id),
    role_oid oid NOT NULL,
    certificate_digest bytea NOT NULL CHECK(pg_catalog.octet_length(certificate_digest)=32),
    confirmed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE FUNCTION wormhole_api_v1.confirm_enrollment(p_capability bytea,p_certificate_digest bytea)
RETURNS TABLE(device_id uuid,confirmed boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $confirm$
DECLARE identity record; device record; role record; enrollment record; prior record; session_record record;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    SELECT * INTO STRICT device FROM wormhole_data.devices d WHERE d.id=identity.device_id FOR UPDATE NOWAIT;
    SELECT * INTO enrollment FROM wormhole_data.user_enrollments e WHERE e.user_id=identity.user_id FOR SHARE NOWAIT;
    IF NOT FOUND OR p_certificate_digest IS NULL OR pg_catalog.octet_length(p_certificate_digest)<>32
        OR pg_catalog.sha256(enrollment.certificate)<>p_certificate_digest THEN
        RAISE EXCEPTION 'Account enrollment changed' USING ERRCODE='WH010';
    END IF;
    SELECT * INTO role FROM pg_catalog.pg_roles r WHERE r.rolname=device.role_name;
    IF NOT FOUND OR NOT role.rolcanlogin OR role.rolsuper OR role.rolcreatedb OR role.rolcreaterole
        OR role.rolreplication OR role.rolbypassrls OR role.rolinherit THEN
        RAISE EXCEPTION 'Device credentials unavailable' USING ERRCODE='WH009';
    END IF;
    SELECT * INTO prior FROM wormhole_data.device_confirmations c WHERE c.device_id=identity.device_id FOR SHARE NOWAIT;
    IF FOUND THEN
        IF prior.role_oid<>role.oid OR prior.certificate_digest<>p_certificate_digest
            OR role.rolvaliduntil IS DISTINCT FROM 'infinity'::timestamptz THEN
            RAISE EXCEPTION 'Device credentials unavailable' USING ERRCODE='WH009';
        END IF;
        RETURN QUERY SELECT identity.device_id,true;
        RETURN;
    END IF;
    -- An already-open connection does not bypass expiration. Only a live finite
    -- enrollment login may be made permanent; ordinary roles cannot opt into this.
    IF role.rolvaliduntil IS NULL OR NOT pg_catalog.isfinite(role.rolvaliduntil)
        OR role.rolvaliduntil<=pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'Device credentials unavailable' USING ERRCODE='WH009';
    END IF;
    SELECT s.* INTO STRICT session_record FROM wormhole_data.sessions s JOIN wormhole_data.device_admissions a ON a.session_id=s.id
        WHERE a.device_id=identity.device_id;
    EXECUTE pg_catalog.format('ALTER ROLE %I VALID UNTIL %L',device.role_name,'infinity');
    INSERT INTO wormhole_data.device_confirmations(device_id,role_oid,certificate_digest)
        VALUES(identity.device_id,role.oid,p_certificate_digest);
    BEGIN
        INSERT INTO wormhole_data.audit_log(user_id,session_id,session_role,source,action,outcome,client_addr,app_version)
            VALUES(identity.user_id,session_record.id,session_user,'ui','confirm_enrollment','success',pg_catalog.inet_client_addr(),session_record.app_version);
    EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'Workspace audit unavailable' USING ERRCODE='WH005'; END;
    RETURN QUERY SELECT identity.device_id,true;
END
$confirm$;
REVOKE ALL ON wormhole_data.device_confirmations FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_api_v1.confirm_enrollment(bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.confirm_enrollment(bytea,bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=14 WHERE singleton;
COMMIT;
