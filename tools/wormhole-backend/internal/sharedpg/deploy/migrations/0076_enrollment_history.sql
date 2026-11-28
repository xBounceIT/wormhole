-- Version 76: retain public certificates when the enrolled signing key changes.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>75 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE TABLE wormhole_data.user_enrollment_history (
    user_id uuid NOT NULL REFERENCES wormhole_data.users(id),
    signing_key_id uuid NOT NULL,
    signing_key_version integer NOT NULL,
    certificate bytea NOT NULL CHECK(octet_length(certificate) BETWEEN 1 AND 1064960),
    PRIMARY KEY(signing_key_id,signing_key_version),
    FOREIGN KEY(signing_key_id,signing_key_version) REFERENCES wormhole_data.keys(key_id,key_version)
);

CREATE FUNCTION wormhole_data.archive_enrollment_certificate() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $history$
BEGIN
    IF EXISTS(SELECT FROM wormhole_data.user_enrollment_history h
        WHERE (h.signing_key_id,h.signing_key_version)=(NEW.signing_key_id,NEW.signing_key_version)) THEN
        RAISE EXCEPTION 'Historical enrollment signing key cannot become current' USING ERRCODE='WH010';
    END IF;
    INSERT INTO wormhole_data.user_enrollment_history(user_id,signing_key_id,signing_key_version,certificate)
        VALUES(OLD.user_id,OLD.signing_key_id,OLD.signing_key_version,OLD.certificate);
    RETURN NEW;
END
$history$;

CREATE TRIGGER preserve_enrollment_certificate AFTER UPDATE OF signing_key_id,signing_key_version
ON wormhole_data.user_enrollments FOR EACH ROW
WHEN ((OLD.signing_key_id,OLD.signing_key_version) IS DISTINCT FROM (NEW.signing_key_id,NEW.signing_key_version))
EXECUTE FUNCTION wormhole_data.archive_enrollment_certificate();

CREATE OR REPLACE FUNCTION wormhole_data.enrolled_author_certificate(p_user uuid,p_signer uuid,p_version integer)
RETURNS bytea LANGUAGE sql STABLE STRICT SET search_path=pg_catalog,pg_temp AS $enrolled$
    SELECT COALESCE(
        (SELECT e.certificate FROM wormhole_data.user_enrollments e
         WHERE e.user_id=p_user AND (e.signing_key_id,e.signing_key_version)=(p_signer,p_version)),
        (SELECT h.certificate FROM wormhole_data.user_enrollment_history h
         WHERE h.user_id=p_user AND (h.signing_key_id,h.signing_key_version)=(p_signer,p_version)));
$enrolled$;

CREATE FUNCTION wormhole_data.enrollment_history_recoverable() RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $check$
    SELECT NOT EXISTS(
        SELECT FROM wormhole_data.user_enrollment_history h
        JOIN wormhole_data.keys k ON (k.key_id,k.key_version)=(h.signing_key_id,h.signing_key_version)
        LEFT JOIN wormhole_data.user_enrollments e ON e.user_id=h.user_id
        WHERE k.owner_id IS DISTINCT FROM h.user_id OR k.kind<>'user-sign' OR e.user_id IS NULL
           OR (h.signing_key_id,h.signing_key_version)=(e.signing_key_id,e.signing_key_version)
    );
$check$;

REVOKE ALL ON TABLE wormhole_data.user_enrollment_history
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
REVOKE ALL ON FUNCTION wormhole_data.archive_enrollment_certificate(),wormhole_data.enrollment_history_recoverable()
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;

{{ENROLLMENT_HISTORY_EXPORT_DEFINITION}}
{{ENROLLMENT_HISTORY_RESTORE_DEFINITION}}

UPDATE wormhole_data.workspace_meta SET schema_version=76 WHERE singleton;
COMMIT;
