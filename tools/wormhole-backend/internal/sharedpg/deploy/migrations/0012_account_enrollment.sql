-- Version 12: committed enrollment certification and atomic account retrieval.
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
    IF NOT FOUND OR meta.workspace_id <> '{{WORKSPACE_ID}}'::uuid
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 11 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Only the eventual enrollment transaction may install this selection. No runtime
-- role receives table writes. Signatures are verified by the native client.
CREATE TABLE wormhole_data.user_enrollments (
    user_id uuid PRIMARY KEY REFERENCES wormhole_data.users(id),
    encryption_key_id uuid NOT NULL,
    encryption_key_version integer NOT NULL,
    signing_key_id uuid NOT NULL,
    signing_key_version integer NOT NULL,
    certificate bytea NOT NULL CHECK(pg_catalog.octet_length(certificate) BETWEEN 1 AND 1064960),
    CHECK(encryption_key_id<>signing_key_id),
    FOREIGN KEY(encryption_key_id,encryption_key_version) REFERENCES wormhole_data.keys(key_id,key_version),
    FOREIGN KEY(signing_key_id,signing_key_version) REFERENCES wormhole_data.keys(key_id,key_version)
);

CREATE FUNCTION wormhole_api_v1.account_enrollment_material(p_capability bytea)
RETURNS TABLE(workspace_id uuid,user_id uuid,encryption_key_id uuid,encryption_key_version integer,
    signing_key_id uuid,signing_key_version integer,wrap_revision bigint,kdf_preset text,
    ask_required boolean,nonce bytea,ciphertext bytea,auth_epoch bigint,
    signed_state bytea,state_sequence bigint,enrollment_certificate bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $enrolled$
DECLARE wrapped record; current_state record; enrolled record; enc record; sign record;
BEGIN
    SELECT * INTO STRICT wrapped FROM wormhole_api_v1.account_keys(p_capability);
    SELECT * INTO STRICT current_state FROM wormhole_api_v1.account_key_state(p_capability);
    SELECT * INTO enrolled FROM wormhole_data.user_enrollments e WHERE e.user_id=wrapped.user_id FOR SHARE NOWAIT;
    IF NOT FOUND OR enrolled.encryption_key_id<>wrapped.encryption_key_id
        OR enrolled.encryption_key_version<>wrapped.encryption_key_version
        OR enrolled.signing_key_id<>wrapped.signing_key_id
        OR enrolled.signing_key_version<>wrapped.signing_key_version THEN
        RAISE EXCEPTION 'Account enrollment unavailable' USING ERRCODE='WH010';
    END IF;
    SELECT * INTO STRICT enc FROM wormhole_data.keys k WHERE k.key_id=enrolled.encryption_key_id AND k.key_version=enrolled.encryption_key_version FOR SHARE NOWAIT;
    SELECT * INTO STRICT sign FROM wormhole_data.keys k WHERE k.key_id=enrolled.signing_key_id AND k.key_version=enrolled.signing_key_version FOR SHARE NOWAIT;
    IF enc.kind<>'user-enc' OR sign.kind<>'user-sign' OR enc.owner_id IS DISTINCT FROM wrapped.user_id
        OR sign.owner_id IS DISTINCT FROM wrapped.user_id OR enc.status<>'active' OR sign.status<>'active' THEN
        RAISE EXCEPTION 'Account enrollment unavailable' USING ERRCODE='WH010';
    END IF;
    RETURN QUERY SELECT wrapped.workspace_id,wrapped.user_id,wrapped.encryption_key_id,wrapped.encryption_key_version,
        wrapped.signing_key_id,wrapped.signing_key_version,wrapped.wrap_revision,wrapped.kdf_preset,
        wrapped.ask_required,wrapped.nonce,wrapped.ciphertext,wrapped.auth_epoch,
        current_state.signed_state,current_state.state_sequence,enrolled.certificate;
END
$enrolled$;
REVOKE ALL ON wormhole_data.user_enrollments FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
REVOKE ALL ON FUNCTION wormhole_api_v1.account_enrollment_material(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_enrollment_material(bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=12 WHERE singleton;
COMMIT;
