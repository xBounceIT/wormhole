-- Version 32: private signed-manifest-bound credential ciphertext read.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>31 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

-- Private ciphertext section for a connection-authorized release. No public
-- raw credential ID accessor; caller must first resolve/authorize that connection.
CREATE FUNCTION wormhole_data.credential_values(p_credential uuid,p_epoch bigint,p_change_seq bigint)
RETURNS TABLE(workspace_id uuid,credential_id uuid,epoch bigint,change_seq bigint,
    field text,row_version bigint,dek_id uuid,dek_version integer,envelope bytea)
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' SET statement_timeout='15s' AS $values$
DECLARE profile record; entry jsonb; value wormhole_data.secret_values; size bigint:=0;
BEGIN
    -- Validates ID/snapshot/readiness/API and locks workspace against all writers.
    SELECT * INTO STRICT profile FROM wormhole_data.credential_record(p_credential,p_epoch,p_change_seq);
    IF (profile.record->>'deleted')::boolean THEN RAISE EXCEPTION 'Credential unavailable' USING ERRCODE='WH018'; END IF;
    FOR entry IN SELECT f.value FROM jsonb_array_elements(profile.record->'fields') f LOOP
        IF NOT (entry->>'present')::boolean THEN CONTINUE; END IF;
        SELECT v.* INTO value FROM wormhole_data.secret_values v
            WHERE v.owner_kind='credential' AND v.owner_id=p_credential AND v.field=entry->>'field';
        IF NOT FOUND OR value.row_version<>(entry->>'version')::bigint
           OR NOT EXISTS(SELECT 1 FROM wormhole_data.keys k WHERE k.key_id=value.dek_id AND k.key_version=value.dek_version AND k.kind='dek') THEN
            RAISE EXCEPTION 'Credential value unavailable' USING ERRCODE='WH010';
        END IF;
        IF octet_length(value.envelope)>6291456 THEN RAISE EXCEPTION 'Credential value is too large' USING ERRCODE='54000'; END IF;
        size:=size+octet_length(value.envelope);
        IF size>8388608 THEN RAISE EXCEPTION 'Credential values are too large' USING ERRCODE='54000'; END IF;
        RETURN QUERY SELECT profile.workspace_id,p_credential,profile.epoch,profile.change_seq,
            value.field,value.row_version,value.dek_id,value.dek_version,value.envelope;
    END LOOP;
END
$values$;
REVOKE ALL ON FUNCTION wormhole_data.credential_values(uuid,bigint,bigint) FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll;
UPDATE wormhole_data.workspace_meta SET schema_version=32 WHERE singleton;
COMMIT;
