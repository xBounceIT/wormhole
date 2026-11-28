-- Version 75: preserve the reviewed suspension during group removal.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>74 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

ALTER TABLE wormhole_data.group_member_rotation_jobs
    ADD COLUMN suspension_revision bigint CHECK(suspension_revision>0);

{{SCOPED_GROUP_REMOVAL_DEFINITION}}

CREATE OR REPLACE FUNCTION wormhole_api_v1.rotate_group_member(p_capability bytea,p_holder uuid,p_holder_version integer,
    p_signer uuid,p_signer_version integer,p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea,
    p_job uuid,p_group uuid,p_revision bigint,p_member uuid,p_review bytea,p_publication jsonb)
RETURNS TABLE(status text,snapshot bytea,roster bytea,manifest bytea,pending bigint,
    org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,
    recipient_id uuid,recipient_version integer,recipient_public bytea,recipient_signature bytea)
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $ordinary_group_removal$
    SELECT * FROM wormhole_api_v1.rotate_group_member(p_capability,p_holder,p_holder_version,p_signer,p_signer_version,
        p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,p_job,p_group,p_revision,p_member,p_review,p_publication,NULL::bigint)
$ordinary_group_removal$;

REVOKE ALL ON FUNCTION
    wormhole_api_v1.rotate_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,uuid,bytea,jsonb,bigint)
    FROM PUBLIC,wh_{{TAG}}_user,wh_{{TAG}}_admin,wh_{{TAG}}_enroll,wh_{{TAG}}_deployer;
GRANT EXECUTE ON FUNCTION
    wormhole_api_v1.rotate_group_member(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea,uuid,uuid,bigint,uuid,bytea,jsonb,bigint)
    TO wh_{{TAG}}_user;
{{SUSPENSION_RESTORE_DEFINITION}}
UPDATE wormhole_data.workspace_meta SET schema_version=75 WHERE singleton;
COMMIT;
