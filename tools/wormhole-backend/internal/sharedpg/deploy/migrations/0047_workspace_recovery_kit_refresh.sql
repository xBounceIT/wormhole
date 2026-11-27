-- Version 47: audited retrieval of the encrypted recovery kit's current CA.
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
    IF NOT FOUND OR meta.workspace_id<>'{{WORKSPACE_ID}}'::uuid OR meta.role_tag<>'{{TAG}}' OR meta.schema_version<>46 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.workspace_recovery_kit_refresh(p_capability bytea,
    p_holder uuid,p_holder_version integer,p_signer uuid,p_signer_version integer,
    p_tls_sequence bigint,p_tls_digest bytea,p_profile_digest bytea,p_account_digest bytea)
RETURNS TABLE(org_key_id uuid,org_key_version integer,enc bytea,ciphertext bytea,signature bytea,ca jsonb,bootstrap_recovery bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' SET statement_timeout='15s'
AS $recovery$
DECLARE identity record; key_copy jsonb; capsule bytea;
BEGIN
    SELECT * INTO STRICT identity FROM wormhole_data.require_server_ca_admin(p_capability,p_holder,p_holder_version,
        p_signer,p_signer_version,p_tls_sequence,p_tls_digest,p_profile_digest,p_account_digest,false);
    IF identity.bundle#>>'{workspaceCa,previousCa}' IS NOT NULL THEN
        RAISE EXCEPTION 'Server CA rotation in progress' USING ERRCODE='WH020';
    END IF;
    key_copy:=wormhole_data.server_ca_key_copy(identity.bundle);
    SELECT b.recovery_capsule INTO capsule FROM wormhole_data.workspace_bootstrap b WHERE b.singleton FOR SHARE NOWAIT;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace recovery capsule unavailable' USING ERRCODE='WH020';
    END IF;
    RETURN QUERY SELECT c.*,key_copy,capsule
        FROM wormhole_data.server_ca_org_copy(identity.actor,p_holder,p_holder_version,p_signer,p_signer_version,'org-enc') c;
    PERFORM wormhole_data.audit_server_ca(identity.actor,identity.session_id,identity.app_version,
        'workspace_recovery_kit_refresh','key_copy_released');
END
$recovery$;

REVOKE ALL ON FUNCTION wormhole_api_v1.workspace_recovery_kit_refresh(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.workspace_recovery_kit_refresh(bytea,uuid,integer,uuid,integer,bigint,bytea,bytea,bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=47 WHERE singleton;
COMMIT;
