-- Version 6: retrieve only the authenticated user's encrypted private-key capsule.
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
       OR meta.role_tag <> '{{TAG}}' OR meta.schema_version <> 5 THEN
        RAISE EXCEPTION 'Workspace migration identity or version mismatch' USING ERRCODE='55000';
    END IF;
END
$guard$;

CREATE FUNCTION wormhole_api_v1.account_keys(p_capability bytea)
RETURNS TABLE(workspace_id uuid,user_id uuid,encryption_key_id uuid,encryption_key_version integer,
    signing_key_id uuid,signing_key_version integer,wrap_revision bigint,kdf_preset text,
    ask_required boolean,nonce bytea,ciphertext bytea,auth_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' SET statement_timeout = '15s'
AS $keys$
DECLARE identity record; wrapped record; account record;
BEGIN
    -- No caller-supplied user identifier: even an admin may retrieve only its own
    -- capsule. The admission check also locks the user/device/account epoch.
    SELECT * INTO STRICT identity FROM wormhole_data.require_device(p_capability);
    SELECT * INTO wrapped FROM wormhole_data.user_key_wraps w WHERE w.user_id=identity.user_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account key wrapper unavailable' USING ERRCODE='WH010'; END IF;
    IF NOT EXISTS (SELECT 1 FROM wormhole_data.keys k WHERE k.key_id=wrapped.encryption_key_id
        AND k.key_version=wrapped.encryption_key_version AND k.kind='user-enc'
        AND k.owner_id=identity.user_id AND k.status='active')
       OR NOT EXISTS (SELECT 1 FROM wormhole_data.keys k WHERE k.key_id=wrapped.signing_key_id
        AND k.key_version=wrapped.signing_key_version AND k.kind='user-sign'
        AND k.owner_id=identity.user_id AND k.status='active') THEN
        RAISE EXCEPTION 'Account key wrapper unavailable' USING ERRCODE='WH010';
    END IF;
    SELECT * INTO STRICT account FROM wormhole_data.account_auth a WHERE a.user_id=identity.user_id;
    RETURN QUERY SELECT '{{WORKSPACE_ID}}'::uuid,identity.user_id,wrapped.encryption_key_id,
        wrapped.encryption_key_version,wrapped.signing_key_id,wrapped.signing_key_version,
        wrapped.wrap_revision,wrapped.kdf_preset,wrapped.ask_required,wrapped.nonce,wrapped.ciphertext,account.auth_epoch;
END
$keys$;
REVOKE ALL ON FUNCTION wormhole_api_v1.account_keys(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION wormhole_api_v1.account_keys(bytea) TO wh_{{TAG}}_user;
UPDATE wormhole_data.workspace_meta SET schema_version=6 WHERE singleton;
COMMIT;
